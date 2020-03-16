#!/usr/bin/env python3
"""
Description: Protects song by adding metadata or any other security measures
Use: Once per song
Usage:
./protectRITSong.py --region-list "United States" "Japan" "Australia" --region-secrets-path region.secrets --outfile protectRITdemo.drm --infile Sound-Bite_One-Small-Step.wav --owner "misha" --user-secrets-path user.secrets
output: encrypted song, aes.key will be sent to firmware
"""
import json
import struct
import os
import wave
from argparse import ArgumentParser
import numpy as np

import random, string
from Crypto.Cipher import AES

class CreateDrmHeader(object):
    first_segment_size = struct.pack("=I", 0)
    def __init__(self, path_to_song, regions, user, user_secret_location, region_info):
        """
        struct drm_header { //sizeof() = 1368
            uint8_t song_id[SONGID_LEN=16];                         16      16     
            char owner[UNAME_SIZE=16];                              16      32      
            uint32_t regions[MAX_SHARED_REGIONS=32];                128     160 
            uint32_t len_250ms;                                     4       164
            uint32_t nr_segments;                                   4       
            uint32_t first_segment_size;                            4
            struct wav_header wavdata;                              44
            uint8_t mp_sig[EDDSA_SIG_SIZE=64]; //miPod signature    64
            char shared_users[UNAME_SIZE=16][MAX_SHARED_USERS=64];  64*16
            uint8_t owner_sig[EDDSA_SIG_SIZE=64];                   64
        };        
        """
        self.song_id = str.encode("".join(random.choices(string.digits, k=16)))
        self.owner = struct.pack('=16s', str.encode(user))
        self.regions_id = self.create_max_regions(region_info, regions)
        self.wavdata = self.read_wav_header(path_to_song)
        # self.len_250ms = struct.pack('=I', 0)   
        self.len_250ms = self.find_len_250ms()
        self.nr_segments = struct.pack('=I', 4)
        self.mp_sig = self.init_sig()
        self.shared_users = self.init_shared_users()
        self.owner_sig = self.init_sig()

    def create_max_regions(self, region_info, regions):
        rid = bytearray()
        for i in regions:
            rid = rid + struct.pack("=I", int(region_info[str(i)]))
        for i in range(len(regions), 32):
            rid = rid + struct.pack("=I", 0)
        return rid

    def read_wav_header(self, path):
        # open file
        file_name = os.path.abspath(path)
        try:
            fileIn = open(file_name,"rb")
        except IOError as err:
            print("Could not open song file %s" % file_name)
            return
        # bufHeader = fileIn.read(38)
        bufHeader = fileIn.read(44)

        # Verify that the correct identifiers are present
        # print(bufHeader[0:4])
        # print(bufHeader[12:16])
        # if (bufHeader[0:4] != 'RIFF') or \
        #     (bufHeader[12:15] != 'fmt'):
        #     print(("Input file is not a standard WAV file"))
        #     return
        return bufHeader

    # time = FileLength / (Sample Rate * Channels * Bits per sample /8)
    def find_len_250ms(self):
        wav= self.wavdata

        # ChunkID=wav[0:4] # First four bytes are ChunkID which must be "RIFF" in ASCII
        # ChunkSize=struct.unpack('I',wav[4:8]) # 'I' Format is to to treat the 4 bytes as unsigned 32-bit inter
        # TotalSize=ChunkSize[0]+8 # The subscript is used because struct unpack returns everything as tuple
        # DataSize=TotalSize-44 # This is the number of bytes of data
        # Format=wav[8:12] # "WAVE" in ASCII
        # SubChunk1ID=wav[12:16] # "fmt " in ASCII
        # SubChunk1Size=(struct.unpack("I",wav[16:20]))[0] # 'I' format to treat as unsigned 32-bit integer
        # AudioFormat=(struct.unpack("H",wav[20:22]))[0] # 'H' format to treat as unsigned 16-bit integer
        # NumChannels=(struct.unpack("H",wav[22:24]))[0] # 'H' unsigned 16-bit integer
        # SampleRate=(struct.unpack("I",wav[24:28]))[0]
        BytePerSec=(struct.unpack("I",wav[28:32]))[0] # 'I' unsigned 32 bit integer
        # BlockAlign=(struct.unpack("H",wav[32:34]))[0] # 'H' unsigned 16-bit integer
        # BitsPerSample=(struct.unpack("H",wav[34:36]))[0] # 'H' unsigned 16-bit integer
        # SubChunk2ID=wav[36:40] # "data" in ASCII
        # SubChunk2Size=(struct.unpack("I",wav[40:44]))[0]

        BytePer_250ms = (BytePerSec * 250) /1000
        return struct.pack("I", int(BytePer_250ms))

    def init_shared_users(self):
        shared_users = bytearray()
        for i in range(0, 64):
            shared_users = shared_users + struct.pack("=16s", str.encode(''))
        return shared_users

    def init_sig(self):
        sig = ''
        for i in range(0, 4):
            sig = sig + "".join(random.sample(string.ascii_letters + string.digits, k=16))
        return str.encode(sig)

def write_header(outfile, drm_header):
    file = open(outfile, "ab+")
    file.write(drm_header.song_id)
    file.write(drm_header.owner)
    file.write(drm_header.regions_id)
    file.write(drm_header.len_250ms)
    file.write(drm_header.nr_segments)
    file.write(drm_header.first_segment_size)
    file.write(drm_header.wavdata)
    file.write(drm_header.mp_sig)
    file.write(drm_header.shared_users)
    file.write(drm_header.owner_sig)
    file.close()   

class EncryptSong(object):
    def __init__(self, nr_segments, path_to_song):
        self.wav_size = 0
        self.key = self.gen_key()
        self.nr_segments = (struct.unpack('=I', nr_segments))[0]
        self.first_segment_size = str.encode("%04d" % int(16 * 1000))  # block size
        self.encrypt_str = self.encrypt_song(path_to_song)

    def gen_key(self):
        key = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        # key = os.urandom(16)
        key_file = open("aes.key", "w")
        key_file.write(key)
        key_file.close()
        print(key)
        return key

    def encrypt_song(self, path):
        # open file
        encrypt_song_str = bytearray()
        file_name = os.path.abspath(path)
        try:
            fileIn = open(file_name,"rb")
        except IOError as err:
            print("Could not open song file %s" % file_name)
            return
        wav_header = fileIn.read(44)
        # file_stats = (os.stat(file_name)).st_size
        # self.wav_size = (struct.unpack('I', wav_header[40:44]))[0]
        self.wav_size = (struct.unpack('I', wav_header[4:8]))[0] - 44 + 8
        print(self.wav_size)
        # calculate the number of block_size (16)
        nr_block = int(self.wav_size / 16) + 1
        # the encrypt data should be the multiple of 16, so we need to fill the last block to 16
        fill_block_size = 16 - int(self.wav_size % 16)
        fill_block = bytearray(fill_block_size)
        # calculate the size of segments, multiple of 16
        self.first_segment_size = int(nr_block / self.nr_segments) * 16
        # get the real last_segment
        last_segment_size = self.first_segment_size - fill_block_size
        
        # encrypt the song segment by segment
        segment_cipher = AES.new(self.key, AES.MODE_ECB)
        for i in range(0, self.nr_segments-1):
            segment = fileIn.read(self.first_segment_size)
            # segment.decode('iso-8859-1')    
            encrypt_song_str = encrypt_song_str + segment_cipher.encrypt(segment)

        # encrypt the last segment
        last_segment = fileIn.read(last_segment_size) + fill_block
        encrypt_last_segment = segment_cipher.encrypt(last_segment)
        encrypt_song_str = encrypt_song_str + encrypt_last_segment
        return encrypt_song_str

    def save_song(self, outfile):
        fileOut = open(outfile, "ab+")
        fileOut.write(self.encrypt_str)
        fileOut.close

def print_song_header(path):
    fin = open(os.path.abspath(path),"rb") # Read wav file, "r flag" - read, "b flag" - binary 
    ChunkID=fin.read(4) # First four bytes are ChunkID which must be "RIFF" in ASCII
    print("ChunkID=",ChunkID)
    ChunkSizeString=fin.read(4) # Total Size of File in Bytes - 8 Bytes
    ChunkSize=struct.unpack('I',ChunkSizeString) # 'I' Format is to to treat the 4 bytes as unsigned 32-bit inter
    TotalSize=ChunkSize[0]+8 # The subscript is used because struct unpack returns everything as tuple
    print("TotalSize=",TotalSize)
    DataSize=TotalSize-44 # This is the number of bytes of data
    print("DataSize=",DataSize)
    Format=fin.read(4) # "WAVE" in ASCII
    print("Format=",Format)
    SubChunk1ID=fin.read(4) # "fmt " in ASCII
    print("SubChunk1ID=",SubChunk1ID)
    SubChunk1SizeString=fin.read(4) # Should be 16 (PCM, Pulse Code Modulation)
    SubChunk1Size=struct.unpack("I",SubChunk1SizeString) # 'I' format to treat as unsigned 32-bit integer
    print("SubChunk1Size=",SubChunk1Size[0])
    AudioFormatString=fin.read(2) # Should be 1 (PCM)
    AudioFormat=struct.unpack("H",AudioFormatString) # 'H' format to treat as unsigned 16-bit integer
    print("AudioFormat=",AudioFormat[0])
    NumChannelsString=fin.read(2) # Should be 1 for mono, 2 for stereo
    NumChannels=struct.unpack("H",NumChannelsString) # 'H' unsigned 16-bit integer
    print("NumChannels=",NumChannels[0])
    SampleRateString=fin.read(4) # Should be 44100 (CD sampling rate)
    SampleRate=struct.unpack("I",SampleRateString)
    print("SampleRate=",SampleRate[0])
    BytePerSecString=fin.read(4) # 44100*NumChan*2 (88200 - Mono, 176400 - Stereo)
    BytePerSec=struct.unpack("I",BytePerSecString) # 'I' unsigned 32 bit integer
    print("BytePerSec=",BytePerSec[0])
    BlockAlignString=fin.read(2) # NumChan*2 (2 - Mono, 4 - Stereo)
    BlockAlign=struct.unpack("H",BlockAlignString) # 'H' unsigned 16-bit integer
    print("BlockAlign=",BlockAlign[0])
    BitsPerSampleString=fin.read(2) # 16 (CD has 16-bits per sample for each channel)
    BitsPerSample=struct.unpack("H",BitsPerSampleString) # 'H' unsigned 16-bit integer
    print("BitsPerSample=",BitsPerSample[0])
    SubChunk2ID=fin.read(4) # "data" in ASCII
    print("SubChunk2ID=",SubChunk2ID)
    SubChunk2SizeString=fin.read(4) # Number of Data Bytes, Same as DataSize
    SubChunk2Size=struct.unpack("I",SubChunk2SizeString)
    print("SubChunk2Size=",SubChunk2Size[0])
    S1String=fin.read(2) # Read first data, number between -32768 and 32767
    S1=struct.unpack("h",S1String)
    print("S1=",S1[0])
    S2String=fin.read(2) # Read second data, number between -32768 and 32767
    S2=struct.unpack("h",S2String)
    print("S2=",S2[0])
    S3String=fin.read(2) # Read second data, number between -32768 and 32767
    S3=struct.unpack("h",S3String)
    print("S3=",S3[0])
    S4String=fin.read(2) # Read second data, number between -32768 and 32767
    S4=struct.unpack("h",S4String)
    print("S4=",S4[0])
    S5String=fin.read(2) # Read second data, number between -32768 and 32767
    S5=struct.unpack("h",S5String)
    print("S5=",S5[0])
    fin.close()


def main():
    parser = ArgumentParser(description='main interface to protect songs')
    parser.add_argument('--region-list', nargs='+', help='List of regions song can be played in', required=True)
    parser.add_argument('--region-secrets-path', help='File location for the region secrets file',
                        required=True)
    parser.add_argument('--outfile', help='path to save the protected song', required=True)
    parser.add_argument('--infile', help='path to unprotected song', required=True)
    parser.add_argument('--owner', help='owner of song', required=True)
    parser.add_argument('--user-secrets-path', help='File location for the user secrets file', required=True)
    args = parser.parse_args()

    regions = json.load(open(os.path.abspath(args.region_secrets_path)))

    # print_song_header(args.infile)

    drm_header = CreateDrmHeader(args.infile, args.region_list, args.owner, args.user_secrets_path, regions) 
    nr_segments = drm_header.nr_segments
    protect_song = EncryptSong(nr_segments, args.infile)
    # The size of the first segment will be caculated when encrypt the song
    CreateDrmHeader.first_segment_size = struct.pack('=I', protect_song.first_segment_size)
    write_header(args.outfile, drm_header)
    protect_song.save_song(args.outfile)

if __name__ == '__main__':
    main()
