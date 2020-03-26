#!/usr/bin/env python3
"""
Description: Hash the encryt song with mipod_sig then store back to the tail.
Use: Once per song
Usage:
./sig_song_segment.py --infile protectRITdemo.drm --mipod_sig mipod_sig --outfile rit.drm
./sig_song_segment.py --region-list "United States" "Japan" "Australia" --region-secrets-path region.secrets --outfile rit.drm --infile Sound-Bite_One-Small-Step.wav --owner "misha" --user-secrets-path user.secrets
output: encrypted song
"""

import json
import struct
import os
import wave
from argparse import ArgumentParser
import numpy as np

import random, string
from Crypto.Cipher import AES
import hashlib
import hmac
from itertools import zip_longest

def Transform(string):
    keylength = 4
    transposed_str = bytes()
    blocks = [string[i:i+keylength] for i in range(0, len(string)+1, keylength)]
    transposed = [bytes(t) for t in zip_longest(*blocks, fillvalue=0)]
    for i in range(0, 4):
        transposed_str = transposed_str + transposed[i][0:4]
    return transposed_str

def TransSeg(segment, size):  # len should be multiple of 16
    count = int(size/16)
    block_size = 16
    segment_trans = bytes()
    blocks = [segment[i:i+block_size] for i in range(0, len(segment)+1, block_size)]
    for i in range(0, count):
        segment_trans = segment_trans + Transform(blocks[i])
    return segment_trans

def init_sig():
    owner_sig = ''
    for i in range(0, 4):
        owner_sig = owner_sig + "".join(random.sample(string.ascii_letters + string.digits, k=16))
    # mp_sig_file = open("owner_sig", "w")
    # mp_sig_file.write(owner_sig)
    # mp_sig_file.close()
    return str.encode(owner_sig)

def init_pad():
    return struct.pack("=40s", str.encode(''))

def get_mp_key():
    fileIn = open("mipodKey", "rb")
    mipod_key = fileIn.read()
    # mipod_key = struct.unpack('=64B', fileIn.read())
    # print("mipod_key:", mipod_key)
    fileIn.close()
    return mipod_key

def get_owner_key(owner):
    # owner = "misha"
    user = json.load(open(os.path.abspath("provisioned_user.secrets")))
    user_hash = user[owner]
    user_hash = list(map(int, user_hash))
    print(user_hash)
    owner_key = bytearray(user_hash)

    # print(user_hash)

    # fo = open("owner_sig_test", "wb")
    # fo.write(user_hash)
    # fo.close()


    # fileIn = open("owner_sig", "rb")
    # owner_key = fileIn.read()
    # mipod_key = struct.unpack('=64B', fileIn.read())
    # print("owner_key:", owner_key)
    # fileIn.close()
    return owner_key

mp_sig = init_sig()
owner_sig = init_sig()
# self.song_id = str.encode("".join(random.choices(string.digits, k=16)))
song_id = str.encode('9839899488377487')
first_segment_size = 0
nr_segments = 0
mipod_key = get_mp_key()
owner_key = get_owner_key("misha")
pad = init_pad()

class CreateDrmHeader(object):
    # first_segment_size = struct.pack("=I", 0)
    def __init__(self, path_to_song, regions, user, user_secret_location, region_info):
        """
        struct drm_header { //sizeof() = 1368
            uint8_t song_id[SONGID_LEN=16];                         16      16     
            char owner[UNAME_SIZE=16];                              16      32      
            uint32_t regions[MAX_SHARED_REGIONS=32];                128     160 
            uint32_t len_250ms;                                     4       164
            uint32_t nr_segments;                                   4       168  
            uint32_t first_segment_size;                            4       172
            struct wav_header wavdata;                              44      216
            uint8_t mp_sig[EDDSA_SIG_SIZE=64]; //miPod signature    64      280
            char shared_users[UNAME_SIZE=16][MAX_SHARED_USERS=64];  64*16   280+1024=1304 
            uint8_t owner_sig[EDDSA_SIG_SIZE=64];                   64      1368
        };        
        """

        self.owner = struct.pack('=16s', str.encode(user))
        self.regions_id = self.create_max_regions(region_info, regions)
        self.wavdata = self.read_wav_header(path_to_song)
        # self.len_250ms = struct.pack('=I', 0)   
        self.len_250ms = self.find_len_250ms()
        # nr_segments = struct.pack('=I', 10)
        # self.mp_sig = self.init_sig()
        self.shared_users = self.init_shared_users()
        # self.owner_sig = self.init_sig()

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

def write_header(outfile, drm_header):
    global song_id, first_segment_size, mp_sig, owner_sig, nr_segments
    file = open(outfile, "ab+")
    file.write(song_id)
    file.write(drm_header.owner)
    file.write(drm_header.regions_id)
    file.write(drm_header.len_250ms)
    file.write(struct.pack('=I', nr_segments))
    file.write(first_segment_size)
    file.write(drm_header.wavdata)
    file.write(mp_sig)
    file.write(drm_header.shared_users)
    file.write(owner_sig)
    file.close()   

def get_sig(drm_header):
    global song_id, first_segment_size, nr_segments, mipod_key, mp_sig, owner_sig, owner_key
    # fileIn2 = open("rit.drm", "rb")
    # header = fileIn2.read(216)
    # print("header: ", header.hex())
    # fileout = open("test", "wb")
    # fileout.write(header)
    # fileout.close()
    # "iso-8859-1"
    # mp_sig_hash = fileIn2.read(64)
    # print("mp_sig_hash: ", mp_sig_hash)
    # fileIn2.read(1024)
    # owner_sig_hash = fileIn2.read(64)
    # print("owner_sig_hash: ", owner_sig_hash)
    # fileIn2.close()
    msg1 = song_id + drm_header.owner + drm_header.regions_id + drm_header.len_250ms + struct.pack('=I', nr_segments) + first_segment_size + drm_header.wavdata

    m = hmac.new(mipod_key, digestmod="sha512")
    m.update(msg1)
    mp_sig = m.digest()
    # print("mp_sig: ", mp_sig)

    msg2 = msg1 + mp_sig + drm_header.shared_users

    m = hmac.new(owner_key, digestmod="sha512")
    m.update(msg2)
    owner_sig = m.digest()
    # print("owner_sig: ", owner_sig)

class EncryptSong(object):
    def __init__(self, path_to_song):
        self.wav_size = 0
        self.key = self.gen_key()
        # nr_segments = (struct.unpack('=I', nr_segments))[0]
        self.first_segment_size = str.encode("%04d" % int(16 * 1000))  # block size
        self.encrypt_str = self.encrypt_song(path_to_song)
        # define the segment_trailer
        self.idx = struct.pack('=I', 0)
        self.next_segment_size = struct.pack('=I', 0)
        self.sig = init_sig()

    def gen_key(self):
        # if there is no aes.key file, genrate one
        # key = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        # key_file = open("aes.key", "w")
        # key_file.write(key)
        # key_file.close()
        
        # for debugging, we read the genreated aes.key file.
        key_file = open("aes.key", "rb")
        key = key_file.read()
        key_file.close()
        print(Transform(key))
        return Transform(key)

    def create_song_segment_trailer(self, en_segment, idx, next_segment_size):

        """
        struct segment_trailer {
        uint8_t id[SONGID_LEN];     //16
        uint32_t idx;               //4
        uint32_t next_segment_size;     //4
        uint8_t sig[HMAC_SIG_SIZE];
        char _pad_[40]; //do not use this. for cryptographic padding purposes only.
        };

        struct {
            char a[0-!(sizeof(struct segment_trailer) == 128 && CIPHER_BLOCKSIZE == 64)]; //if the segment trailer requirements fail, this will break.
        };
        """
        global mipod_key, song_id, pad
        # segment_trailer = bytearray()
        self.idx = struct.pack('=I', idx)
        if next_segment_size == 0:
            self.next_segment_size = struct.pack('=I', 0)
        else:
            self.next_segment_size = struct.pack('=I', next_segment_size + 128)
        msg = en_segment + song_id + self.idx + self.next_segment_size
        fileOut = open("segment-en", "wb")
        fileOut.write(msg)
        fileOut.close()

        # print('segment: ', msg)
        m = hmac.new(mipod_key, digestmod="sha512")
        # print("miod_key", mipod_key)
        m.update(msg)
        segment_sig = m.digest() 
        # print(segment_sig)     
        segment_trailer = msg + segment_sig + pad

        # print('en-segment: ', next_segment_size)
        # print('segment: ', len(segment_trailer))
        
        return segment_trailer

    def encrypt_song(self, path):
        # open file
        global nr_segments
        encrypt_song_str = bytearray()
        file_name = os.path.abspath(path)
        file_len = os.path.getsize(path)
        print("file_len: ", file_len)
        try:
            fileIn = open(file_name,"rb")
        except IOError as err:
            print("Could not open song file %s" % file_name)
            return
        wav_header = fileIn.read(44)
        # self.wav_size = (struct.unpack('I', wav_header[40:44]))[0]  
        self.wav_size = (struct.unpack('I', wav_header[4:8]))[0] - 44 + 8
        print("wav_size: ", self.wav_size)
        p = int(self.wav_size / 14336)
        remainder = int(self.wav_size % 14336)
        fill_block_size = 128 - int(remainder % 128)
        fill_block = bytearray(fill_block_size)

        self.first_segment_size = 14336
        
        # self.first_segment_size = block_in_each_segment * 16
        print('first_segment: ', self.first_segment_size)
        # print('the whole wav length: ', self.first_segment_size * (nr_segments - 1) + last_segment_size)

        # get the real last_segment
        # fill_block_size = int(nr_block % nr_segments)
        # fill_block_size = 16 - int(self.wav_size % 16) 
        # fill_block = bytearray(fill_block_size)
     
        # print('last_segment_size: ', last_segment_size)
        # last_segment_size = self.first_segment_size - fill_block_size
        # print('last_segment_size', last_segment_size)
        
        # encrypt the song segment by segment
        segment_cipher = AES.new(self.key, AES.MODE_ECB)
        # segment = fileIn.read(self.first_segment_size)
        # encrypt_segment = segment_cipher.encrypt(segment) 
        # encrypt_song_str = encrypt_song_str + self.create_song_segment_trailer(encrypt_segment, 0, self.first_segment_size)
        flag = 0
        segment_str = fileIn.read(self.first_segment_size)
        print("segment size: ", len(segment_str))
        segment_str = TransSeg(segment_str, len(segment_str))
        encrypt_segment = segment_cipher.encrypt(segment_str)
        # with open(file_name, "rb") as f:
        #     while True:
        #         dd = f.read()
        while fileIn.tell() < file_len:
            # print(fileIn.tell())
            segment = fileIn.read(self.first_segment_size)
            if len(segment) < self.first_segment_size:
                segment = segment + fill_block
                # flag = 1
            next_size = self.first_segment_size
            # if flag == 1:
            #     next_size = 0 
            segment = TransSeg(segment, len(segment))
            encrypt_song_str = encrypt_song_str + self.create_song_segment_trailer(encrypt_segment, nr_segments, next_size)
            encrypt_segment = segment_cipher.encrypt(segment)    
            nr_segments += 1    
        # print(fileIn.tell())
        # write file segment
        encrypt_song_str = encrypt_song_str + self.create_song_segment_trailer(encrypt_segment, nr_segments, 0)
        nr_segments += 1 
        fileIn.close()  

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
    protect_song = EncryptSong(args.infile)
    # The size of the first segment will be caculated when encrypt the song
    global first_segment_size, nr_segments
    first_segment_size = struct.pack('=I', protect_song.first_segment_size + 128)
    mp_sig = get_sig(drm_header)
    write_header(args.outfile, drm_header)
    protect_song.save_song(args.outfile)

if __name__ == '__main__':
    main()
