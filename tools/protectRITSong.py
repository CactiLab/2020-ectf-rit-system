#!/usr/bin/env python3
"""
Description: Protects song by adding metadata or any other security measures
Use: Once per song
Usage:
./protectRITSong.py --song-id 2 --region-list "United States" "Japan" "Australia" --region-secrets-path region.secrets --outfile demo.drm --infile Sound-Bite_One-Small-Step.wav --owner "misha" --user-secrets-path user.secrets
output: encrypted song, aes.key will be sent to firmware
"""
import json
import struct
import os
from argparse import ArgumentParser
import numpy as np

import random, string
from Crypto.Cipher import AES

class CreateDrmHeader(object):
    first_segment_size = struct.pack("=I", 0)
    def __init__(self, path_to_song, regions, user, user_secret_location, region_info):
        """
        struct drm_header { //sizeof() = 1368
            uint8_t song_id[SONGID_LEN=16]; 
            char owner[UNAME_SIZE=16]; 
            uint32_t regions[MAX_SHARED_REGIONS=32]; 
            uint32_t len_250ms; 
            uint32_t nr_segments; 
            uint32_t first_segment_size;
            struct wav_header wavdata;
            uint8_t mp_sig[EDDSA_SIG_SIZE=64]; //miPod signature
            char shared_users[UNAME_SIZE=16][MAX_SHARED_USERS=64]; 
            uint8_t owner_sig[EDDSA_SIG_SIZE=64];          
        };        
        """
        self.song_id = str.encode("".join(random.choices(string.digits, k=16)))
        self.owner = struct.pack('=16s', str.encode(user))
        self.regions_id = self.create_max_regions(region_info, regions)
        self.len_250ms = struct.pack('=I', 0)
        self.nr_segments = struct.pack('=I', 4)
        self.wavdata = self.read_wav_header(path_to_song)
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
        bufHeader = fileIn.read(38)
        # Verify that the correct identifiers are present
        # print(bufHeader[0:4])
        # print(bufHeader[12:16])
        # if (bufHeader[0:4] != 'RIFF') or \
        #     (bufHeader[12:15] != 'fmt '):
        #     print(("Input file is not a standard WAV file"))
        #     return
        return bufHeader

    def init_shared_users(self):
        shared_users = bytearray()
        for i in range(0, 64):
            shared_users = shared_users + struct.pack("=4s", str.encode(''))
        return shared_users

    def init_sig(self):
        owner_sig = ''
        for i in range(0, 4):
            owner_sig = owner_sig + "".join(random.sample(string.ascii_letters + string.digits, 16))
        return str.encode(owner_sig)

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
        key = os.urandom(16)
        key_file = open("aes.key", "ab")
        key_file.write(key)
        key_file.close()
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
        file_stats = (os.stat(file_name)).st_size
        self.wav_size = file_stats
        # calculate the number of block_size (16)
        nr_block = int(file_stats / 16) + 1
        # the encrypt data should be the multiple of 16, so we need to fill the last block to 16
        fill_block_size = 16 - int(file_stats % 16)
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

    drm_header = CreateDrmHeader(args.infile, args.region_list, args.owner, args.user_secrets_path, regions) 
    nr_segments = drm_header.nr_segments
    protect_song = EncryptSong(nr_segments, args.infile)
    CreateDrmHeader.first_segment_size = struct.pack('=I', protect_song.first_segment_size)
    write_header(args.outfile, drm_header)
    protect_song.save_song(args.outfile)

if __name__ == '__main__':
    main()
