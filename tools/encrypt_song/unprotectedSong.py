#!/usr/bin/env python3
"""
Description: UnProtects song by adding metadata or any other security measures
Use: Once per song
Usage:
./unprotectedSong.py --infile protectRITdemo.drm --outfile unprotectRIT.wav --keyfile aes.key
output: decrypted song
"""
import json
import struct
import os
import wave
from argparse import ArgumentParser
import numpy as np

import random, string
from Crypto.Cipher import AES

class ReadDrmHeader(object):
    def __init__(self, path_to_song):
        """
        struct drm_header { //sizeof() = 1368
            uint8_t song_id[SONGID_LEN=16];                         16      0:16
            char owner[UNAME_SIZE=16];                              16      16:32     
            uint32_t regions[MAX_SHARED_REGIONS=32];                128     32:160
            uint32_t len_250ms;                                     4       160:164
            uint32_t nr_segments;                                   4       164:168
            uint32_t first_segment_size;                            4       168:172
            struct wav_header wavdata;                              44      172:216
            uint8_t mp_sig[EDDSA_SIG_SIZE=64]; //miPod signature    64      216:280
            char shared_users[UNAME_SIZE=16][MAX_SHARED_USERS=64];  64*16   280:1304
            uint8_t owner_sig[EDDSA_SIG_SIZE=64];                   64      1304:1368
        };        
        """
        self.drmdata = self.read_drm_header(path_to_song) 
        self.nr_segments = (struct.unpack('=I', self.drmdata[164:168]))[0]
        self.first_segment_size = (struct.unpack('=I', self.drmdata[168:172]))[0]
        self.protectsong = bytearray()

    def read_drm_header(self, path):
        # open file
        file_name = os.path.abspath(path)
        try:
            fileIn = open(file_name,"rb")
        except IOError as err:
            print("Could not open song file %s" % file_name)
            return
        bufHeader = fileIn.read(1368)
        fileIn.close()
        return bufHeader

class DecryptSong(object):
    def __init__(self, nr_segments, first_segment_size, path_to_protectsong):
        self.key = self.get_key()
        self.nr_segments = nr_segments
        self.first_segment_size = first_segment_size  # block size
        # self.encrypt_str = self.read_protectsong(path_to_protectsong)
        self.decrypt_str = self.decrypt_song(nr_segments, first_segment_size, path_to_protectsong)

    def get_key(self):
        key_file = open("aes.key", "rb")
        key = key_file.read()
        key_file.close()
        return key

    def decrypt_song(self, nr_segments, first_segment_size, path_to_protectsong):
        # open file
        decrypt_song_str = bytearray()
        segment = bytearray()
        file_name = os.path.abspath(path_to_protectsong)
        try:
            fileIn = open(file_name,"rb")
        except IOError as err:
            print("Could not open song file %s" % file_name)
            return
        bufHeader = fileIn.read(1368)

        # encrypt the song segment by segment
        segment_decipher = AES.new(self.key, AES.MODE_ECB)
        for i in range(0, self.nr_segments - 1):
            segment = fileIn.read(self.first_segment_size)  
            decrypt_song_str = decrypt_song_str + segment_decipher.decrypt(segment)
        segment = fileIn.read()
        decrypt_song_str = decrypt_song_str + segment_decipher.decrypt(segment)

        return decrypt_song_str

    def save_song(self, outfile):
        fileOut = open(outfile, "ab+")
        fileOut.write(self.decrypt_str)
        fileOut.close

def main():
    parser = ArgumentParser(description='main interface to protect songs')
    parser.add_argument('--outfile', help='path to save the unprotected song', required=True)
    parser.add_argument('--infile', help='path to protected song', required=True)
    parser.add_argument('--keyfile', help='the key to decrypt the song', required=True)
    args = parser.parse_args()

    drm_header = ReadDrmHeader(args.infile) 
    nr_segments = drm_header.nr_segments
    first_segment_size = drm_header.first_segment_size

    protect_song = DecryptSong(nr_segments, first_segment_size, args.infile)

    protect_song.save_song(args.outfile)

if __name__ == '__main__':
    main()
