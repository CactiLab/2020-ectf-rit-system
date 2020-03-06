#!/usr/bin/env python3
"""
Description: Protects song by adding metadata or any other security measures
Use: Once per song

./create_drm_header.py --song-id 2 --region-list "United States" "Japan" "Australia" --region-secrets-path region.secrets --outfile demo.drm --infile Sound-Bite_One-Small-Step.wav --owner "misha" --user-secrets-path user.secrets
"""
import json
import struct
import os
import wave
from argparse import ArgumentParser
import numpy as np

import random, string
from ctypes import create_string_buffer 

# ./create_drm_header.py --song-id 2 --region-list "United States" "Japan" "Australia" --region-secrets-path region.secrets --outfile demo.drm --infile Sound-Bite_One-Small-Step.wav --owner "misha" --user-secrets-path user.secrets

class CreateDrmHeader(object):
    def __init__(self, path_to_song, regions, user, user_secret_location, region_info, song_id):
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
        # self.song_id = "".join(random.sample(string.ascii_letters + string.digits, 16))
        self.song_id = os.urandom(16)
        self.owner = str.encode("%016s" % (user))
        self.regions_id = self.create_max_regions(region_info, regions)
        self.len_250ms = str.encode("%04d" % int())
        self.nr_segments = str.encode("%04d" % int("4"))
        self.first_segment_size = str.encode("%04d" % int())
        self.wavdata = self.read_wav_header(path_to_song)
        self.mp_sig = self.init_sig()
        self.shared_users = self.init_shared_users()
        self.owner_sig = self.init_sig()

    def str_to_byte(self, str):
        return str.encode(str)

    def create_max_regions(self, region_info, regions):
        rid = ''
        for i in regions:
            rid = rid + ("%04d" % int(region_info[str(i)]))
        for i in range(len(regions), 32):
            rid = rid + ("%04d" % int())
        return str.encode(rid)

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
        shared_users = ''
        for i in range(0, 64):
            shared_users = shared_users + ("%016d" % int())
        return str.encode(shared_users)

    def init_sig(self):
        owner_sig = ''
        for i in range(0, 4):
            owner_sig = owner_sig + "".join(random.sample(string.ascii_letters + string.digits, 16))
        return str.encode(owner_sig)

    def write_drm_header(self):
        file = open('drm_header.drm', "ab+")
        file.write(self.song_id)
        file.write(self.owner)
        file.write(self.regions_id)
        file.write(self.len_250ms)
        file.write(self.nr_segments)
        file.write(self.first_segment_size)
        file.write(self.wavdata)
        file.write(self.mp_sig)
        file.write(self.shared_users)
        file.write(self.owner_sig)
        file.close()


def main():
    parser = ArgumentParser(description='main interface to protect songs')
    parser.add_argument('--song-id', help='List of song ids can be inserted in', required=True)
    parser.add_argument('--region-list', nargs='+', help='List of regions song can be played in', required=True)
    parser.add_argument('--region-secrets-path', help='File location for the region secrets file',
                        required=True)
    parser.add_argument('--outfile', help='path to save the protected song', required=True)
    parser.add_argument('--infile', help='path to unprotected song', required=True)
    parser.add_argument('--owner', help='owner of song', required=True)
    parser.add_argument('--user-secrets-path', help='File location for the user secrets file', required=True)
    args = parser.parse_args()

    print (args)

    regions = json.load(open(os.path.abspath(args.region_secrets_path)))

    drm_header = CreateDrmHeader(args.infile, args.region_list, args.owner, args.user_secrets_path, regions, args.song_id)
    drm_header.write_drm_header()

if __name__ == '__main__':
    main()
