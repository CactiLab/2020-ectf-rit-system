#!/usr/bin/env python3
"""
usage: ./replace_AES_key.py aes.key
"""

import os
import struct
from argparse import ArgumentParser

def replace_aes_key(file_name):
        try:
            fileIn = open(file_name,"rb")
        except IOError as err:
            print("Could not open song file %s" % file_name)
            return
        aes_key_bytes = fileIn.read()
        aes_key = aes_key_bytes.hex()
        # aes_key = struct.unpack('16s', aes_key_bytes)
        # aes_key = bytes.decode(aes_key_bytes, 'iso-8859-1')
        # IQZQN9BCqGt6OPuH 49515a514e394243714774364f507548
        command = './replace_AES_key.sh ' + aes_key
        print(command)
        os.system(command)

def main():
    parser = ArgumentParser(description='main interface to replace the aes key')
    parser.add_argument('--infile', help='File location for the key file',
                        required=True)
    args = parser.parse_args()
    replace_aes_key(args.infile)

if __name__ == '__main__':
    main()