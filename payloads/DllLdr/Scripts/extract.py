#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import sys
import struct
import argparse

def main(options):
    with open(options.f, 'rb') as f:
        object_file = f.read()

    num_sections = struct.unpack('<H', object_file[2 : 2 + 2])[0]
    #print(f"num_sections: {num_sections}")

    for num_section in range(num_sections):
        size_header = 20
        size_section = 40
        section = object_file[size_header + (size_section * num_section) : size_header + (size_section * num_section) + size_section]
        name = struct.unpack('8s', section[:8])[0].decode('ascii').rstrip('\x00')
        if name == '.text':
            size_of_raw_data = struct.unpack('<I', section[16: 16 + 4])[0]
            #print(f'size_of_raw_data: {hex(size_of_raw_data)}')
            pointer_to_raw_data = struct.unpack('<I', section[20: 20 + 4])[0]
            #print(f'pointer_to_raw_data: {hex(pointer_to_raw_data)}')
            text_section = object_file[pointer_to_raw_data: pointer_to_raw_data + size_of_raw_data]
            with open(options.o, 'wb') as f:
                f.write(text_section)
            return

    print('.text section not found')


if __name__ == '__main__':
    parser = argparse.ArgumentParser( description = 'Extracts shellcode from an Object File.' );
    parser.add_argument( '-f', required = True, help = 'Path to the source executable', type = str );
    parser.add_argument( '-o', required = True, help = 'Path to store the output raw binary', type = str );
    options = parser.parse_args();
    main(options)
