#!/usr/bin/env python

import argparse
import os
import struct
import sys

def auto_int(x):
    return int(x, 0)

def decompress_mio0(raw_bytes):
    magic = raw_bytes[:4]
    assert magic == b'MIO0'

    uncompressed_size, lengths_offs, data_offs = struct.unpack('>LLL', raw_bytes[4:16])
    flags_offs = 0x10

    output = b""
    while True:
        command_byte = raw_bytes[flags_offs]
        flags_offs += 1

        for i in reversed(range(8)):
            if command_byte & (1 << i):
                # Literal
                uncompressed_size -= 1
                output += bytes([raw_bytes[data_offs]])
                data_offs += 1
            else:
                # LZSS
                tmp, = struct.unpack('>H', raw_bytes[lengths_offs:lengths_offs+2])
                lengths_offs += 2

                window_offset = (tmp & 0x0FFF) + 1
                window_length = (tmp >> 12) + 3
                uncompressed_size -= window_length
                for j in range(window_length):
                    output += bytes([output[-window_offset]])

            if uncompressed_size <= 0:
                return output

def print_hex_dump(raw_bytes):
    count = 0
    for b in raw_bytes:
        if count % 16 == 0:
            sys.stdout.write(' ' * 4)
        sys.stdout.write('{:02x} '.format(b))
        count += 1
        if count % 16 == 0:
            sys.stdout.write('\n')
    if count % 16:
        sys.stdout.write('\n')

def pw64_dump_filesys(fname, startOffset, hexSize, outputDir):
    currentDumpFilename = None

    if outputDir:
        os.makedirs(outputDir, exist_ok=True)

    def dump_binary(raw_bytes):
        if outputDir and currentDumpFilename is not None:
            with open(f'{outputDir}/{currentDumpFilename}', 'wb') as f:
                f.write(raw_bytes)

        if hexSize > 0:
            if len(raw_bytes) > hexSize:
                raw_bytes = raw_bytes[:hexSize]
            print_hex_dump(raw_bytes)

    def chunk_iter():
        while (fin.tell() < formEnd):
            chunkType = fin.read(4)
            chunkTypeStr = chunkType.decode('utf-8')

            # Special handling: GZIP chunks are decompressed before they're interpreted
            if chunkType == b'GZIP':
                gzipLength = int.from_bytes(fin.read(4), byteorder='big')
                absOffset = fin.tell() + gzipLength
                magic = fin.read(4)
                magicStr = magic.decode('utf-8')
                decompLength = int.from_bytes(fin.read(4), byteorder='big')

                compBytes = fin.read(gzipLength - 8)

                length = decompLength
                rawBytes = decompress_mio0(compBytes)
            else:
                length = int.from_bytes(fin.read(4), byteorder='big')
                rawBytes = fin.read(length)
                magicStr = chunkTypeStr

            yield magicStr, rawBytes

    def print_chunk_header(magicStr, rawBytes, extra=''):
        fileOffset = fin.tell()
        print('0x%06X|%06X:   %s: 0x%06X: %s' % (fileOffset, fileOffset - startOffset, magicStr, len(rawBytes), extra))

    with open(fname, 'rb') as fin:
        fin.seek(startOffset)
        while True:
            fileOffset = fin.tell()
            sys.stdout.write('0x%06X|%06X: ' % (fileOffset, fileOffset - startOffset))
            magic = fin.read(4)

            if len(magic) == 0 or magic == b'\0\0\0\0': # End of file
                break

            # All entries should be FORMs
            assert magic == b'FORM'
            formLength = int.from_bytes(fin.read(4), byteorder='big')
            formEnd = fin.tell() + formLength
            formType = fin.read(4)
            formTypeStr = formType.decode('utf-8')
            print('%s: 0x%06X (end: 0x%06X)' % (formTypeStr, formLength, formEnd))
            chunkIndex = 0

            currentDumpPrefix = f'{formTypeStr}_0x{fileOffset:X}'
            currentDumpFilename = None

            if formTypeStr == 'UVSQ':
                # UVSQ has a single COMM block
                for magicStr, rawBytes in chunk_iter():
                    print_chunk_header(magicStr, rawBytes)
                    if magicStr == 'COMM':
                        count = int(rawBytes[0])
                        uvsq = '>Hf'
                        # +1 becuase last u16/float might be special
                        for i in range(count + 1):
                            (idx, val) = struct.unpack(uvsq, rawBytes[1+6*i:7+6*i])
                            print('    0x%04X: %f' % (idx, val))
            elif formTypeStr == 'PDAT':
                for magicStr, rawBytes in chunk_iter():
                    if magicStr == 'PPOS':
                        floats = struct.unpack('>ffffff', rawBytes)
                        print_chunk_header(magicStr, rawBytes, '%g %g %g %g %g %g' % floats)
                    else:
                        print_chunk_header(magicStr, rawBytes)
                        dump_binary(rawBytes)
            else:
                # Generic handler
                for magicStr, rawBytes in chunk_iter():
                    length = len(rawBytes)
                    currentDumpFilename = f'{currentDumpPrefix}_{chunkIndex}_{magicStr}.bin'

                    if magicStr == 'PAD ': # PAD always seems to be 4 bytes of 0 - ignore it
                        print_chunk_header(magicStr, rawBytes)
                    elif magicStr == 'NAME': # ASCII name identifier
                        nameStr = rawBytes.decode('utf-8').rstrip('\0')
                        print_chunk_header(magicStr, rawBytes, nameStr)
                    elif magicStr == 'INFO': # usually mission objective
                        infoStr = rawBytes.decode('utf-8').rstrip('\0')
                        print_chunk_header(magicStr, rawBytes, infoStr)
                    elif magicStr == 'JPTX': # some ASCII identifier
                        infoStr = rawBytes.decode('utf-8').rstrip('\0')
                        print_chunk_header(magicStr, rawBytes, infoStr)
                    elif magicStr in ['PART', 'STRG', 'BITM', 'FRMT', 'IMAG',
                                      'ESND', 'TPAD', 'CNTG', 'HOPD', 'LWIN',
                                      'LSTP', 'TARG', 'FALC', 'BALS', 'HPAD',
                                      'BTGT', 'THER', 'PHTS', 'SIZE', 'DATA',
                                      'QUAT', 'XLAT', 'PHDR', 'RHDR', 'PPOS',
                                      'RPKT', 'COMM',
                                      '.CTL', '.TBL',
                                      'SCPP', 'SCPH', 'SCPX', 'SCPY', 'SCPR', 'SCPZ', 'SCP#',
                                      'LEVL', 'RNGS', 'BNUS', 'WOBJ', 'LPAD', 'TOYS', 'TPTS', 'APTS']:
                        print_chunk_header(magicStr, rawBytes)
                        dump_binary(rawBytes)
                    else:
                        # Should not happen.
                        assert False

                chunkIndex += 1
        else:
            # Should not happen.
            assert False

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Pilotwings 64 File System Dumper')
    ap.add_argument('file', help='File path of input')
    ap.add_argument('-s', '--start', dest='startOffset', type=auto_int, default=0x0DF5B0, help='Start offset of file system')
    ap.add_argument('-x', '--hex', dest='hexSize', type=auto_int, default=0x60, help='Size of hexdump for unparsed sections')
    ap.add_argument('-o', '--output-dir', dest='outputDir', help="Automatically dump and decompress individual files")
    args = ap.parse_args()
    pw64_dump_filesys(args.file, args.startOffset, args.hexSize, args.outputDir)
