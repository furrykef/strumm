#!/usr/bin/env python
# Currently only designed for SCUMM 5. Might be easily tweaked for
# other versions. Ignores room names (which are in the index file
# anyway), but not object names. Requires descumm in PATH.
#
# Currently does not bother to separate strings by verb. If there
# are two verb scripts for an object, and both have a string, they
# will be grouped together as if they were in the same script.
#
# Written for Python 2.7.
#
# This code is released uner the MIT license.
# See COPYING.txt for details.
from __future__ import division
import argparse
import io
import os
import re
import struct
import subprocess
import sys
import tempfile


TEXT_RE = re.compile(r'Text\("([^"]+)"\)')


# Expected errors when processing a SCUMM file -- generally, when an
# incompatibility has been detected
class ScummFileError(Exception):
    pass

# Unexpected errors when processing -- should print traceback.
# Note that "unexpected" includes errors that occur with corrupted or
# malevolent SCUMM files (e.g. files that lie about the size of their
# blocks) -- but they're still expected enough that their detection
# shouldn't ever be turned off, and so 'assert' is inadequate.
class WTFError(Exception):
    pass


# Error when calling descumm
class DescummError(Exception):
    pass


class DecryptingStream(object):
    def __init__(self, stream, xor):
        self._stream = stream
        self._xor = xor

    # @TODO@ -- performance can probably be improved
    def read(self, *args, **kwargs):
        data = self._stream.read(*args, **kwargs)
        # The 'if' check is not necessary, but can save time :)
        if self._xor != 0:
            data = "".join(chr(ord(x) ^ self._xor) for x in data)
        return data

    def seek(self, *args, **kwargs):
        return self._stream.seek(*args, **kwargs)

    def tell(self):
        return self._stream.tell()


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    args = parseArgs(argv)

    if args.scumm_ver != 5:
        print >> sys.stderr, "Only SCUMM version 5 is supported"
        return 1

    try:
        with open(args.infile, 'rb') as infile:
            magic = infile.read(1)
            xor = ord(magic[0]) ^ ord('L')
            infile = DecryptingStream(infile, xor)
            infile.seek(0, os.SEEK_SET)
            magic = infile.read(4)
            if magic != 'LECF':
                raise ScummFileError("This is not a compatible SCUMM file.")
            infile.seek(0, os.SEEK_SET)
            processor = Processor(infile)
            processor.process()
    except IOError, e:
        print >> sys.stderr, "IO error:", e
        return 1
    except ScummFileError, e:
        print >> sys.stderr, "SCUMM file error:", e
        return 1
    except DescummError, e:
        print >> sys.stderr, "Error calling descumm:", e
        return 1


class Processor(object):
    def __init__(self, infile):
        self._infile = infile
        self._obj_dict = {}
        self._current_obj = None

    def process(self):
        self._processBlock()
        # Print out objects
        for key, value in self._obj_dict.items():
            print "***** OBJECT AT: %08X (%s) *****" % (key, value.name)
            print value.scripts

    # @TODO@ -- needs to be adjusted for versions earlier than 5.
    def _processBlock(self):
        hdr_offset = self._infile.tell()
        block_type = self._infile.read(4)
        raw_size = struct.unpack('>I', self._infile.read(4))[0]

        # @TODO@ - will be different value for versions earlier than 5.
        hdr_size = 8

        # The 'size' value includes the header that we just read.
        # We want the size of the actual data, so we subtract the
        # size of this header.
        size = raw_size - hdr_size

        if block_type in ('LECF', 'LFLF', 'ROOM'):
            # This block is a container
            self._processSubBlocks(size)
        elif block_type in ('SCRP', 'LSCR', 'ENCD', 'EXCD', 'VERB'):
            # This block is a script
            # Seek back to where the header was
            self._infile.seek(hdr_offset, os.SEEK_SET)
            result = self._handleScript(raw_size)
            if block_type == 'VERB':
                self._current_obj.scripts = result
            else:
                print "***** %s SCRIPT AT: %08X *****" % (block_type, hdr_offset)
                print result
        elif block_type == 'OBCD':
            # This block is an object
            self._current_obj = GameObj()
            self._obj_dict[hdr_offset] = self._current_obj
            self._processSubBlocks(size)
        elif block_type == 'OBNA':
            # This block is the name of the current object
            self._current_obj.name = self._readASCIIZ()
        else:
            # This block isn't recognized as a useful block type to us.
            # Skip it if it looks like an actual block; barf if not
            # (since that probably means we screwed up).
            if not isValidBlockType(block_type):
                raise WTFError("Invalid block type at offset %X" % hdr_offset)
            self._infile.seek(size, os.SEEK_CUR)

    def _processSubBlocks(self, size):
        end = self._infile.tell() + size
        while self._infile.tell() < end:
            self._processBlock()
        if self._infile.tell() > end:
            raise WTFError("Overshot the end of a block while processing sub-blocks!")

    def _handleScript(self, size):
        disasm = self._dissassembleScript(size)
        out_stream = io.BytesIO()
        for match in TEXT_RE.findall(disasm):
            print >> out_stream, "[String]"
            print >> out_stream, unescape(match)
            print >> out_stream
        return out_stream.getvalue()

    # @TODO@ - does not raise DescummError if descumm not found
    def _dissassembleScript(self, size):
        # Dump the script to a temporary file and process w/ descumm
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tf:
            tf.write(self._infile.read(size))
        try:
            # @TODO@ -- change '-5' as appropriate
            # @TODO@ -- capture stderr, too?
            cmd = subprocess.Popen(
                ['descumm', '-5', tf.name],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = cmd.communicate()
            if cmd.returncode != 0:
                raise DescummError("descumm returned non-zero result: %d\ndescumm's stderr:\n%s" % (cmd.returncode, stderr))
            return stdout
        finally:
            os.unlink(tf.name)

    # A bit of a misnomer since this will handle Shift-JIS strings
    # just fine ;)
    def _readASCIIZ(self):
        out = io.BytesIO()
        while True:
            ch = self._infile.read(1)
            if ch == '\0':
                return out.getvalue()
            out.write(ch)


def isValidBlockType(block_type):
    assert len(block_type) == 4
    for ch in block_type:
        if not ('A' <= block_type <= 'Z'):
            return False
    return True


def unescape(string):
    out = io.BytesIO()
    pos = 0
    while pos < len(string):
        ch = string[pos]
        if ch != '\\':
            out.write(ch)
            pos += 1
        else:
            pos += 1
            ch = string[pos]
            if ch == 'x':
                value = int(string[pos+1:pos+3], 16)
                out.write(chr(value))
                pos += 3
            elif ch == '\\':
                out.write('\\')
                pos += 1
            else:
                raise WTFError("Unexpected escape code: %s" % ch)
    return out.getvalue()


# GameObjs
class GameObj(object):
    __slots__ = ['name', 'scripts']


# @TODO@ -- argparse calls sys.exit() in case of '--help' or failure
def parseArgs(argv):
    parser = argparse.ArgumentParser(description="SCUMM text extractor")
    parser.add_argument(
        "scumm_ver",
        type=int
    )
    parser.add_argument(
        "infile",
        type=str,
        help="input file (e.g. monkeyk.001)"
    )
    return parser.parse_args(argv)


if __name__ == '__main__':
    sys.exit(main())
