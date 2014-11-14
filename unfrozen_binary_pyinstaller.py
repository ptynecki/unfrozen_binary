#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = 'Katharsis'
__copyright__ = 'Copyright 2014, Piotr Tynecki'
__license__ = 'BSD'
__version__ = '1.0'

import marshal
import os
import shutil
import sys
import struct
import zlib

from common import uncompyle_decompilation
from common import unpyc3

# import logging
#
# logging.basicConfig(level=logging.INFO)
#
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.INFO)
#
# if os.path.exists('hello.log'):
#     os.remove('hello.log')
#
# handler = logging.FileHandler('hello.log')
# handler.setLevel(logging.INFO)
#
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# handler.setFormatter(formatter)
#
# logger.addHandler(handler)


class UnfrozenPyInstaller(object):
    def __init__(self, exe_file):
        self.exe_file = exe_file

        self.exe_file_source = open(self.exe_file, 'rb')

        exe_file_path = os.path.abspath(self.exe_file)

        self.COOKIE_SIZE = 24
        self.MAGIC = 'MEI\014\013\012\013\016'

        self.end = None

        self.PYC_HEADER = None

        self.magic = None
        self.length_of_package = None
        self.TOC = None
        self.TOClen = None
        self.pyvers = None
        self.pylibname = None

        self.current_path = os.getcwd()

        dir_name = os.path.splitext(os.path.basename(exe_file_path))[0]

        # Deletes previous output directory than creates a new one
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)

        os.mkdir(dir_name)
        os.chdir(dir_name)

        self.pyc_files = []

    def read_and_check(self):
        # Navigaate to EOF
        self.exe_file_source.seek(0, os.SEEK_END)

        # Get EOF Position
        self.end = self.exe_file_source.tell()

        # Navigate to COOKIE position
        self.exe_file_source.seek(self.end - self.COOKIE_SIZE, os.SEEK_SET)

        magic = self.exe_file_source.read(8)

        if magic != self.MAGIC:
            # Check new pyinstaller format

            self.exe_file_source.seek(0, os.SEEK_END)

            self.COOKIE_SIZE += 64

            self.exe_file_source.seek(self.end - self.COOKIE_SIZE, os.SEEK_SET)

            magic = self.exe_file_source.read(8)

            if magic != self.MAGIC:
                sys.exit('Error: Magic mismatch - not a PyInstaller archive')

        # Navigate to COOKIE position
        self.exe_file_source.seek(self.end - self.COOKIE_SIZE, os.SEEK_SET)

        # Read CArchive cookie
        # magic - MEI\014\013\012\013\016
        # length_of_package - len of entire package
        # TOC - pos (rel to start) of TableOfContents
        # TOClen - length of TableOfContents
        # pyvers - version of Python
        # pylibname - ???

        try:
            # ! - network (big-endian)
            # 8s - 8-byte string, 4i - means exactly iiii
            # s - char[], string
            # i - int, integer (4 size)
            if self.COOKIE_SIZE == 24:
                self.magic, self.length_of_package, self.TOC, self.TOClen, self.pyvers = struct.unpack(
                    '!8s4i',
                    self.exe_file_source.read(self.COOKIE_SIZE)
                )
            elif self.COOKIE_SIZE == 88:
                self.magic, self.length_of_package, self.TOC, self.TOClen, self.pyvers, self.pylibname = struct.unpack(
                    '!8s4i64s',
                    self.exe_file_source.read(self.COOKIE_SIZE)
                )
        except struct.error:
            sys.exit('Error: Unsupported PyInstaller version or not a PyInstaller archive')

        if self.pyvers == 27:
            self.PYC_HEADER = '\x03\xF3\x0D\x0A\x00\x00\x00\x00'
        elif self.pyvers == 26:
            self.PYC_HEADER = '\xD1\xF2\x0D\x0A\x00\x00\x00\x00'
        elif self.pyvers == 25:
            self.PYC_HEADER = '\xB3\xF2\x0D\x0A\x00\x00\x00\x00'
        else:
            sys.exit('Error: Unsupported Python version - only Python 2.5, 2.6, 2.7 are supported')

        print(u"Magic: {0}".format(repr(self.magic)))
        print(u"Length of package: {0}".format(repr(self.length_of_package)))
        print(u"Position of TableOfContents: {0}".format(repr(self.TOC)))
        print(u"Length of TableOfContents: {0}".format(repr(self.TOClen)))
        print(u"Python version: {0}".format(repr(self.pyvers)))
        print(u"Python library name: {0}".format(repr(self.pylibname.rstrip('\x00')) if self.pylibname else None))

    def unpack_carchive_and_zlibarchive(self):
        # The data that is appended at the end of the PE file
        data_pos = self.end - self.length_of_package

        #Now read CArchive table position content
        self.exe_file_source.seek(-self.length_of_package, os.SEEK_END)
        self.exe_file_source.seek(self.TOC, os.SEEK_CUR)

        remaining = self.TOClen

        print("\nInside of the CArchive")

        while remaining > 0:
            toc_length = struct.unpack('!i', self.exe_file_source.read(4))[0]

            print("\nThis TOC length: {0}".format(repr(toc_length)))

            #4 bytes already read in previous step
            file_info = struct.unpack(
                '!iiiBc%ds' % (toc_length - 18),
                self.exe_file_source.read(toc_length - 4)
            )

            toc_position = file_info[0]
            compressed_data_size = file_info[1]
            uncompressed_data_size = file_info[2]
            compressed_flag = file_info[3]
            type_compressed_data = file_info[4]
            name = file_info[5]

            print("This TOC position: {0}".format(toc_position))
            print("Compressed data size: {0}".format(compressed_data_size))
            print("Uncompressed data size: {0}".format(uncompressed_data_size))
            print("Compression flag: {0}".format(compressed_flag))
            # b - binary, z - zlib, m - module, s - script,  x - data, o - runtime option
            print("Compression type: {0}".format(type_compressed_data))

            #Remove trailing null bytes from name
            name = name.rstrip('\00').replace('\\', '/')

            if type_compressed_data == 's':
                name = "%s.py" % name
            elif type_compressed_data == 'm':
                name = "%s.pyc" % name

            print("\nName: {0}".format(name))

            #Save current file ptr
            saved_pointer = self.exe_file_source.tell()

            #Navigate to this data
            self.exe_file_source.seek(data_pos + toc_position)

            #Now read the data
            buf = self.exe_file_source.read(compressed_data_size)

            #Now decompress the data if it is compressed
            if compressed_flag == 1:
                buf = zlib.decompress(buf)

            # Remove bad sign from EOF for Python source file
            if type_compressed_data == 's':
                buf = buf[:-1]

            directory_path = os.path.dirname(name)

            print("Directory: {0}".format(directory_path if directory_path else "current"))

            if directory_path != '':
                #Check if path exists, create if not
                if not os.path.exists(directory_path):
                    os.makedirs(directory_path)

            fd = open(name, 'wb')
            fd.write(buf)
            fd.close()

            #Now if the file is a pyz extract its contents
            if type_compressed_data == 'z':
                #Create a directory having same name as that of the pyz with _extracted appended
                directory_name = name + '_extracted'

                if not os.path.exists(directory_name):
                    os.mkdir(directory_name)

                #Open the pyz file
                archive = open(name, 'rb')
                #Skip 8 bytes (MAGIC)
                archive.seek(8)

                offset = struct.unpack("!i", archive.read(4))[0]

                archive.seek(offset)

                toc = marshal.load(archive)

                for key in toc.keys():
                    ispkg, pos, length = toc.get(key)
                    #print "\tispkg:", ispkg
                    #print "\tPosition:", pos
                    #print "\tLength:", length

                    archive.seek(pos)

                    compressedobj = archive.read(length)

                    decomp = zlib.decompress(compressedobj)

                    pyc_file_path = os.path.join(directory_name, key + ".pyc")

                    pyc_file = open(pyc_file_path, 'wb')

                    #Pyinstaller always removes the pyc file header, we have to add it to make the pyc file valid
                    pyc_file.write(self.PYC_HEADER)
                    pyc_file.write(decomp)
                    pyc_file.close()

                    self.pyc_files.append(pyc_file_path)

                archive.close()

            #Now go to saved file ptr
            self.exe_file_source.seek(saved_pointer)

            remaining = remaining - toc_length

    def get_additional_pyc_files(self):
        """ Returns additional .pyc files from main directory """
        self.pyc_files.extend([f for f in os.listdir(".") if f.endswith('.pyc')])

    @staticmethod
    def decompilation(file_name):
        """ Runs unpyc3 or uncompyle2 decompiler """
        if sys.version_info[:2] == (3, 3):
            file_name = os.path.basename(unpyc3(file_name))
        elif sys.version_info[0] in (1, 2):
            dec_file_name = uncompyle_decompilation(file_name)

            if dec_file_name:
                os.path.basename(dec_file_name)
            else:
                print("{0} file can't be decompiled".format(file_name))
        else:
            print("It's impossible to decompile: {0}".format(os.path.basename(file_name)))

            return

        print("\nPython source code file: {0}".format(file_name))

    def unfrozen(self):
        """ Runs re algorithm in correct order """
        self.read_and_check()
        self.unpack_carchive_and_zlibarchive()

        self.get_additional_pyc_files()

        # Decompilation for .pyc files
        for pyc_file in self.pyc_files:
            self.decompilation(pyc_file)

        os.chdir(self.current_path)

        print("\nWork is done.")


if __name__ == "__main__":
    pyinstaller_1 = UnfrozenPyInstaller(sys.argv[1])
    pyinstaller_1.unfrozen()