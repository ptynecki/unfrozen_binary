#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = 'Katharsis'
__copyright__ = 'Copyright 2014, Piotr Tynecki'
__license__ = 'BSD'
__version__ = '1.0'


import marshal
import imp
import ntpath
import os
import shutil
import sys
import time
import struct
import zipfile

import pefile

from common import magic_numbers
from common import uncompyle_decompilation
from common import unpyc3


class UnfrozenPy2exe(object):
    def __init__(self, exe_file):
        self.exe_file = exe_file

        exe_file_path = os.path.abspath(self.exe_file)

        self.current_path = os.getcwd()

        dir_name = os.path.splitext(os.path.basename(exe_file_path))[0]

        # Deletes previous output directory than creates a new one
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)

        os.mkdir(dir_name)
        os.chdir(dir_name)

        self.pe = pefile.PE(exe_file_path)

        self.res = None
        self.data = None

        self.current = struct.calcsize('4i')
        self.metadata = None

        self.pyc_files = []

    def get_pythonscript_resource(self):
        """ Returns PYTHONSCRIPT entry """
        res = None

        for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.name and entry.name.string == u"PYTHONSCRIPT":
                res = entry.directory.entries[0].directory.entries[0]

                break

        self.res = res

        return res

    def dump_pythonscript_resource(self):
        """  Returns the dump of the given resource """
        rva = self.res.data.struct.OffsetToData
        size = self.res.data.struct.Size

        data = self.pe.get_data(rva, size)

        # Read py2exe header to get magic number, unbuffered & optimize flags and code bytes length
        self.metadata = struct.unpack('4i', data[:self.current])

        print("Magic value: {0}".format(self.metadata[0]))
        print("optimize flag: {0}".format(self.metadata[1]))
        print("unbuffered flag: {0}".format(self.metadata[2]))
        print("Code bytes length: {0}".format(self.metadata[3]))

        self.data = data

        return data

    def get_archive_name(self):
        """ Returns archive .zip name or empty string if doesn't exists """
        arcname = ""

        if sys.version_info[0] >= 3:
            while chr(self.data[self.current]) != "\000":
                arcname += chr(self.data[self.current])

                self.current += 1
        else:
            while self.data[self.current] != "\000":
                arcname += self.data[self.current]

                self.current += 1

        if arcname:
            print("\nArchive name: {0}\n".format(arcname))
        else:
            print("\nArchive is embedded. Unzipping the binary.")

        return arcname

    @staticmethod
    def get_current_magic():
        """ Returns current Python magic number """
        return imp.get_magic()

    @staticmethod
    def get_timestamp():
        """ Generates timestamp data for .pyc header """
        today = time.time()
        ret = struct.pack('=L', int(today))

        return ret

    def set_pyc_files(self):
        """ Saves Python .pyc or .pyo files from the binary and returns list of them """
        if sys.version_info[0] >= 3:
            code_bytes = self.data[self.current + 1:]
        else:
            code_bytes = self.data[self.current + 1:-2]

        code_objects = marshal.loads(code_bytes)

        bytecode_ext = 'pyc'

        if self.metadata[1]:
            bytecode_ext = 'pyo'

        for co in code_objects:
            pyc_header = self.get_current_magic() + self.get_timestamp()
            pyc_basename = os.path.splitext(co.co_filename)
            pyc_name = ntpath.basename(r"%s.%s" % (pyc_basename[0], bytecode_ext))

            print("Extracting: {0}".format(pyc_name))

            destination = pyc_name

            pyc = open(destination, 'wb')
            pyc.write(pyc_header)

            marshaled_code = marshal.dumps(co)

            pyc.write(marshaled_code)
            pyc.close()

            self.pyc_files.append(pyc_name)

    @staticmethod
    def get_magic_number_and_mod_date(file_name):
        """ Returns tuple with magic number and modyfication time of .pyc file """
        if os.path.isfile(file_name) and os.path.splitext(file_name)[1] in ('.pyc', '.pyo'):
            with open(file_name, 'rb') as f:
                magic_number_hex = f.read(4)

                try:
                    unix_time = struct.unpack('=II', f.read(8))
                    timestamp = time.asctime(time.localtime(unix_time[0]))

                    magic_number_value = struct.unpack('H2B', magic_number_hex)
                except struct.error:
                    raise Exception("Error: Bad file format or file doesn't exists")

                python_version = magic_numbers.get(magic_number_value[0], '')

                if magic_number_value[1:] != (13, 10):
                    raise Exception("Error: Wrong magic bytes: %s" % magic_number_hex.encode('hex'))

                if not python_version:
                    raise Exception("Error: Unknown Python version or wrong magic bytes")

                print("\nPython bytecode file: {0}".format(file_name))
                print("Python version: {0}".format(python_version))
                print("Modyfication time: {0}".format(timestamp))

                return python_version, unix_time[0], timestamp

        raise Exception("Error: Bad file format or file doesn't exists")

    @staticmethod
    def decompilation(file_name):
        """ Runs unpyc3 or uncompyle2 decompiler """
        if sys.version_info[:2] == (3, 3):
            file_name = os.path.basename(unpyc3(file_name))
        elif sys.version_info[0] in (1, 2):
            file_name = os.path.basename(uncompyle_decompilation(file_name))
        else:
            print("It's impossible to decompile: {0}".format(os.path.basename(file_name)))

            return

        print("\nPython source code file: {0}".format(file_name))

    def unpack_archive(self, archive_name):
        """ Unpacks .zip archive for rest .pyc files or unpack binary """
        if archive_name:
            archive = zipfile.ZipFile(
                os.path.join(
                    self.current_path,
                    os.path.split(self.exe_file)[0],
                    archive_name
                )
            )

            extraction_path = os.path.splitext(archive_name)[0]

            archive.extractall(extraction_path)
        else:
            archive = zipfile.ZipFile(
                os.path.join(
                    self.current_path,
                    self.exe_file
                )
            )

            extraction_path = os.path.join(os.getcwd(), 'library')

            archive.extractall(extraction_path)

        archive_pyc_files = []

        for path, dirs, files in os.walk(extraction_path):
            for f in files:
                archive_pyc_files.append(os.path.join(path, f))

        return archive_pyc_files

    def unfrozen(self):
        """ Runs re algorithm in correct order """
        self.get_pythonscript_resource()
        self.dump_pythonscript_resource()

        archive_name = self.get_archive_name()

        self.set_pyc_files()

        # Decompilation for boot and main Python script
        for pyc_file in self.pyc_files:
            self.get_magic_number_and_mod_date(pyc_file)
            self.decompilation(pyc_file)

        # Decompilation for rest .pyc files (inside of archive or binary)
        for pyc_file in self.unpack_archive(archive_name):
            self.decompilation(pyc_file)

        os.chdir(self.current_path)

        print("\nWork is done.")

if __name__ == "__main__":
    py2exe_1 = UnfrozenPy2exe(sys.argv[1])
    py2exe_1.unfrozen()