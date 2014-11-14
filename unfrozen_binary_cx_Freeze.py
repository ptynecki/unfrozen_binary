#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = 'Katharsis'
__copyright__ = 'Copyright 2014, Piotr Tynecki'
__license__ = 'BSD'
__version__ = '1.0'


import os
import sys
import shutil
import re
import zipfile


from common import uncompyle_decompilation
from common import unpyc3


class UnfrozencxFreeze(object):
    def __init__(self, exe_file):
        self.exe_file = exe_file

        self.exe_file_path = os.path.abspath(self.exe_file)

        self.current_path = os.getcwd()

        dir_name = os.path.splitext(os.path.basename(self.exe_file_path))[0]

        # Deletes previous output directory than creates a new one
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)

        os.mkdir(dir_name)
        os.chdir(dir_name)

        self.extraction_path = None

        self.pyc_files = []

    def get_archive_name(self):
        """ Returns archive .zip name or binary name """
        with open(self.exe_file_path, 'rb') as f:
            source = f.read()

            # Pattern for library.zip for other archive name
            search_obj = re.search(r'\x00(\w+).zip\x00', source, re.M | re.I)

            if search_obj:
                archive_name = re.sub(r'[\x00\s]+', '', search_obj.group())

                archive_path = os.path.join(os.path.split(self.exe_file_path)[0], archive_name)

                if os.path.exists(archive_path):
                    print("Archive name: {0}".format(archive_name))
                else:
                    archive_name = self.exe_file

                    print("Archive is embedded. Unzipping the binary.")
            else:
                archive_name = self.exe_file

                print("Archive is embedded. Unzipping the binary.")

        return os.path.basename(archive_name)

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

    def rename_main_script(self):
        """ Renames __main__.pyc to real .pyc name """
        orig_main_script_path = os.path.join(
            self.extraction_path,
            "__main__.pyc"
        )

        # If filename__main__.pyc exists inside of archive
        if not os.path.exists(orig_main_script_path):
            orig_main_script_path = os.path.join(
                self.extraction_path,
                "{0}__main__.pyc".format(os.path.splitext(os.path.basename(self.exe_file))[0].lower())
            )

        new_main_script_path = os.path.join(
            self.extraction_path,
            "%s.pyc" % os.path.splitext(os.path.basename(self.exe_file))[0]
        )

        print(
            '\nRenaming: {0} to {1}'.format(
                os.path.basename(orig_main_script_path),
                os.path.basename(new_main_script_path))
        )

        os.rename(orig_main_script_path, new_main_script_path)

    def unpack_archive(self, archive_name):
        """ Unpacks .zip archive or binary for all .pyc files """
        archive = zipfile.ZipFile(
            os.path.join(
                self.current_path,
                os.path.split(self.exe_file)[0],
                archive_name
            )
        )

        self.extraction_path = os.getcwd()

        archive.extractall(self.extraction_path)

        self.rename_main_script()

        archive_pyc_files = []

        for path, dirs, files in os.walk(self.extraction_path):
            for f in files:
                archive_pyc_files.append(os.path.join(path, f))

        return archive_pyc_files

    def unfrozen(self):
        """ Runs the algorithm in correct order """
        archive_name = self.get_archive_name()

        # Decompilation for all .pyc files (inside of archive or binary)
        for pyc_file in self.unpack_archive(archive_name):
            self.decompilation(pyc_file)

        os.chdir(self.current_path)

        print("\nWork is done.")


if __name__ == "__main__":
    cx_Freeze_1 = UnfrozencxFreeze(sys.argv[1])
    cx_Freeze_1.unfrozen()