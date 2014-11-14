# -*- coding: utf-8 -*-

__author__ = 'Katharsis'
__copyright__ = 'Copyright 2014, Piotr Tynecki'
__license__ = 'BSD'
__version__ = '1.0'

import sys
import os

import peutils
import pefile


python_version = sys.version_info[:2]

if python_version[0] == 3:
    from decompilers.unpyc3.unpyc3 import dec_module
elif python_version[0] in (1, 2):
    from decompilers.uncompyle2 import uncompyle_file
    from decompilers.uncompyle2 import Walker
else:
    sys.exit(-1)


def is_compressed(binary_file):
    try:
        signatures = peutils.SignatureDatabase('signatures.db')

        pe = pefile.PE(binary_file)

        matches = signatures.match(pe, ep_only=True)

        if matches:
            return matches[0]
        else:
            return None
    except IOError:
        raise Exception("Error: signatures.db doesn't exists")


def uncompyle_decompilation(file_name):
    """
        uncompyle2 support decompilation for Python 1.5 - 2.7a0 (details on magics.py)

        Return (reversed source code) .py file path
    """
    py_file = ".".join([os.path.splitext(file_name)[0], 'py'])

    with open(py_file, 'w') as file_obj:
        try:
            uncompyle_file(file_name, file_obj)
        except (IndexError, Walker.ParserError):
            return None

    return py_file


def unpyc3(file_name):
    """
        unpyc3 support decompilation for Python 3.3

        Return (reversed source code) .py file path
    """
    py_file = ".".join([os.path.splitext(file_name)[0], 'py'])

    with open(py_file, 'w') as file_obj:
        file_obj.write(str(dec_module(file_name)))

    return py_file


magic_numbers = {
    20121: 'Python 1.5.x', 50428: 'Python 1.6', 50823: 'Python 2.0.x',
    60202: 'Python 2.1.x', 60717: 'Python 2.2', 62011: 'Python 2.3a0',
    62021: 'Python 2.3a0', 62041: 'Python 2.4a0', 62051: 'Python 2.4a3',
    62061: 'Python 2.4b1', 62071: 'Python 2.5a0', 62081: 'Python 2.5a0',
    62091: 'Python 2.5a0', 62092: 'Python 2.5a0', 62101: 'Python 2.5b3',
    62111: 'Python 2.5b3', 62121: 'Python 2.5c1', 62131: 'Python 2.5c2',
    62151: 'Python 2.6a0', 62161: 'Python 2.6a1', 62171: 'Python 2.7a0',
    62181: 'Python 2.7a0', 62191: 'Python 2.7a0', 62201: 'Python 2.7a0',
    62211: 'Python 2.7a0', 3000: 'Python 3000', 3010: 'Python 3000',
    3020: 'Python 3000', 3030: 'Python 3000', 3040: 'Python 3000',
    3050: 'Python 3000', 3060: 'Python 3000', 3061: 'Python 3000',
    3071: 'Python 3000', 3081: 'Python 3000', 3091: 'Python 3000',
    3101: 'Python 3000', 3103: 'Python 3000', 3111: 'Python 3.0a4',
    3131: 'Python 3.0a5', 3141: 'Python 3.1a0', 3151: 'Python 3.1a0',
    3160: 'Python 3.2a0', 3170: 'Python 3.2a1', 3180: 'Python 3.2a2',
    3190: 'Python 3.3a0', 3200: 'Python 3.3a0', 3210: 'Python 3.3a0',
    3220: 'Python 3.3a1', 3230: 'Python 3.3a4', 3250: 'Python 3.4a1',
    3260: 'Python 3.4a1', 3270: 'Python 3.4a1', 3280: 'Python 3.4a1',
    3290: 'Python 3.4a4', 3300: 'Python 3.4a4', 3310: 'Python 3.4rc2',
    3320: 'Python 3.5a0',
}