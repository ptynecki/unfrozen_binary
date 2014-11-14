unfrozen_binary 1.0
===================

Python toolset for decompression and decompilation `Python frozen binaries`. Support `unpyc3` and `uncompyle2` decompilers only.  

unfrozen_binary contains:

* `unfrozen_binary_py2exe.py` - works on py2exe binaries,
* `unfrozen_binary_cx_Freeze.py` - works on cx_Freeze binaries,
* `unfrozen_binary_bbfreeze.py` - works on bbfreeze binaries,
* `unfrozen_binary_pyinstaller.py` - works on PyInstaller binaries.

Requirments:

* [pefile](https://pypi.python.org/pypi/pefile) - Portable Executable reader module,
* [unpyc3](https://github.com/figment/unpyc3) - Decompiler for Python 3.3,
* [uncompyle2](https://github.com/wibiti/uncompyle2) - Decompiler for Python 3.7.

How to use the toolset:

```chmod +x unfrozen_binary_<name>.py
./unfrozen_binary_<name>.py binary_file_based_on_<name>.exe```

More about the decompresion and decompilation Python frozen binaries you can read in [my presentation about hacking Python binaries](https://github.com/PyStok/PyStok-1/tree/master/Hackowanie%20zamro%C5%BConych%20binari%C3%B3w) (sorry, polish only).
