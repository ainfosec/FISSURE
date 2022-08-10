libbtbb
=======

This is the Bluetooth baseband decoding library, forked from the GR-Bluetooth 
project.  It can be used to extract Bluetooth packet and piconet information 
from Ubertooth devices as well as GR-Bluetooth/USRP.

This code is incomplete, it is still under active development.  Patches and 
bug reports should be submitted to the bug tracker on GitHub:
https://github.com/greatscottgadgets/libbtbb/issues

This software has been developed and tested on Linux, it should work on other 
platforms but this has yet to be tested.


Build Instructions
==================

Libbtbb can be built and installed as follows:
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```

This will install the library to /usr/local/lib and the headers to 
/usr/local/include, to install to different locations use:
```
$ cmake -DINSTALL_DIR=/path/to/install -DINCLUDE_DIR=/path/to/include ..
```

If you have previous versions of libbtbb, libubertooth or the Ubertooth tools
installed, you can use the cleanup script to remove them:
```
$ sudo cmake/cleanup.sh -d
```

To list the installed files without removing them, use:
```
$ cmake/cleanup.sh
```
