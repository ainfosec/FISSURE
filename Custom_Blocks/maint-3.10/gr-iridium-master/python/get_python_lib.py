# From https://github.com/pothosware/SoapySDR/tree/master/python
# https://github.com/pothosware/SoapySDR/blob/master/LICENSE_1_0.txt
import os
import sys
import site
from distutils.sysconfig import get_python_lib

if __name__ == '__main__':
    prefix = sys.argv[1]

    #ask distutils where to install the python module
    install_dir = get_python_lib(plat_specific=True, prefix=prefix)

    #use sites when the prefix is already recognized
    try:
        paths = [p for p in site.getsitepackages() if p.startswith(prefix)]
        if len(paths) == 1:
            install_dir = paths[0]
    except AttributeError:
        pass

    #strip the prefix to return a relative path
    print(os.path.relpath(install_dir, prefix))
