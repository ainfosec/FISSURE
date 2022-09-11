# Install script for directory: /home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/python/ainfosec

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/python3.10/dist-packages/gnuradio/ainfosec" TYPE FILE FILES
    "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/python/ainfosec/__init__.py"
    "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/python/ainfosec/adsb_encode.py"
    "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/python/ainfosec/UDP_to_Wireshark.py"
    "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/python/ainfosec/UDP_to_Wireshark_Async.py"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/python3.10/dist-packages/gnuradio/ainfosec" TYPE FILE FILES
    "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/build/python/ainfosec/__init__.pyc"
    "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/build/python/ainfosec/adsb_encode.pyc"
    "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/build/python/ainfosec/UDP_to_Wireshark.pyc"
    "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/build/python/ainfosec/UDP_to_Wireshark_Async.pyc"
    "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/build/python/ainfosec/__init__.pyo"
    "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/build/python/ainfosec/adsb_encode.pyo"
    "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/build/python/ainfosec/UDP_to_Wireshark.pyo"
    "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/build/python/ainfosec/UDP_to_Wireshark_Async.pyo"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-ainfosec/build/python/ainfosec/bindings/cmake_install.cmake")

endif()

