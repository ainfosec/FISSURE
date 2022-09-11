# http://www.vtk.org/Wiki/CMake_FAQ#Can_I_do_.22make_uninstall.22_with_CMake.3F

IF(NOT EXISTS "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-fuzzer/build/install_manifest.txt")
  MESSAGE(FATAL_ERROR "Cannot find install manifest: \"/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-fuzzer/build/install_manifest.txt\"")
ENDIF(NOT EXISTS "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-fuzzer/build/install_manifest.txt")

FILE(READ "/home/user/FISSURE/Custom_Blocks/maint-3.10/gr-fuzzer/build/install_manifest.txt" files)
STRING(REGEX REPLACE "\n" ";" files "${files}")
FOREACH(file ${files})
  MESSAGE(STATUS "Uninstalling \"$ENV{DESTDIR}${file}\"")
  IF(EXISTS "$ENV{DESTDIR}${file}")
    EXEC_PROGRAM(
      "/usr/local/lib/python3.10/dist-packages/cmake/data/bin/cmake" ARGS "-E remove \"$ENV{DESTDIR}${file}\""
      OUTPUT_VARIABLE rm_out
      RETURN_VALUE rm_retval
      )
    IF(NOT "${rm_retval}" STREQUAL 0)
      MESSAGE(FATAL_ERROR "Problem when removing \"$ENV{DESTDIR}${file}\"")
    ENDIF(NOT "${rm_retval}" STREQUAL 0)
  ELSEIF(IS_SYMLINK "$ENV{DESTDIR}${file}")
    EXEC_PROGRAM(
      "/usr/local/lib/python3.10/dist-packages/cmake/data/bin/cmake" ARGS "-E remove \"$ENV{DESTDIR}${file}\""
      OUTPUT_VARIABLE rm_out
      RETURN_VALUE rm_retval
      )
    IF(NOT "${rm_retval}" STREQUAL 0)
      MESSAGE(FATAL_ERROR "Problem when removing \"$ENV{DESTDIR}${file}\"")
    ENDIF(NOT "${rm_retval}" STREQUAL 0)
  ELSE(EXISTS "$ENV{DESTDIR}${file}")
    MESSAGE(STATUS "File \"$ENV{DESTDIR}${file}\" does not exist.")
  ENDIF(EXISTS "$ENV{DESTDIR}${file}")
ENDFOREACH(file)
