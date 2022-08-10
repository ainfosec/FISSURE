include(GrPython)

if(NOT PYTHONINTERP_FOUND)
  return()
endif()

GR_PYTHON_INSTALL(
  FILES __init__.py decoder.py framer.py
  DESTINATION ${GR_PYTHON_DIR}/adsb
)
