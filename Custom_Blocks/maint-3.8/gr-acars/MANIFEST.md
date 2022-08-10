title: The ACARS OOT Module
brief: Short description of gr-acars
tags: # Tags are arbitrary, but look at CGRAN what other authors are using
  - sdr
author:
  - JM Friedt <jmfriedt_at_femto-st.fr>
copyright_owner:
  - JM Friedt
license:
gr_supported_version: 3.8
#repo: # Put the URL of the repository here, or leave blank for default
#website: <module_website> # If you have a separate project website, put it here
#icon: <icon_url> # Put a URL to a square image here that will be used as an icon on CGRAN
---
The updated gr-acars decoding block
* improves computational load by detecting messages using a dynamic threshold rather
than detecting the 2400 Hz preamble: no need for FFT as long as a sufficiently strong
message is not detected
* replaces libfftw with the native GNU Radio FFT wrapper, allowing for multiple blocks
to be inserted in the same flowgraph (see example)
* attempts at tracking the bitrate clock

Compile using 
``cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ..``

The latest version is 3.8ng for the New Generation algorithm aimed at
tracking the datastream clock.
