btclassify
==========

btclassify converts hex Bluetooth Class of Device (CoD) into
human-readable output.

Run it like this:

    $ ./btclassify.py 38010c 0x5a020c 240404
    0x38010c: Computer (Laptop): Audio, Object Transfer, Capturing
    0x5a020c: Phone (Smartphone): Telephony, Object Transfer, Capturing, Networking
    0x240404: Audio/Video (Wearable Headset Device): Audio, Rendering

Data Source
-----------

Class of Device data is maintained by the Bluetooth SIG on the
[Baseband Assigned Numbers](https://www.bluetooth.org/en-us/specification/assigned-numbers/baseband)
page.

Author
------

btclassify was written by Mike Ryan.

Mike's site/blog: https://lacklustre.net/

Official source: https://github.com/mikeryan/btclassify
