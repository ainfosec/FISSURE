#!/usr/bin/env python

import re
import sys

# show usage
if len(sys.argv) < 2:
    print "Usage: btclassify.py <class> [<class> ...]"
    print "    Class looks like: 0x112233. 0x optional"
    sys.exit(1)

for class_string in sys.argv[1:]:
    # I'm a Perl guy, sue me
    m = re.match('(0x)?([0-9A-Fa-f]{6})', class_string)
    if m is None:
        print "Invalid class, skipping (%s)" % class_string
        continue

    hex_string = m.group(2)

    # "class" is a reserved word in Python, so CoD is class
    CoD = int(hex_string, 16)

    # Class of Device: 0x38010c (Computer - services: Audio, Object transfer, Capturing)

    # Major Device Classes
    classes = ['Miscellaneous', 'Computer', 'Phone', 'LAN/Network Access Point',
               'Audio/Video', 'Peripheral', 'Imaging', 'Wearable', 'Toy',
               'Health']
    major_number = (CoD >> 8) & 0x1f
    if major_number < len(classes):
        major = classes[major_number]
    elif major_number == 31:
        major = 'Uncategorized'
    else:
        major = 'Reserved'

    # Minor - varies depending on major
    minor_number = (CoD >> 2) & 0x3f
    minor = None

    # computer
    if major_number == 1:
        classes = [
            'Uncategorized', 'Desktop workstation', 'Server-class computer',
            'Laptop', 'Handheld PC/PDA (clamshell)', 'Palm-size PC/PDA',
            'Wearable computer (watch size)', 'Tablet']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    # phone
    elif major_number == 2:
        classes = [
            'Uncategorized', 'Cellular', 'Cordless', 'Smartphone',
            'Wired modem or voice gateway', 'Common ISDN access']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    # network access point
    elif major_number == 3:
        minor_number >> 3
        classes = [
            'Fully available', '1% to 17% utilized', '17% to 33% utilized',
            '33% to 50% utilized', '50% to 67% utilized',
            '67% to 83% utilized', '83% to 99% utilized',
            'No service available']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    # audio/video
    elif major_number == 4:
        classes = [
            'Uncategorized', 'Wearable Headset Device', 'Hands-free Device',
            '(Reserved)', 'Microphone', 'Loudspeaker', 'Headphones',
            'Portable Audio', 'Car audio', 'Set-top box', 'HiFi Audio Device',
            'VCR', 'Video Camera', 'Camcorder', 'Video Monitor',
            'Video Display and Loudspeaker', 'Video Conferencing',
            '(Reserved)', 'Gaming/Toy']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    # peripheral, this one's gross
    elif major_number == 5:
        feel_number = minor_number >> 4
        classes = [
            'Not Keyboard / Not Pointing Device', 'Keyboard',
            'Pointing device', 'Combo keyboard/pointing device']
        feel = classes[feel_number]

        classes = [
            'Uncategorized', 'Joystick', 'Gamepad', 'Remote control',
            'Sensing device', 'Digitizer tablet', 'Card Reader', 'Digital Pen',
            'Handheld scanner for bar-codes, RFID, etc.',
            'Handheld gestural input device' ]
        if minor_number < len(classes):
            minor_low = classes[minor_number]
        else:
            minor_low = 'reserved'
        
        minor = '%s, %s' % (feel, minor_low)

    # imaging
    elif major_number == 6:
        minors = []
        if minor_number & (1 << 2):
            minors.append('Display')
        if minor_number & (1 << 3):
            minors.append('Camera')
        if minor_number & (1 << 4):
            minors.append('Scanner')
        if minor_number & (1 << 5):
            minors.append('Printer')
        if len(minors > 0):
            minors = ', '.join(minors)

    # wearable
    elif major_number == 7:
        classes = ['Wristwatch', 'Pager', 'Jacket', 'Helmet', 'Glasses']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    # toy
    elif major_number == 8:
        classes = ['Robot', 'Vehicle', 'Doll / Action figure', 'Controller',
                   'Game']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    # health
    elif major_number == 9:
        classes = [
            'Undefined', 'Blood Pressure Monitor', 'Thermometer',
            'Weighing Scale', 'Glucose Meter', 'Pulse Oximeter',
            'Heart/Pulse Rate Monitor', 'Health Data Display', 'Step Counter',
            'Body Composition Analyzer', 'Peak Flow Monitor',
            'Medication Monitor', 'Knee Prosthesis', 'Ankle Prosthesis',
            'Generic Health Manager', 'Personal Mobility Device']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    # Major Service Class (can by multiple)
    services = []
    if CoD & (1 << 23):
        services.append('Information')
    if CoD & (1 << 22):
        services.append('Telephony')
    if CoD & (1 << 21):
        services.append('Audio')
    if CoD & (1 << 20):
        services.append('Object Transfer')
    if CoD & (1 << 19):
        services.append('Capturing')
    if CoD & (1 << 18):
        services.append('Rendering')
    if CoD & (1 << 17):
        services.append('Networking')
    if CoD & (1 << 16):
        services.append('Positioning')
    if CoD & (1 << 15):
        services.append('(reserved)')
    if CoD & (1 << 14):
        services.append('(reserved)')
    if CoD & (1 << 13):
        services.append('Limited Discoverable Mode')

    output = [major]
    if minor is not None:
        output.append(' (%s)' % minor)
    output.append(': ')
    output.append(', '.join(services))

    print '0x%s: %s' % (hex_string, ''.join(output))
