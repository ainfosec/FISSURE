"""Finite AIS one-slot HDLC/CRC/bit-stuffing/NRZI framing for offline IQ tests.

No RF transmission, socket output, or device control. This module deliberately
creates a bounded *single 256-bit radio slot* from a validated 160-/168-bit AIS payload. Synthetic Type 1/18 position
reports and Type 24 class-B static reports are supported.

AIS NMEA payload bits are represented MSB-first in each octet, but HDLC
serializes each data octet LSB-first on the air. CRC-16/X.25 uses reflected
polynomial 0x8408, init 0xffff, xorout 0xffff, and sends FCS low bit first.
Only payload/FCS bits are stuffed between flags.
"""
from __future__ import annotations

SLOT_BITS = 256
HDLC_FLAG = "01111110"


def _binary(value):
    if not value or any(bit not in '01' for bit in value):
        raise ValueError("Expected a nonempty binary string")
    return value


def x25_fcs(payload_bits):
    """Compute the AIS HDLC/X.25 frame-check sequence from on-air-order bits."""
    crc = 0xFFFF
    for bit in _binary(payload_bits):
        mix = (crc & 1) ^ (bit == "1")
        crc >>= 1
        if mix:
            crc ^= 0x8408
    return crc ^ 0xFFFF


def bit_stuff(payload_and_fcs):
    result = []
    ones = 0
    for bit in _binary(payload_and_fcs):
        result.append(bit)
        ones = ones + 1 if bit == "1" else 0
        if ones == 5:
            result.append("0")
            ones = 0
    return "".join(result)


def nrzi_encode(bits, initial_level=1):
    level = int(initial_level)
    encoded = []
    for bit in _binary(bits):
        if bit == "0":
            level ^= 1
        encoded.append(str(level))
    return "".join(encoded)


def nrzi_decode(levels, initial_level=1):
    last = int(initial_level)
    decoded = []
    for bit in _binary(levels):
        level = int(bit)
        decoded.append("1" if level == last else "0")
        last = level
    return "".join(decoded)


def to_on_air_octet_order(payload_bits):
    """Serialize AIS dearmored payload octets LSB-first for HDLC.

    GNU Radio 3.8 digital.hdlc_deframer_bp assembles the serial bits into
    bytes LSB-first; absent this reversal, receiver output becomes the
    bit-reversed version of every source byte (type 1 is decoded as type 8).
    """
    if len(_binary(payload_bits)) % 8:
        raise ValueError("AIS payload must contain whole octets")
    return "".join(payload_bits[i:i + 8][::-1] for i in range(0, len(payload_bits), 8))


def build_slot(payload_bits):
    """Return exactly 32 packed bytes (MSB-first) for GNU Radio 3.8 GMSK.

    The 8-bit leading ramp, 24-bit training pattern and flags surround the
    stuffed payload + CRC. The end buffer fills out the 256-bit AIS slot.
    NRZI is applied before passing the bits to GNU Radio's GMSK modulator.
    """
    if len(_binary(payload_bits)) not in (160, 168):
        raise ValueError("Only 160-/168-bit single-slot AIS messages are supported")
    on_air_payload = to_on_air_octet_order(payload_bits)
    fcs = x25_fcs(on_air_payload)
    fcs_bits = "".join(str((fcs >> bit) & 1) for bit in range(16))
    stuffed = bit_stuff(on_air_payload + fcs_bits)
    ramp = "01" * 4
    training = "01" * 12
    frame = ramp + training + HDLC_FLAG + stuffed + HDLC_FLAG
    if len(frame) > SLOT_BITS:
        raise ValueError("Stuffed AIS frame exceeds one 256-bit TDMA slot: %d bits" % len(frame))
    # The unused tail is a guard interval, not an additional packet.
    frame += "0" * (SLOT_BITS - len(frame))
    encoded = nrzi_encode(frame)
    packed = bytes(int(encoded[i:i + 8], 2) for i in range(0, SLOT_BITS, 8))
    return packed
