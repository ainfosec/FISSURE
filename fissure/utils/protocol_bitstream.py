"""Plain bitstream input utilities shared by FISSURE analysis and future actions.

This module intentionally does not import Qt or assume a framing/protocol format.
All indexing is zero-based; ranges used by callers are half-open [start, end).
"""

import json
import os
import re

import numpy as np

MAX_BITSTREAM_BITS = 8_000_000


def normalize_bits(bits):
    """Copy a 1-D sequence of zeros and ones to an owned uint8 array."""
    values = np.asarray(bits)
    if values.ndim != 1 or len(values) == 0:
        raise ValueError("Bitstream must be a nonempty one-dimensional sequence")
    if len(values) > MAX_BITSTREAM_BITS:
        raise ValueError(f"Bitstream exceeds {MAX_BITSTREAM_BITS:,} bits")
    if not np.all((values == 0) | (values == 1)):
        raise ValueError("Bitstream must contain only zero and one values")
    return np.array(values, dtype=np.uint8, copy=True)


def _parse_bits_text(text):
    cleaned = re.sub(r"[\s,_]", "", text)
    if not cleaned or re.search(r"[^01]", cleaned):
        raise ValueError("Expected a text file containing only 0/1 bits")
    if len(cleaned) > MAX_BITSTREAM_BITS:
        raise ValueError("Bitstream is too large")
    return np.frombuffer(cleaned.encode("ascii"), dtype=np.uint8).copy() - ord("0")


def _parse_hex_text(text):
    cleaned = re.sub(r"0[xX]", "", text)
    cleaned = re.sub(r"[\s,_:]", "", cleaned)
    if not cleaned or re.search(r"[^0-9a-fA-F]", cleaned):
        raise ValueError("Expected hexadecimal digits (optionally separated by spaces)")
    if len(cleaned) * 4 > MAX_BITSTREAM_BITS:
        raise ValueError("Bitstream is too large")
    return _parse_bits_text("".join(f"{int(char, 16):04b}" for char in cleaned))


def read_bitstream_file(filepath):
    """Read explicit raw bits, text hex, JSON bits or packed binary bytes.

    .bits/.bit: ASCII 0 and 1; .hex: hex digits; .bin/.dat: packed MSB-first
    bytes; .txt: bit text if only 0/1, otherwise hexadecimal if valid;
    .json: {'bits': '<01...>'} or {'bits': [0,1,...]}.
    """
    filepath = os.path.abspath(os.fspath(filepath))
    if not os.path.isfile(filepath):
        raise ValueError("Bitstream file does not exist")
    extension = os.path.splitext(filepath)[1].lower()
    if extension not in {".bits", ".bit", ".txt", ".hex", ".bin", ".dat", ".json"}:
        raise ValueError("Unsupported bitstream format; choose .bits, .hex, .bin, .txt or .json")
    if os.path.getsize(filepath) > MAX_BITSTREAM_BITS + 1024 * 1024:
        raise ValueError("Bitstream file is too large")
    if extension in {".bin", ".dat"}:
        with open(filepath, "rb") as stream:
            raw = stream.read(MAX_BITSTREAM_BITS // 8 + 1)
        if not raw:
            raise ValueError("Bitstream file is empty")
        if len(raw) * 8 > MAX_BITSTREAM_BITS:
            raise ValueError("Bitstream is too large")
        return np.unpackbits(np.frombuffer(raw, dtype=np.uint8), bitorder="big").copy()
    with open(filepath, "r", encoding="utf-8-sig") as stream:
        text = stream.read(MAX_BITSTREAM_BITS + 1024 * 1024 + 1)
    if extension in {".bits", ".bit"}:
        return _parse_bits_text(text)
    if extension == ".hex":
        return _parse_hex_text(text)
    if extension == ".json":
        record = json.loads(text)
        if not isinstance(record, dict) or "bits" not in record:
            raise ValueError("JSON bitstream must contain a 'bits' field")
        return _parse_bits_text(record["bits"]) if isinstance(record["bits"], str) else normalize_bits(record["bits"])
    compact = re.sub(r"[\s,_]", "", text)
    if compact and re.fullmatch("[01]+", compact):
        return _parse_bits_text(text)
    return _parse_hex_text(text)
