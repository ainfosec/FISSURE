
def encoding_to_parameters(encoding):

    encodings = [
        {"bpsc": 1, "cbps":  48, "dbps":  24},
        {"bpsc": 1, "cbps":  48, "dbps":  36},
        {"bpsc": 2, "cbps":  96, "dbps":  48},
        {"bpsc": 2, "cbps":  96, "dbps":  72},
        {"bpsc": 4, "cbps": 192, "dbps":  96},
        {"bpsc": 4, "cbps": 192, "dbps": 144},
        {"bpsc": 6, "cbps": 288, "dbps": 192},
        {"bpsc": 6, "cbps": 288, "dbps": 216}
        ]

    enc = encodings[encoding]

    return enc["bpsc"], enc["cbps"], enc["dbps"]


def payload_to_symbols(payload, encoding):

    bpsc, cbps, dbps = encoding_to_parameters(encoding)

    # 24 header + 4 crc + payload
    data_byte = 24 + 4 + payload
    symbols = int(round((16 + data_byte * 8 + 6) / float(dbps) + 0.5))

    return symbols + 5


def mac_payload_to_payload(payload):
    return payload - 28


def payload_to_mac_payload(payload):
    return payload + 28


def payload_to_samples(payload, encoding):
    return payload_to_symbols(payload, encoding) * 80 + 1


def symbols_to_payload(symbols, encoding):

    bpsc, cbps, dbps = encoding_to_parameters(encoding)


    bytes = (((symbols - 5) * dbps) - 16 - 6) / 8

    assert(bytes > 28)

    return bytes - 24 - 4
