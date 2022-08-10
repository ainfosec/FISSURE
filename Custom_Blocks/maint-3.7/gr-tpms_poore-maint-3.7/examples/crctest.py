import crcmod

# Calculate CRC
# msg1: 0101001010001010010100010000001000011111011000001000111110 10110110 1100
# msg2: 0101001010001010010100010000110000010101111010100000111101 00000110 110000

bits_no_crc = '0101001010001010010100010000001000011111011000001000111110'
#bits_no_crc = '0101001010001010010100010000110000010101111010100000111101'

for m in range(0,256):
    crc_data =  '000000' + bits_no_crc + ''
    crc_data_bytes = []
    for n in range(0,len(crc_data)/8):
        crc_data_bytes.append(int(crc_data[n*8:n*8+8],2))
    crc_data_bytes = str(bytearray(crc_data_bytes))            
    #check_fn = crcmod.mkCrcFun(0x100 | 0x13, initCrc=0x0, rev=False)
    check_fn = crcmod.mkCrcFun(0x100 | 19, initCrc=0x0, rev=False)
    crc = '{0:08b}'.format(check_fn(crc_data_bytes))
    bits = bits_no_crc + crc
    print m
    print crc
    #print str(len(bits)) + "\n"
