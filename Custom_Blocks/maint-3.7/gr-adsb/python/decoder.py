#!/usr/bin/env python
'''
   Copyright 2015 Wolfgang Nagele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''

import math
import threading
from gnuradio import gr

LENGTH = 56
CHARSET = '#ABCDEFGHIJKLMNOPQRSTUVWXYZ#####################0123456789######'

planes = {}


class decoder(gr.sync_block):
  def __init__(self, rx_msgq, tx_msgq, output_type, check_parity):
    gr.sync_block.__init__(self,
                           name = "ADSB Decoder",
                           in_sig = None,
                           out_sig = None)

    thread = decoder_thread(rx_msgq, tx_msgq, output_type, check_parity)
    thread.start()


class decoder_thread(threading.Thread):
  def __init__(self, rx_msgq, tx_msgq, output_type, check_parity):
    threading.Thread.__init__(self)
    self.setDaemon(True)

    self.rx_msgq = rx_msgq
    self.tx_msgq = tx_msgq
    self.output_type = output_type
    self.check_parity = check_parity


  def run(self):
    while True:
      try:
        self.decode(self.rx_msgq.delete_head().to_string())
      except IndexError, ValueError:
        pass


  def decode(self,decoded_msg):
    df = bin2dec(decoded_msg[:5])
    # Sanity check DF value
    if df not in [0, 4, 5, 11, 16, 17, 19, 20, 21, 22, 24]:
      return

    # Detect extended messages
    extended = False
    if LENGTH * 2 == len(decoded_msg):
      extended = True

    # Verify parity
    bad_parity = (0 != get_parity(decoded_msg, extended))
    if self.check_parity and bad_parity:
        return

    if self.output_type in ["csv", "json"]:
      ca = bin2dec(decoded_msg[5:8])
      tc = bin2dec(decoded_msg[32:37])
      icao = bin2dec(decoded_msg[8:32])
      callsign = None
      speed = -1
      heading = -1
      position = None
      odd_even = -1
      if df in [11, 17]:
        if tc >= 1 and tc <= 4:
          callsign = get_callsign(decoded_msg)
        elif tc >= 9 and tc <= 18:
          odd_even = bin2dec(decoded_msg[53])

          if icao not in planes:
            planes[icao] = {}
          if 1 == odd_even:
            planes[icao]["odd"] = get_position_data(decoded_msg)
          else:
            planes[icao]["even"] = get_position_data(decoded_msg)
          if "odd" in planes[icao] and "even" in planes[icao]:
            position = get_position(planes[icao]["even"][0],
                                    planes[icao]["odd"][0],
                                    planes[icao]["even"][1],
                                    planes[icao]["odd"][1],
                                    odd_even)
        elif tc == 19:
          speed_heading = get_speed_heading(decoded_msg)
          speed = speed_heading[0]
          heading = speed_heading[1]

      if "csv" == self.output_type:
        adsb_str = "%06X,%s,%s,%s,%s,%s,%s,%s,%s\n" % \
       (icao,
        callsign if callsign else "",
        int(speed) if speed != -1 else "",
        int(heading) if heading != -1 else "",
        "%.02f,%.02f" % (position[0], position[1]) if position else "",
        odd_even if odd_even != -1 else "",
        df if df != -1 else "",
        ca if ca != -1 else "",
        tc if tc != -1 else "")

      if "json" == self.output_type:
        adsb_str = '{"icao": "%06X", "callsign": "%s", "speed": "%s", "heading": "%s", "position": "%s", "eo": "%s", "downlink_format": "%s", "message_subtype": "%s", "type_code": "%s", "parity": "%s"}\n' % \
       (icao,
        callsign if callsign else "",
        int(speed) if speed != -1 else "",
        int(heading) if heading != -1 else "",
        "%.02f,%.02f" % (position[0], position[1]) if position else "",
        odd_even if odd_even != -1 else "",
        df if df != -1 else "",
        ca if ca != -1 else "",
        tc if tc != -1 else "",
	"bad" if bad_parity else "ok")

      self.tx_msgq.insert_tail(gr.message_from_string(adsb_str))

    elif "hex" == self.output_type:
      self.tx_msgq.insert_tail(gr.message_from_string("*%X;\n" % bin2dec(decoded_msg)))


def bin2dec(buf):
  if 0 == len(buf): # Crap input
    return -1
  return int(buf, 2)


def get_callsign(msg):
  csbin = msg[40:96]
  cs = ''
  cs += CHARSET[bin2dec(csbin[0:6])]
  cs += CHARSET[bin2dec(csbin[6:12])]
  cs += CHARSET[bin2dec(csbin[12:18])]
  cs += CHARSET[bin2dec(csbin[18:24])]
  cs += CHARSET[bin2dec(csbin[24:30])]
  cs += CHARSET[bin2dec(csbin[30:36])]
  cs += CHARSET[bin2dec(csbin[36:42])]
  cs += CHARSET[bin2dec(csbin[42:48])]
  cs = cs.replace('#', '')
  return cs


def get_position_data(msg):
  lat = bin2dec(msg[54:71])
  lon = bin2dec(msg[71:88])
  return (lat, lon)

# TODO: Does not account for surface calculations
# TODO: Age of odd and even messages needs to be considered to ensure correct calculation
# Ported from algorithm used in dump1090 (https://github.com/MalcolmRobb/dump1090/blob/master/mode_s.c)
def get_position(lat0, lat1, lon0, lon1, oe):
  j = int(math.floor(((59 * lat0 - 60 * lat1) / 131072.0) + 0.5))
  rlat0 = 360.0 / 60.0 * (cpr_mod(j, 60) + lat0 / 131072.0)
  rlat1 = 360.0 / 59.0 * (cpr_mod(j, 59) + lat1 / 131072.0)

  if rlat0 >= 270:
    rlat0 -= 360
  if rlat1 >= 270:
    rlat1 -= 360

  if rlat0 < -90 or rlat0 > 90 or rlat1 < -90 or rlat1 > 90:
    return None

  if (cpr_nl(rlat0) != cpr_nl(rlat1)):
    return None

  lat = -1
  lon = -1
  if 1 == oe:
    ni = cpr_nf(rlat1, 1)
    m = int(math.floor((((lon0 * (cpr_nl(rlat1) - 1)) - (lon1 * cpr_nl(rlat1))) / 131072.0) + 0.5))
    lon = cpr_dlon(rlat1, 1) * (cpr_mod(m, ni) + lon1 / 131072.0)
    lat = rlat1
  else:
    ni = cpr_nf(rlat0, 0)
    m = int(math.floor((((lon0 * (cpr_nl(rlat0) - 1)) - (lon1 * cpr_nl(rlat0))) / 131072.0) + 0.5))
    lon = cpr_dlon(rlat0, 0) * (cpr_mod(m, ni) + lon0 / 131072.0)
    lat = rlat0

  if lon > 180:
    lon -= 360

  if lat == -1 or lon == -1:
    return None

  return (lat, lon)

def cpr_nf(lat, oe):
  nl = cpr_nl(lat) - oe
  if nl < 1:
    nl = 1
  return nl

def cpr_dlon(lat, oe):
  return 360.0 / cpr_nf(lat, oe)

def cpr_mod(a, b):
  res = a % b
  if res < 0:
    res += b
  return res

def cpr_nl(lat):
  if lat < 0 : lat = -lat
  if lat < 10.47047130 : return 59
  if lat < 14.82817437 : return 58
  if lat < 18.18626357 : return 57
  if lat < 21.02939493 : return 56
  if lat < 23.54504487 : return 55
  if lat < 25.82924707 : return 54
  if lat < 27.93898710 : return 53
  if lat < 29.91135686 : return 52
  if lat < 31.77209708 : return 51
  if lat < 33.53993436 : return 50
  if lat < 35.22899598 : return 49
  if lat < 36.85025108 : return 48
  if lat < 38.41241892 : return 47
  if lat < 39.92256684 : return 46
  if lat < 41.38651832 : return 45
  if lat < 42.80914012 : return 44
  if lat < 44.19454951 : return 43
  if lat < 45.54626723 : return 42
  if lat < 46.86733252 : return 41
  if lat < 48.16039128 : return 40
  if lat < 49.42776439 : return 39
  if lat < 50.67150166 : return 38
  if lat < 51.89342469 : return 37
  if lat < 53.09516153 : return 36
  if lat < 54.27817472 : return 35
  if lat < 55.44378444 : return 34
  if lat < 56.59318756 : return 33
  if lat < 57.72747354 : return 32
  if lat < 58.84763776 : return 31
  if lat < 59.95459277 : return 30
  if lat < 61.04917774 : return 29
  if lat < 62.13216659 : return 28
  if lat < 63.20427479 : return 27
  if lat < 64.26616523 : return 26
  if lat < 65.31845310 : return 25
  if lat < 66.36171008 : return 24
  if lat < 67.39646774 : return 23
  if lat < 68.42322022 : return 22
  if lat < 69.44242631 : return 21
  if lat < 70.45451075 : return 20
  if lat < 71.45986473 : return 19
  if lat < 72.45884545 : return 18
  if lat < 73.45177442 : return 17
  if lat < 74.43893416 : return 16
  if lat < 75.42056257 : return 15
  if lat < 76.39684391 : return 14
  if lat < 77.36789461 : return 13
  if lat < 78.33374083 : return 12
  if lat < 79.29428225 : return 11
  if lat < 80.24923213 : return 10
  if lat < 81.19801349 : return 9
  if lat < 82.13956981 : return 8
  if lat < 83.07199445 : return 7
  if lat < 83.99173563 : return 6
  if lat < 84.89166191 : return 5
  if lat < 85.75541621 : return 4
  if lat < 86.53536998 : return 3
  if lat < 87.00000000 : return 2
  else : return 1


def get_speed_heading(msg):
  v_ew_dir = bin2dec(msg[45])
  v_ew     = bin2dec(msg[46:56])

  v_ns_dir = bin2dec(msg[56])
  v_ns     = bin2dec(msg[57:67])

  v_ew = -1 * v_ew if v_ew_dir else v_ew
  v_ns = -1 * v_ns if v_ns_dir else v_ns

  speed = math.sqrt(v_ns * v_ns + v_ew * v_ew)

  heading = math.atan2(v_ew, v_ns)
  heading = heading * 360.0 / (2 * math.pi)
  heading = heading if heading >= 0 else heading + 360

  return [speed, heading]


# Ported from: http://www.radarspotters.eu/forum/index.php?topic=5617.msg41293#msg41293
def get_parity(msg, extended):
  msg_length = len(msg)
  payload = msg[:msg_length - 24]
  parity = msg[msg_length - 24:]

  data = bin2dec(payload[0:32])
  if extended:
    data1 = bin2dec(payload[32:64])
    data2 = bin2dec(payload[64:]) << 8

  hex_id = bin2dec(parity) << 8

  for i in range(0, len(payload)):
    if ((data & 0x80000000) != 0):
      data ^= 0xFFFA0480
    data <<= 1

    if extended:
      if ((data1 & 0x80000000) != 0):
        data |= 1
      data1 <<= 1

      if ((data2 & 0x80000000) != 0):
        data1 = data1 | 1
      data2 <<= 1

  return (data ^ hex_id) >> 8
