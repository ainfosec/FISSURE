#pragma once
namespace iridium {

enum class direction {
  UNDEF = 0,
  DOWNLINK = 1,
  UPLINK = 2,
};

const int SYMBOLS_PER_SECOND = 25000;
const int UW_LENGTH = 12;

const int SIMPLEX_FREQUENCY_MIN = 1626000000;

const int PREAMBLE_LENGTH_SHORT = 16;
const int PREAMBLE_LENGTH_LONG = 64;

const int MIN_FRAME_LENGTH_NORMAL = 131; // IBC frame
const int MAX_FRAME_LENGTH_NORMAL = 191;

const int MIN_FRAME_LENGTH_SIMPLEX = 80; // Single page IRA
const int MAX_FRAME_LENGTH_SIMPLEX = 444;

const int UW_DL[] = {0, 2, 2, 2, 2, 0, 0, 0, 2, 0, 0, 2};
const int UW_UL[] = {2, 2, 0, 0, 0, 2, 0, 0, 2, 0, 2, 2};

}
