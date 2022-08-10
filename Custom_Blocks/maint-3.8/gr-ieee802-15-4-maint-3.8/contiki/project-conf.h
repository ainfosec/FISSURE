// channel 26 is the default
#define RF_CHANNEL 26

// turn off radio duty cycling
// this is important, otherwise you will miss most of the packets
#define NETSTACK_CONF_RDC nullrdc_driver

// disable MAC functionality (for immediate channel access?)
#define NETSTACK_CONF_MAC nullmac_driver
