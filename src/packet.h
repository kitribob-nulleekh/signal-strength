#ifndef SRC_PACKET_H_
#define SRC_PACKET_H_

#include <unistd.h>
#include "mac.h"

#define RADIOTAP_SIZE 18

struct RadHdr {
    uint8_t rev;
    uint8_t pad;
    uint16_t len;
    uint32_t preFlag;
    uint8_t flag;
    uint8_t rate;
    uint16_t freq;
    uint16_t chnFlag;
    uint8_t antSig;
    uint8_t dummy;
    uint16_t rxFlag;
    uint8_t antSig2;
    uint8_t ant;
};

#define IEEE_SIZE 24
#define BEACON_SUBTYPE 0x80
#define PROBE_SUBTYPE 0x50

struct IeeeHdr {
    uint8_t subtype;
    uint8_t flag;
    uint16_t dur;
    Mac dMac;
    Mac sMac;
    Mac bssid;
    uint16_t seq;
    uint16_t fixedParam[6];
};

#endif //SRC_PACKET_H
