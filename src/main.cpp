#include <cstdio>
#include <pcap.h>
#include <string>
#include <unistd.h>
#include <stdint.h>
#include "packet.h"
#include "mac.h"


void Usage(char* arg) {
	printf("syntax: %s <interface> <mac>\n", arg);
	printf("sample: %s mon0 00:11:22:33:44:55\n", arg);
}

void show_info(pcap_t* handle, Mac target) {
	pcap_pkthdr* hdr;
	const u_char* pkt;

	int res, sIp, sTcp, sPay;

	res = pcap_next_ex(handle, &hdr, &pkt);

	if (res == 0) return;
	if (res == -1 || res == -2) {
		printf("FATAL: pcap_next_ex | gres=%d\n", res);
	}
	
	RadHdr* radHdr = (RadHdr*)pkt;
	IeeeHdr* ieeeHdr = (IeeeHdr*)(pkt+radHdr->len);
	
	//ref: http://80211notes.blogspot.com/2013/09/understanding-address-fields-in-80211.html
	short type=ieeeHdr->subtype & 0b00001100;
	
	if (type == 0b00001000 && ieeeHdr->bssid == target) {
		printf("%d\td: %s\ts: %s\tbssid: %s\n",
				radHdr->antSig-0xff,
				std::string(ieeeHdr->dMac).c_str(),
				std::string(ieeeHdr->sMac).c_str(),
				std::string(ieeeHdr->bssid).c_str());
	} else if (type == 0b00000000 && ieeeHdr->sMac == target) {
		printf("%d\td: %s\ts: %s\tbssid: %s\n",
                                radHdr->antSig-0xff,
                                std::string(ieeeHdr->dMac).c_str(),
                                std::string(ieeeHdr->sMac).c_str(),
                                std::string(ieeeHdr->bssid).c_str());
	}
}

int main(int argc, char** argv) {
	if (3 != argc) {
		Usage(argv[0]);
		return -1;
	}

	char* dev = argv[1];
	char  errBuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errBuf);
	if (handle == nullptr) {
		printf("FATAL: Couldn't open device %s(%s)\n", dev, errBuf);
		return -1;
	}

        Mac target = Mac(argv[2]);

	while (true) {
		show_info(handle, target);
	}

	pcap_close(handle);
}
