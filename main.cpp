#include <cstdio>
#include <pcap.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <libnet.h>
#include <queue>
#include <map>

#include "ethhdr.h"
#include "arphdr.h"

using namespace std;



queue< pair<char *, char *> > q;
map<char *, char *> mp;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

typedef struct {
        char* dev_;
} Param;

Param param = {
        .dev_ = NULL
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int macaddr(char *ifname, char *myMacstr) {
    struct ifaddrs *ifap, *ifaptr;
    unsigned char *ptr;

    if (getifaddrs(&ifap) == 0) {
        for(ifaptr = ifap; ifaptr != NULL; ifaptr = (ifaptr)->ifa_next) {
            if (!strcmp((ifaptr)->ifa_name, ifname) && (((ifaptr)->ifa_addr)->sa_family == AF_PACKET)) {
                struct sockaddr_ll *s = (struct sockaddr_ll*)(ifaptr->ifa_addr);
                int i;
                int len = 0;
                for (i = 0; i < 6; i++) {
                    len += sprintf(myMacstr+len, "%02X%s", s->sll_addr[i], i < 5 ? ":":"");
                }
                break;
            }
        }
        freeifaddrs(ifap);
        return ifaptr != NULL;
    } else {
        return 0;
    }
}

// Mac sMac_parser (const u_char *packet, char *targetIp, char *sourceIp){
// 	struct EthArpPacket *etharp_packet = (struct EthArpPacket *) packet;

// 	if( ntohs(etharp_packet->eth_.type_) == EthHdr::Arp && ntohs(etharp_packet->arp_.op_) == ArpHdr::Reply &&
// 		ntohl(etharp_packet->arp_.sip_) == static_cast<uint32_t>(Ip(targetIp)) && ntohl(etharp_packet->arp_.tip_) == static_cast<uint32_t>(Ip(sourceIp)) ){
// 			return etharp_packet->arp_.smac_;
// 	}

// 	fprintf(stderr, "Can not get Source Mac Address\n");
// 	return Mac("00:00:00:00:00:00");
// }


Mac getMacAddr(pcap_t *handle, char *sourceIp, char *targetIp, char *myMacstr){

	Mac senderMac;

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac(myMacstr);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(myMacstr);
	packet.arp_.sip_ = htonl(Ip(sourceIp));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(targetIp));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

    while (true) {
        struct pcap_pkthdr* packet_header;
        const u_char *packet;

        int res = pcap_next_ex(handle, &packet_header, &packet);
        if(res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
		struct EthArpPacket *etharp_packet = (struct EthArpPacket *) packet;

		if( ntohs(etharp_packet->eth_.type_) == EthHdr::Arp && ntohs(etharp_packet->arp_.op_) == ArpHdr::Reply &&
			ntohl(etharp_packet->arp_.sip_) == static_cast<uint32_t>(Ip(targetIp)) && ntohl(etharp_packet->arp_.tip_) == static_cast<uint32_t>(Ip(sourceIp)) ){
				return etharp_packet->arp_.smac_;
		}

		// senderMac = sMac_parser(packet, targetIp, sourceIp);
	}
	fprintf(stderr, "Can not get Source Mac Address\n");
	return Mac("00:00:00:00:00:00");
}

void send_arp(pcap_t *handle, char *senderIp, char *targetIp, char *myMacstr){

	Mac senderMac = getMacAddr(handle, targetIp, senderIp, myMacstr);

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("00:00:00:00:00:00"); //senderMac
	packet.eth_.smac_ = Mac("00:00:00:00:00:00"); //myMac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(myMacstr);
	packet.arp_.sip_ = htonl(Ip(targetIp));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //senderMac
	packet.arp_.tip_ = htonl(Ip(senderIp));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	printf("Send-arp %s %s success", senderIp, targetIp);

}


int main(int argc, char* argv[]) {

	if (argc < 4) {
		usage();
		return -1;
	}
	
	// 내 MAC addr 가져오기
    char myMacstr[18], *ifname;

	ifname = argv[1];
	if (!macaddr(ifname, myMacstr)) {
		printf("%s: not found\n", ifname);
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	for(int i=2; i<argc; i+=2){
		q.push({argv[i], argv[i+1]});
	}

	for(int i=0;i<q.size();i++){
		
		char *senderIp = q.front().first;
		char *targetIp = q.front().second;

		q.pop();

		if(mp.find(senderIp) != mp.end())
			continue;

		send_arp(handle, senderIp, targetIp, myMacstr);
		mp.insert({senderIp, targetIp});

	}

	pcap_close(handle);
	return 0;
}
