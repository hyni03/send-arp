#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

int macaddr(char *ifname, char *macaddrstr) {
    struct ifaddrs *ifap, *ifaptr;
    unsigned char *ptr;

    if (getifaddrs(&ifap) == 0) {
        for(ifaptr = ifap; ifaptr != NULL; ifaptr = (ifaptr)->ifa_next) {
            if (!strcmp((ifaptr)->ifa_name, ifname) && (((ifaptr)->ifa_addr)->sa_family == AF_PACKET)) {
                struct sockaddr_ll *s = (struct sockaddr_ll*)(ifaptr->ifa_addr);
                int i;
                int len = 0;
                for (i = 0; i < 6; i++) {
                    len += sprintf(macaddrstr+len, "%02X%s", s->sll_addr[i], i < 5 ? ":":"");
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


int main(int argc, char* argv[]) {

    char macaddrstr[18], *ifname;
    

    if (argc == 2) {
        ifname = argv[1];

        if (macaddr(ifname, macaddrstr)) {
            printf("%s: %s\n", ifname, macaddrstr);
            return 0;
        } else {
            printf("%s: not found\n", ifname);
            return 1;
        }
        
    } else {
        printf("list all interfaces: %s -l\n", argv[0]);
        printf("single interface: %s interface_name\n", argv[0]);
        return 2;
    }
}