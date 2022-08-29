#pragma once

#include <cstdio>
#include <string>
#include <pcap.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <map>
#include <iostream>
#include <libnet.h>
#include <netinet/in.h>

#include "ethhdr.h"
#include "arphdr.h"


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

using namespace std;

/**
 * @brief 
 * 
 * @param op	Operation(Request, Reply)
 * @param sip  	Sender IP
 * @param tip  	Target IP
 * @param dmac	Source MAC
 * @param smac	Destination MAC
 * @param sendermac Sender MAC
 * @param targetmac Target MAC
 * 
 * @return 		EthArpPacket 
 */
EthArpPacket setArpPacket(
	uint16_t op, 
	Ip sip, 
	Ip tip,
	Mac dmac,
	Mac smac,
	Mac sendermac,
	Mac targetmac
){
	EthArpPacket packet;
	/* ppt 보고 바꾸기*/
	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = sendermac;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = targetmac;
	packet.arp_.tip_ = htonl(tip);
	return packet;
}




/**
 * @brief Get the mac address object
 * 
 * @return string 
 */
string getMyMacAddr(void) {
    int socket_fd;
    int count_if;

    struct ifreq  *t_if_req;
    struct ifconf  t_if_conf;

    char arr_mac_addr[18] = {0x00, };

    memset(&t_if_conf, 0, sizeof(t_if_conf));

    t_if_conf.ifc_ifcu.ifcu_req = NULL;
    t_if_conf.ifc_len = 0;

    if( (socket_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
        return "";
    }

    if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) {
        return "";
    }

    if( (t_if_req = (ifreq *)malloc(t_if_conf.ifc_len)) == NULL ) {
        close(socket_fd);
        free(t_if_req);
        return "";

    } else {
        t_if_conf.ifc_ifcu.ifcu_req = t_if_req;
        if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) {
            close(socket_fd);
            free(t_if_req);
            return "";
        }

        count_if = t_if_conf.ifc_len / sizeof(struct ifreq);
        for( int idx = 0; idx < count_if; idx++ ) {
            struct ifreq *req = &t_if_req[idx];

            if( !strcmp(req->ifr_name, "lo") ) {
                continue;
            }

            if( ioctl(socket_fd, SIOCGIFHWADDR, req) < 0 ) {
                break;
            }

            sprintf(arr_mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned char)req->ifr_hwaddr.sa_data[0],
                (unsigned char)req->ifr_hwaddr.sa_data[1],
                (unsigned char)req->ifr_hwaddr.sa_data[2],
                (unsigned char)req->ifr_hwaddr.sa_data[3],
                (unsigned char)req->ifr_hwaddr.sa_data[4],
                (unsigned char)req->ifr_hwaddr.sa_data[5]);
            break;
        }
    }

    close(socket_fd);
    free(t_if_req);

    return arr_mac_addr;
}

/**
 * @brief Get the Ip Address object
 * 
 * @param ip_addr 
 * @param netInterface 
 */
void getMyIpAddr(char* ip_addr, char* netInterface)
{
	struct ifreq ifr;
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, netInterface, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	} else {
		inet_ntop(AF_INET, 
            ifr.ifr_addr.sa_data+2,
			ip_addr,
            sizeof(struct sockaddr));
	}
}