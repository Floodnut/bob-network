#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <netinet/in.h>


struct ether_packet
{
    uint8_t     ether_dhost[ETHER_ADDR_LEN];
    uint8_t     ether_shost[ETHER_ADDR_LEN];
    uint16_t    ether_type;   
    uint8_t     eth_payload[1500];
};