#include "packet.h"


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}      

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		
		/* 이더넷 패킷 확인 */ 
		struct ether_packet* eth;
		eth = (struct ether_packet*)packet;
		if(ntohs(eth->ether_type) == ETHERTYPE_IP){
			uint8_t* dstEther = eth->ether_dhost;
			uint8_t* srcEther = eth->ether_shost;
			
			/* IPv4 패킷 확인 */	
			struct libnet_ipv4_hdr* ip;
			ip = (struct libnet_ipv4_hdr*)(eth->eth_payload);

			/* TCP 확인 */
			if(ip->ip_p == 0x6){
				struct libnet_tcp_hdr* tcp;
				tcp = (struct libnet_tcp_hdr*)((u_char*)ip + (ip->ip_hl * 4));
				uint8_t* tcp_payload[10]; 

				printf("=====================================================\n");
				printf("%u bytes captured\n", header->caplen);
				printf("-----------------------------------------------------\n");
				printf("Ethernet\nSrc MAC\t%s\n", ether_ntoa((ether_addr*)srcEther));
				printf("Dst MAC\t%s \n", ether_ntoa((ether_addr*)dstEther));
				printf("-----------------------------------------------------\n");
				printf("IPv4 \nSrc IP\t%s\n", inet_ntoa(ip->ip_src));
				printf("Dst IP\t%s\n", inet_ntoa(ip->ip_dst));
				printf("-----------------------------------------------------\n");
				printf("TCP \nSrc Port\t%d\nDst Port\t%d\nPayload\t",ntohs(tcp->th_sport), ntohs(tcp->th_dport));
				
				if(header->caplen == 14 + ip->ip_hl * 4 +  tcp->th_off * 4){
					printf("No Data");
				}
				else{
					for(int i = 0 ; i < 10 ; i++)
						printf("%x ", *(((u_char*)tcp) + (tcp->th_off * 4) + i));
				}

				printf("\n=====================================================\n");
			}
			
		}
	}

	pcap_close(pcap);
}
