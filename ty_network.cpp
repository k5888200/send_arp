#include "ty_network.h"

char *usr_ether_ntoa_r (const struct ether_addr *addr, char *buf)
{
	snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
			addr->ether_addr_octet[0], addr->ether_addr_octet[1],
			addr->ether_addr_octet[2], addr->ether_addr_octet[3],
			addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
	return buf;
}

char *usr_ether_ntoa (const struct ether_addr *addr)
{
	static char buf[18];
	return usr_ether_ntoa_r(addr, buf);
}

void my_assert(bool cond, const char *format, ...){
	if(!cond){
		va_list ap;
		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);
		exit(1);
	}
}

int GetLocalIP(struct in_addr* IP, const char *interface){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, strlen(interface));
	if(ioctl(fd, SIOCGIFADDR, &ifr) == -1) return 0;
	close(fd);

	memcpy(IP, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof(in_addr));

	return 1;
}


int GetLocalHA(struct ether_addr* HA, const char *interface){
	int fd;
	struct ifreq ifr;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, strlen(interface));
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) return 0;
	close(fd);

	memcpy(HA, ifr.ifr_ifru.ifru_hwaddr.sa_data, sizeof(ether_addr));

	return 1;
}


int GetHA(pcap_t *handle, const struct ether_addr *srcHA, const struct in_addr *srcIP, struct ether_addr *dstHA, const struct in_addr *dstIP){
	unsigned char *packet = (unsigned char *)malloc(ETHER_MAX_LEN);
	size_t tot_len = 0, len;
	my_assert( (len = GenEtherPacket(packet, (const ether_addr*)"\xff\xff\xff\xff\xff\xff\xff\xff", srcHA, ETHERTYPE_ARP)) >= 0, "Error on Generate Ether Packet!\n"); tot_len += len;
	my_assert( (len = GenARPPacket(packet+tot_len, ARPOP_REQUEST, srcHA, srcIP, (const ether_addr*)"\x00\x00\x00\x00\x00\x00\x00\x00", dstIP)) >= 0, "Error on Generate ARP Packet\n"); tot_len += len;

	if( pcap_sendpacket(handle, packet, tot_len) != 0){ 
		fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
		return 0;
	}

	int res;
	struct pcap_pkthdr* 		header;
	struct ether_header* 	eh;
	struct arphdr 			*arp_hdr;
	struct arp_payload		*arp_pay;
	const unsigned char* buf;
	while( (res = pcap_next_ex(handle, &header, &buf)) >= 0){
		if (res == 0) continue;
		eh = (ether_header *)buf;
		if(ntohs(eh->ether_type) != ETH_P_ARP) continue;
		if(memcmp(eh->ether_dhost, srcHA, ETHER_ADDR_LEN)) continue;
		arp_hdr = (struct arphdr*)(buf + sizeof(struct ether_header));
		arp_pay = (struct arp_payload*)((unsigned char*)arp_hdr + sizeof(struct arphdr));
		if(ntohs(arp_hdr->ar_op) != ARPOP_REPLY) continue;
		if(memcmp(&(arp_pay->TargetHA), srcHA, ETHER_ADDR_LEN)) continue;
		if(memcmp(&(arp_pay->TargetIP), srcIP, IP_ADDR_LEN)) continue;
		if(memcmp(&(arp_pay->SenderIP), dstIP, IP_ADDR_LEN)) continue;

		memcpy(dstHA, &(arp_pay->SenderHA), ETHER_ADDR_LEN);

		break;
	}


	return 1;
}



// Success => len, Fail => -1
size_t GenEtherPacket(unsigned char *packet, const struct ether_addr* dst_ha, const struct ether_addr* src_ha, u_int16_t ether_type){
	struct ether_header eh;

	memcpy(eh.ether_dhost, dst_ha, ETHER_ADDR_LEN);
	memcpy(eh.ether_shost, src_ha, ETHER_ADDR_LEN);
	eh.ether_type = htons(ether_type);

	memcpy(packet, &eh, sizeof(struct ether_header));

	return sizeof(ether_header);
}

size_t GenARPPacket(unsigned char *packet, const u_int16_t opcode, const struct ether_addr *SenderHA, const struct in_addr *SenderIP, const struct ether_addr *TargetHA, const struct in_addr *TargetIP){
	struct arphdr 	arp_hdr;
	struct arp_payload	arp_pay;

	arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
	arp_hdr.ar_pro = htons(ETHERTYPE_IP);
	arp_hdr.ar_hln = ETHER_ADDR_LEN;
	arp_hdr.ar_pln = IP_ADDR_LEN;
	arp_hdr.ar_op  = htons(opcode);

	memcpy(&arp_pay.SenderHA, SenderHA, ETHER_ADDR_LEN);
	memcpy(&arp_pay.SenderIP, SenderIP, IP_ADDR_LEN);
	memcpy(&arp_pay.TargetHA, TargetHA, ETHER_ADDR_LEN);
	memcpy(&arp_pay.TargetIP, TargetIP, IP_ADDR_LEN);	

	int len = 0;
	memcpy(packet + len, &arp_hdr, sizeof(struct arphdr)); len += sizeof(struct arphdr);
	memcpy(packet + len, &arp_pay, sizeof(struct arp_payload)); len += sizeof(struct arp_payload);

	return len;
}
