#include "ty_network.h"

int main(int argc, char* argv[]) {
	my_assert(argc == 4, "syntax: %s <interface> <send ip> <target ip>\n", argv[0]);

	in_addr attack_ip, sender_ip, target_ip;
	ether_addr attack_ha, sender_ha;

	my_assert( GetLocalIP(&attack_ip, argv[1]) , "Error On Getting IP Address");

	my_assert( GetLocalHA(&attack_ha, argv[1]), "Error On Getting Hardware Address");

	for(int i=0;i<6;i++) printf("%02x ",attack_ha.ether_addr_octet[i]); printf("\n");

	return 0;
}
