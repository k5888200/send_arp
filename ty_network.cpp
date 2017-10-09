#include "ty_network.h"

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

int GetHA(struct ether_addr* HA, const struct in_addr* IP){
}