#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <bits/stdc++.h>



void usage() {
	printf("syntax: pcap_test <interface> <send ip> <target ip>\n");
	printf("sample: pcap_test wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (0 && argc != 4) {
		usage();
		return -1;
	}

	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa;
	char *addr;

	getifaddrs (&ifap);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family==AF_INET) {
			sa = (struct sockaddr_in *) ifa->ifa_addr;
			addr = inet_ntoa(sa->sin_addr);
			printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);
		}
	}

	freeifaddrs(ifap);
	return 0;
}
