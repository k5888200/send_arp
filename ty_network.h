#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <bits/stdc++.h>
#include <unistd.h>



void my_assert(bool cond, const char* format, ...)
__attribute__ ((format (printf, 2, 3)));


int GetLocalIP(struct in_addr* IP, const char *interface);

int GetLocalHA(struct ether_addr* HA, const char *interface);