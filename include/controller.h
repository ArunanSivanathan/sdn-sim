#ifndef __controller_h__
#define __controller_h__
#include "dbg.h"
#include "service.h"
#include "equeue.h"
#include "controller.h"
#include "dbg.h"
#include "dsetime.h"
#include "detect_PF.h"

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

struct flowrule;

int init_controller(int);
struct packet_meta *create_rule(char* ether_shost,char* ether_dhost,
	uint16_t ether_type, uint8_t ip_tos, uint8_t ip_p, char *ip_src, char *ip_dst, u_short sport, u_short dport);

struct packet_meta *create_ruleRawMac(u_char *ether_shost, u_char *ether_dhost,
	uint16_t ether_type, uint8_t ip_tos, uint8_t ip_p, struct in_addr ip_src, struct in_addr ip_dst, u_short sport, u_short	dport);


int to_controller(struct packet_meta *p_m, const unsigned char *packet, struct pcap_pkthdr* header);
int mac_aton(char *macString,u_char** mchar);
void PrintData (const unsigned char* data , int Size);

int mac_copy(u_char* from, u_char** to);

int controllerMode;



#endif