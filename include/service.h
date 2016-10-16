#ifndef __service_h__
#define __service_h__


#include "dsetime.h"
#include "equeue.h"
#include "controller.h"
#include "dbg.h"


#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

struct sim_summary;
enum ACTION_TYPE {
	FORWARD=(0<<0),
	DROP=(1<<0),
	FWD_TO_CONTROLLER=(1<<1),
	DEEP_ANALYSIS=(1<<2)
};

struct packet_meta{
	//Frame
	u_char* ether_dhost;
	u_char* ether_shost;
	uint16_t ether_type;
	//vlanID????
	//Frame

	//IP
	uint8_t 	ip_tos; //Type of service. 
	uint8_t 	ip_p; //Protocol. 
	struct	in_addr	ip_src; //Source IP address. 
	struct	in_addr	ip_dst; //Destination IP address. 
	//IP

	//TCP/UDP
	u_short	sport;		// source port
	u_short	dport;		//destination port
};

struct flowrule {
	int flowId;
	unsigned int priority;
	struct packet_meta *match;
	enum ACTION_TYPE action;
	unsigned long datacounter;
	unsigned long packetcounter;

	struct flowrule *next_rule;
};
struct flowrule *first_rule;

void log_packet_err(struct timeval ts, const char *reason);
int do_service(unsigned long pid, const unsigned char *packet, struct pcap_pkthdr *header, struct sim_summary *s);
struct packet_meta * extract_meta(const unsigned char *packet, struct pcap_pkthdr * header);

void printMac(u_char* mac);
void printIP(struct in_addr ipno);

struct flowrule *flowrule_add(unsigned int priority, struct packet_meta *new_rule, enum ACTION_TYPE action);
u_short flowrule_comp(struct packet_meta *m_rule, struct packet_meta *m_packet);
//void traverse_flow();
struct flowrule *match_rules(struct packet_meta *c_meta);
int takeaction(unsigned long pid,struct flowrule *c_f,struct packet_meta *c_meta,const unsigned char *packet, struct pcap_pkthdr *header,struct sim_summary *s );
//void print_pac_meta(struct packet_meta *pm);

u_short compMac(u_char *mac1, u_char *mac2);
char* strMac(u_char* mac);
#endif
