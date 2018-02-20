#ifndef __equeue_h__
#define __equeue_h__

#include <stdio.h> 
#include <stdlib.h>

#include <string.h>
//for Linux
#include <time.h>
#include <pcap.h>

#include "dbg.h"
#include "dsetime.h"
#include "service.h"
#include "dosCheck.h"

enum EVENT_TYPE {PACK_ARRIVAL,SERVICE_IN,SERVICE_OUT};
struct packet_meta;
struct event_node {
	struct timeval ts;		//destination port
	unsigned long id;
	enum EVENT_TYPE event;		// source port
	struct event_node	*past_event;		// datagram length
	struct event_node	*next_event;
};

struct packet_events {
	unsigned long packetno;
	struct timeval arrival;		//destination port
	struct timeval waiting;
	struct timeval service_in;		//destination port
	struct timeval service_out;		//destination port
	//struct event_node	*past_event;		// datagram length
};

struct sim_summary{
	unsigned long count_packet;
	unsigned long count_data;
	unsigned long count_dropped;
	unsigned long count_fwded;
	unsigned long count_fwd_controller;
};
enum ACTION_TYPE;


int tickTimeCallBack(struct timeval *ts);
struct event_node *insertEvent( unsigned int p_id, enum EVENT_TYPE e_t, struct timeval ts);
void print_packet_action(unsigned long pid, enum ACTION_TYPE action, struct pcap_pkthdr *header);
void print_flowmatch(unsigned long pid, int fid, struct pcap_pkthdr *header);
void closelogs();
void openlogs();
void flush_event_logs(struct event_node *upto_this);
void print_packet_events(struct packet_events *p_e,unsigned int pack_size);
int openlog_packet_event();
int openlog_event_traverse();
int openlog_action();
int openlog_flowmatch();
int openlog_flowuse();
int openlog_flowentry();
int openlog_packet();
void print_summary(struct sim_summary *s);
int printFlowUse(int secs, int *CurrentCount,unsigned long long *currentRate);
int printPacketTuples(unsigned long pid, struct packet_meta *c_meta, struct pcap_pkthdr *header);
int printFlowEntry();
#define MaxFlows 5000
#define FLOWUSEPRINT 1
#define PACKETINFOPRINT 1
#define EVENTINFO 0

int noOflastPackets[MaxFlows];
int noOfcurrentPackets[MaxFlows];

unsigned long long lastDataPassed[MaxFlows];
unsigned long long currentDataPassed[MaxFlows];

#endif
