#ifndef __dectect_PF_h__
#define __dectect_PF_h__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>
#include "dbg.h" 
#include "service.h"

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
struct packet_meta;

void findPF(const unsigned char *payload, int size);
int deep_analysis(struct packet_meta *p_m, const unsigned char *packet, struct pcap_pkthdr* header,unsigned long pid);
void PrintDNS (const unsigned char* data , int Size,FILE *filePointer);
char* strMacFileName(u_char* mac);
#endif