#include "service.h"

int do_service(unsigned long pid, const unsigned char *packet, struct pcap_pkthdr *header, struct sim_summary *s){
	//debug("Packet sevicing on progress");
	//debug("Packet ID %lu ",pid);
	
	tickTimeCallBack(&(header->ts));//todo: not the arrival time, it should be process started time




	struct packet_meta *c_meta  = extract_meta(packet,header);
	if (c_meta!=NULL){

		//print_pac_meta(c_meta);

		printPacketTuples(pid,c_meta,header);
		struct flowrule *f_match = match_rules(c_meta);

		if (takeaction(pid,f_match, c_meta, packet,header,s)){
			f_match = match_rules(c_meta);
			takeaction(pid,f_match, c_meta, packet,header,s);
		}
 		free(c_meta);
		return 1;
	}
	else{
		//log_warn("Meta-data retrieval unsuccessfull");
		free(c_meta);
		return 0;
	}
}

struct packet_meta * extract_meta(const unsigned char *packet, struct pcap_pkthdr * header){
	struct packet_meta *c_meta = (struct packet_meta*)malloc(sizeof(struct packet_meta));; // to extract current meta data;
	check(c_meta,"Failed to create packet meta data");

	struct ether_header *eptr;  /* net/ethernet.h */

	struct ip *p_ip;
	struct udphdr *p_udp;
	struct tcphdr *p_tcp;

	unsigned int capture_len;
	unsigned int IP_header_length;

	capture_len = header->caplen;
	/* Assume Ethernet encapsulation. */
	if (capture_len < sizeof(struct ether_header)){
		/* Ethernet header corrupted*/
		//log_packet_err(header->ts, "Short Ethernet Header");
		return NULL;
	}

		/* start with the ether header... */
	    eptr = (struct ether_header *) packet;
	    c_meta->ether_dhost = eptr->ether_dhost;
	    //printMac(c_meta->ether_dhost );
	    //debug("Size of MAC address: %zu",sizeof(c_meta->ether_dhost));
	    c_meta->ether_shost = eptr->ether_shost;
	    //printMac(c_meta->ether_shost );

	    c_meta->ether_type = eptr->ether_type;

	   //skip all packets except IPv4
	if (c_meta->ether_type!=0x08){
		return NULL;
	}

	//ToDo: ARP packet

	/* Skip over the Ethernet header. */
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);

	if (capture_len < sizeof(struct ip)){
		/* IP header corrupted*/
		//log_packet_err(header->ts, "Short IP Header");
		return NULL;
	}


	p_ip = (struct ip*) packet;
	IP_header_length = p_ip->ip_hl * 4;	/* ip_hl is in 4-byte words */

	if (capture_len < IP_header_length)
	{
		/* didn't capture the full IP header including options */
		log_packet_err(header->ts, "IP header with options not captured; Packet");
		return NULL;
	}

	c_meta->ip_tos = p_ip->ip_tos;
	c_meta->ip_p = p_ip->ip_p;
	c_meta->ip_src = p_ip->ip_src;
	c_meta->ip_dst = p_ip->ip_dst;



	/* Skip over the IP header to get to the UDP header. */
	packet += IP_header_length;
	capture_len -= IP_header_length;

	if(c_meta->ip_p ==IPPROTO_TCP){

		if (capture_len < sizeof(struct tcphdr))
		{
			log_packet_err(header->ts, "TCP header Corrupted");
			return NULL;
		}

		p_tcp = (struct tcphdr*) packet;

		c_meta->sport = ntohs(p_tcp->th_sport);
		c_meta->dport = ntohs(p_tcp->th_dport);

	}
	else if(c_meta->ip_p ==IPPROTO_UDP){


		if (capture_len < sizeof(struct udphdr)){
			log_packet_err(header->ts, "UDP header Corrupted ");
			return NULL;
		}

		p_udp = (struct udphdr*) packet;

		c_meta->sport = ntohs(p_udp->uh_sport);
		c_meta->dport = ntohs(p_udp->uh_dport);

	}
	else if(c_meta->ip_p == 0x1){//Echo Ping
		return NULL;
		//Skip now
	}
	else if(c_meta->ip_p == 0x2){//IGMP
		return NULL;
	}	
	else{
		debug("New IP proto found: %x",c_meta->ip_p);
	}

	return c_meta;

	error:
	return NULL;
}

u_short flowrule_comp(struct packet_meta *m_rule, struct packet_meta *m_packet){

	if( m_rule->ether_dhost!=NULL && compMac(m_rule->ether_dhost,m_packet->ether_dhost)==0)
	{
		//debug("dhost rule mismatch");			
		return 0;
	}

	if( m_rule->ether_shost!=NULL && compMac(m_rule->ether_shost,m_packet->ether_shost)==0)
	{
		//debug("shost rule mismatch");			
		return 0;
	}
	if( m_rule->ether_type !=0 && m_rule->ether_type != m_packet->ether_type)
	{
		//debug("ether_type rule mismatch");			
		return 0;
	}
	/* For future development
		if( m_rule->ip_tos !=0 && m_rule->ip_tos != m_packet->ip_tos)
			return 0;
	*/
	if( m_rule->ip_p !=0 && m_rule->ip_p!= m_packet->ip_p)
	{
		//debug("Protocol mismatch");			
		return 0;
	}

	if( m_rule->ip_src.s_addr !=0 && m_rule->ip_src.s_addr != m_packet->ip_src.s_addr)
	{
		//debug("src address mismatch");			
		return 0;
	}

	if( m_rule->ip_dst.s_addr !=0 && m_rule->ip_dst.s_addr != m_packet->ip_dst.s_addr)
	{
		//debug("dst address mismatch");			
		return 0;
	}

	if( m_rule->sport !=0 && m_rule->sport != m_packet->sport)
	{
		//debug("sport mismatch");			
		return 0;
	}

	if( m_rule->dport !=0 && m_rule->dport != m_packet->dport)
	{
		//debug("dport mismatch");			
		return 0;
	}

	return 1;
}

struct flowrule *flowrule_add(unsigned int priority, struct packet_meta *new_rule,enum ACTION_TYPE action){

	static int fcounter = 0;

	struct flowrule *ptr = (struct flowrule*)malloc(sizeof(struct flowrule));
	check(ptr, "Failed to create rules.");

	ptr->match=new_rule;
	ptr->flowId=fcounter++;
	ptr->priority=priority;
	ptr->action=action;
	ptr->datacounter=0;
	ptr->packetcounter=0;
	ptr->next_rule=NULL;


	if (first_rule==NULL){
		first_rule = ptr;
	}
	else{
		struct flowrule *cur_f;
		struct flowrule *pre_f;
		cur_f = (struct flowrule*) first_rule;
		pre_f = NULL;


		while(cur_f!=NULL && cur_f->priority > ptr->priority ){
		    pre_f = cur_f;
		    cur_f=cur_f->next_rule;

		} 
	        
		ptr->next_rule=cur_f;
		if ( pre_f ==NULL){
		        first_rule = ptr;
		}
		else{
		        pre_f->next_rule= ptr;
		}

	}
  
	return ptr;

	error:
		return NULL;
}

int takeaction(unsigned long pid,struct flowrule *c_f,struct packet_meta *c_meta,const unsigned char *packet, struct pcap_pkthdr *header,struct sim_summary *s){

	s->count_packet += 1;
	s->count_data += header->caplen;

	if(c_f==NULL){//No matching rule
		//debug("%lu:\tPacket send to controller",pid);
		to_controller(c_meta,packet,header);
		s->count_fwd_controller += 1;
		return 0;
	}
	else{
		c_f->packetcounter += 1;//Increase packet counter
		c_f->datacounter += header->caplen;//Increase data counter
	}

	if (!(c_f->action & FWD_TO_CONTROLLER)) print_packet_action(pid,c_f->action,header);//To avoid 

	print_flowmatch(pid,c_f->flowId,header);
	if(~(c_f->action) & DROP){
		//debug("%lu:\tPacket Forwarded",pid);
		s->count_fwded += 1;
	}
	if(c_f->action & DROP){
		//debug("%lu:\tPacket Dropped",pid);
		s->count_dropped += 1;
	}
	if(c_f->action & FWD_TO_CONTROLLER){
		//debug("%lu:\tPacket fwd to controller",pid);
		int reMatch=to_controller(c_meta,packet,header);
		s->count_fwd_controller += 1;
		return reMatch;//Rematch the packets
	}
	if(c_f->action & DEEP_ANALYSIS){
		//debug("%lu:\tPacket fwd to deep_analysis",pid);
		int reMatch=deep_analysis(c_meta,packet,header,pid);
		s->count_dropped += 1;
		return reMatch;//Rematch the packets
	}
	return 0;
}

struct flowrule *match_rules(struct packet_meta *c_meta){
	struct flowrule *c_f=first_rule;
	while(c_f!=NULL){
		if (flowrule_comp(c_f->match,c_meta)){
			return c_f;
		}
		c_f=c_f->next_rule;
	}
	return NULL;
}

u_short compMac(u_char *mac1, u_char *mac2){
	/* copied from Steven's UNP */

        int i = ETHER_ADDR_LEN;
        do{
        		if(*mac1++ != *mac2++){
        			return 0;
        		}
        }while(--i>0);

        return 1;
}

void printMac(u_char* mac){
	/* copied from Steven's UNP */
        if (mac == NULL){
                fprintf(stderr, "NULL");
                return;
        }
        int i = ETHER_ADDR_LEN;
        do{
                fprintf(stderr, "%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*mac++);
        }while(--i>0);
}

char* strMac(u_char* mac){
	static char m[18];
	if (mac == NULL){
		strncpy (m,"NULL",18);
	}
	else{
	snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
	return m;
}

void printIP(struct in_addr ipno){
	fprintf(stderr, "%s", inet_ntoa(ipno));
	return;
}

//This function need to be replaced by macro
void log_packet_err(struct timeval ts, const char *reason){ 
	fprintf(stderr, "%s: %s\n", timestamp_string(&ts), reason);
}

/*
void print_pac_meta(struct packet_meta *pm){

	fprintf(stderr, "S_host:");
	printMac(pm->ether_shost);

	fprintf(stderr, "\tD_host:");
	printMac(pm->ether_dhost);
	
	fprintf(stderr, "\tEtherType:0x%x", pm->ether_type);

	fprintf(stderr, "\tType of Service:0x%x",pm->ip_tos); //Type of service. 
	fprintf(stderr, "\tProtocol:0x%x",pm->ip_p); //Protocol.
	
	//IP
	fprintf(stderr, "\tS_ip:");
    printIP(pm->ip_src);
    fprintf(stderr, "\tD_ip:");
    printIP(pm->ip_dst);  

    fprintf(stderr, "\tS_port:%d",pm->sport);
    fprintf(stderr, "\tD_port:%d",pm->dport);

} 

void traverse_flow(){

}*/
