#include "controller.h"

	
struct packet_meta *DstGateWay; //All packets with Gateways IP to PortOpening
struct packet_meta *toBelkinSwitch; //External Activity to Belkin Switch
struct packet_meta *frmBelkinSwitch; //External Activity from Belkin Switch
struct packet_meta *toCamera; //External Activity to DLink Camera
struct packet_meta *frmCamera; //External Activity from DLink Camera
struct packet_meta *ssdpDiscovery; //SSDP Discovery
struct packet_meta *ssdpResponce; //SSDP Responce
struct packet_meta *defaultAnyThing; //defaultAnyThing


int init_controller(){
	debug("Initializing controller");

	first_rule=NULL;

	/* IOT Traffic
	
	//All packets with Gateways IP
	DstGateWay =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","192.168.1.2",0,0);
	flowrule_add(63,DstGateWay,1<<3);

	//External Activity to Belkin Switch
	toBelkinSwitch =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","192.168.1.223",0,0);
	flowrule_add(127,toBelkinSwitch,1<<3);

	frmBelkinSwitch =  create_rule(NULL,NULL,0,0,0,"192.168.1.223","0.0.0.0",0,0);
	flowrule_add(127,frmBelkinSwitch,1<<3);


	//External Activity from DLink Camera
	toCamera =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","192.168.1.124",0,0);
	flowrule_add(127,toCamera,1<<3);

	frmCamera =  create_rule(NULL,NULL,0,0,0,"192.168.1.124","0.0.0.0",0,0);
	flowrule_add(127,frmCamera,1<<3);


	//External Activity from DLink Motion detect
	toBelkinSwitch =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","192.168.1.193",0,0);
	flowrule_add(127,toBelkinSwitch,1<<3);

	frmBelkinSwitch =  create_rule(NULL,NULL,0,0,0,"192.168.1.193","0.0.0.0",0,0);
	flowrule_add(127,frmBelkinSwitch,1<<3);

	//External Activity from Smart thing
	toBelkinSwitch =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","192.168.1.196",0,0);
	flowrule_add(127,toBelkinSwitch,1<<3);

	frmBelkinSwitch =  create_rule(NULL,NULL,0,0,0,"192.168.1.196","0.0.0.0",0,0);
	flowrule_add(127,frmBelkinSwitch,1<<3);

	//SSDP Discovery
	ssdpDiscovery =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,1900);
	flowrule_add(1,ssdpDiscovery,1<<3);

	//SSDP Responce
	ssdpResponce =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",1900, 0);
	flowrule_add(1,ssdpResponce,1<<3);

	defaultAnyThing =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,0);
	flowrule_add(0,defaultAnyThing,DROP);

	*/

	//All packets with Gateways IP
	DstGateWay =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","192.168.1.2",0,0);
	flowrule_add(63,DstGateWay,FWD_TO_CONTROLLER|FORWARD);

	//External Activity to Belkin Switch
	toBelkinSwitch =  create_rule("f4:f2:6d:22:9d:00",NULL,0,0,0,"0.0.0.0","192.168.1.223",0,0);
	flowrule_add(127,toBelkinSwitch,FWD_TO_CONTROLLER|FORWARD);

	//External Activity from Belkin Switch
	frmBelkinSwitch =  create_rule(NULL,"f4:f2:6d:22:9d:00",0,0,0,"192.168.1.223","0.0.0.0",0,0);
	flowrule_add(127,frmBelkinSwitch,FWD_TO_CONTROLLER|FORWARD);

	//External Activity to DLink Camera
	toCamera =  create_rule("f4:f2:6d:22:9d:00",NULL,0,0,0,"0.0.0.0","192.168.1.124",0,0);
	flowrule_add(127,toCamera,FWD_TO_CONTROLLER|FORWARD);

	//External Activity from DLink Camera
	frmCamera =  create_rule(NULL,"f4:f2:6d:22:9d:00",0,0,0,"192.168.1.124","0.0.0.0",0,0);
	flowrule_add(127,frmCamera,FWD_TO_CONTROLLER|FORWARD);


	//SSDP Discovery
	ssdpDiscovery =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,1900);
	flowrule_add(1,ssdpDiscovery,FWD_TO_CONTROLLER|FORWARD);

	//SSDP Responce
	ssdpResponce =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",1900, 0);
	flowrule_add(1,ssdpResponce,FWD_TO_CONTROLLER|FORWARD);

	defaultAnyThing =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,0);
	flowrule_add(0,defaultAnyThing,DROP);

	//print_pac_meta(r1);
	return 0;
}

int to_controller(struct packet_meta *p_m, const unsigned char *packet, struct pcap_pkthdr* header){
	//debug("Packet received by controller");
	//print_pac_meta(p_m);
	//fprintf(stderr, "\n");


	unsigned int capture_len = header->caplen;
	unsigned int length;

	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);

	struct ip *p_ip = (struct ip*) packet;
	length = p_ip->ip_hl * 4;	/* ip_hl is in 4-byte words */


	/* Skip over the IP header to get to the UDP header. */
	packet += length;
	capture_len -= length;

	if(p_m->ip_p ==IPPROTO_TCP){
		struct tcphdr *p_tcp  = (struct tcphdr*)packet;
		length = p_tcp->th_off * 4;
		packet += length;
		capture_len -= length;
	}
	else if(p_m->ip_p ==IPPROTO_UDP){
		length = sizeof(struct udphdr);
		packet += length;
		capture_len -= length;
	}


	if(flowrule_comp(toBelkinSwitch,p_m)){
		fprintf(stderr,"suspicious instruction:  Access to Belkin WeMo Switch from external\n\tIP:");
		printIP(p_m->ip_src);
		fprintf(stderr,"\n\t**Flow forwarded as normal\n");

		struct packet_meta *r =  create_rule("f4:f2:6d:22:9d:00",NULL,0,0,0,inet_ntoa(p_m->ip_src),"192.168.1.223",0,0);
		flowrule_add(255,r,FORWARD);
	}
	else if(flowrule_comp(frmBelkinSwitch,p_m)){
		fprintf(stderr,"suspicious instruction:  Response from Belkin WeMo Switch to external\n\tIP:");
		printIP(p_m->ip_dst);
		fprintf(stderr,"\n\t**Flow forwarded as normal\n");
		struct packet_meta *r =  create_rule(NULL,"f4:f2:6d:22:9d:00",0,0,0,"192.168.1.223",inet_ntoa(p_m->ip_dst),0,0);
		flowrule_add(255,r,FORWARD);	
	}
	else if(flowrule_comp(toCamera,p_m)){
		fprintf(stderr,"suspicious instruction:  Access to DLink Camera from external\n\tIP:");
		printIP(p_m->ip_src);
		fprintf(stderr,"\n\t**Flow forwarded as normal\n");
		struct packet_meta *r =  create_rule("f4:f2:6d:22:9d:00",NULL,0,0,0,inet_ntoa(p_m->ip_src),"192.168.1.124",0,0);
		flowrule_add(255,r,FORWARD);	
	}
	else if(flowrule_comp(frmCamera,p_m)){
		fprintf(stderr,"suspicious instruction:  Response from DLink Camera to external\n\tIP:");
		printIP(p_m->ip_dst);
		fprintf(stderr,"\n\t**Flow forwarded as normal\n");
		struct packet_meta *r =  create_rule(NULL,"f4:f2:6d:22:9d:00",0,0,0,"192.168.1.124",inet_ntoa(p_m->ip_dst),0,0);
		flowrule_add(255,r,FORWARD);	
	}
	else if(flowrule_comp(DstGateWay,p_m)){
		//Find Port forwarding
		findPF(packet, capture_len);	
	}

	//PrintData (packet , capture_len);

	return 0;
}

struct packet_meta *create_rule(
					char* ether_shost,
					char* ether_dhost,
					uint16_t ether_type,

					uint8_t 	ip_tos, //Type of service. 
					uint8_t 	ip_p, //Protocol. 
					char 	*ip_src, //Source IP address. 
					char	*ip_dst, //Destination IP address. 

					u_short	sport,		// source port
					u_short	dport		//destination port
				 )
{


	struct packet_meta *rle = (struct packet_meta*)malloc(sizeof(struct packet_meta));

	mac_aton(ether_dhost,&rle->ether_dhost);
	mac_aton(ether_shost,&rle->ether_shost);

	rle->ether_type		= ether_type;
	rle->ip_tos			= ip_tos; //Type of service. 
	rle->ip_p			= ip_p; //Protocol.
	
	
    inet_aton(ip_src, &rle->ip_src);
	inet_aton(ip_dst, &rle->ip_dst);       

	rle->sport=sport;		// source port
	rle->dport=dport;		//destination port
        

    return rle;
}


void PrintData (const unsigned char* data , int Size)
{
    int i,j;

    fprintf(stderr,"Size of the payload:%d\n",Size);
    fprintf(stderr,"Header:%c%c%c%c\n",data[0] ,data[1],data[2],data[3]);
    if(Size>4 && data[0]=='P' && data[1]=='O'&& data[2]=='S'&& data[3]=='T'){
	    for(i=0 ; i < Size ; i++)
	    {

	            for(j=0 ; j<=16 ; j++)
	            {
	                if(data[j]>=32 && data[j]<=128) fprintf(stderr,"%c",(unsigned char)data[16*i+j]);
	                else fprintf(stderr,".");
	            }
	    }
	    fprintf(stderr, "\n%s\n","End of Packet");

    }

}

int mac_aton(char *macString,u_char** mchar){

	//If no MAC address
	if (macString==NULL){
		*mchar=NULL;
		return 0;

	}

	*mchar=(u_char*)malloc(sizeof(u_char)*ETHER_ADDR_LEN);
	check(*mchar,"Failed to char*");

	char others;
	int values[ETHER_ADDR_LEN];
	int i;

	if( ETHER_ADDR_LEN == sscanf( macString, "%x:%x:%x:%x:%x:%x%c",
		&values[0], &values[1], &values[2],
		&values[3], &values[4], &values[5],&others) )
	{
		/* convert to uint8_t */
		for( i = 0; i < ETHER_ADDR_LEN; i++ )
			(*mchar)[i] = (u_char) values[i];

		return 1;
	}

	else
	{
		log_err("Invalid MAC");
		return 0;
	}

	error:
		return 0;
}


