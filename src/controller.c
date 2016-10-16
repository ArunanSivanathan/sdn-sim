#include "controller.h"

	
struct packet_meta *dropme; 
struct packet_meta *defaultAnyThing; //defaultAnyThing
struct	in_addr LOCAL_IP_PREFIX;
int IPmask;
char multicast[17] = "ff:ff:ff:ff:ff:ff";

int init_controller( int mode){
	debug("Initializing controller");
	controllerMode = mode;

	first_rule=NULL;
	/*DNS server identification*/

	struct packet_meta *DNS, *NTP;


	if (controllerMode==0){//Capture ALL IP level flows
		debug("Controller Mode: 5 Tuples");
		defaultAnyThing =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,0);
		flowrule_add(0,defaultAnyThing,FWD_TO_CONTROLLER);
	}
	else if(controllerMode==1){//NTP mode
		debug("Controller Mode: NTP extraction");
		NTP= create_rule(NULL,NULL,0,0,0x11,"0.0.0.0","0.0.0.0",0,123);
		flowrule_add(1,NTP,FWD_TO_CONTROLLER);

		defaultAnyThing =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,0);
		flowrule_add(0,defaultAnyThing,DROP);
	}
	else if(controllerMode==2){//DNS mode
		/*DNS server identification*/
		debug("Controller Mode: DNS extraction");
		DNS= create_rule(NULL,NULL,0,0,0x11,"0.0.0.0","0.0.0.0",0,53);
		flowrule_add(1,DNS,FWD_TO_CONTROLLER);

		defaultAnyThing =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,0);
		flowrule_add(0,defaultAnyThing,DROP);		
	}
	else if(controllerMode==3){//Unicast or Broadcast
		/*DNS server identification*/

		debug("Controller Mode: Unicast or broadcast");
		DNS= create_rule(NULL,multicast,0,0,0,"0.0.0.0","0.0.0.0",0,0);
		flowrule_add(1,DNS,DROP);

		defaultAnyThing =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,0);
		flowrule_add(0,defaultAnyThing,DROP);		
	} 
	else if(controllerMode==4){//Unicast or Broadcast
		/*DNS server identification*/

		debug("Controller Mode: Secured vs not Secured");
		DNS= create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,443);
		flowrule_add(1,DNS,DROP);

		NTP= create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",443,0);
		flowrule_add(1,NTP,DROP);

		defaultAnyThing =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,0);
		flowrule_add(0,defaultAnyThing,DROP);		
	} 
	else if(controllerMode==7){//Unicast or Broadcast
		/*DNS server identification*/

		debug("Controller Mode: 7 Tuples(Remote Only)");

		inet_aton("192.168.0.0", &LOCAL_IP_PREFIX); //store Local IP
		IPmask=16;
		defaultAnyThing =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,0);
		flowrule_add(0,defaultAnyThing,FWD_TO_CONTROLLER);	
	} 
	else if(controllerMode==8){//To get IoT packet Size
		/*DNS server identification*/

		debug("Controller Mode: IotPacket Size");

		//inet_aton("192.168.0.0", &LOCAL_IP_PREFIX); //store Local IP
		//IPmask=16;

		//char* nonIoT[7] = {"08:21:ef:3b:fc:e3","ac:bc:32:d4:6f:2f","74:2f:68:81:69:42","f4:5c:89:93:cc:85","b4:ce:f6:a7:a3:c2","40:f3:08:ff:1e:da","d0:a6:37:df:a1:e1"};//IoT Devices
		char* IoT[28] = {"00:62:6e:51:27:2e", "e8:ab:fa:19:de:4f", "00:0d:88:7e:2f:82", 
						"00:16:6c:ab:6b:88", "00:17:88:2b:9a:25", "00:24:e4:11:18:a8", 
						"00:24:e4:10:ee:4c", "00:24:e4:1b:6f:96", "00:24:e4:20:28:c6", 
						"00:24:e4:44:68:44", "18:b4:30:25:be:e4", 
						"18:b7:9e:02:20:44", "30:8c:fb:2f:e4:b2", "30:8c:fb:b6:ea:45", 
						"44:65:0d:56:cc:d3", "50:c7:bf:00:56:39", "70:5a:0f:e4:9b:c0", 
						"70:ee:50:03:b8:ac", "70:ee:50:18:34:43", "74:6a:89:00:2e:25", 
						"74:c6:3b:29:d7:1d", "d0:52:a8:00:67:5e", "d0:73:d5:01:83:08", 
						"e0:76:d0:33:bb:85", "ec:1a:59:79:f4:89", "ec:1a:59:7a:02:c5", 
						"ec:1a:59:83:28:11", "f4:f2:6d:93:51:f1"};//IoT Devices

		for (int i=0;i<28;i++){

			dropme =  create_rule(IoT[i],NULL,0,0,0,"0.0.0.0","0.0.0.0",0,0);
			flowrule_add(1,dropme,FWD_TO_CONTROLLER);

			dropme =  create_rule(NULL,IoT[i],0,0,0,"0.0.0.0","0.0.0.0",0,0);
			flowrule_add(1,dropme,FWD_TO_CONTROLLER);
		}

		defaultAnyThing =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,0);
		flowrule_add(0,defaultAnyThing,DROP);	
	} 
	else if(controllerMode==70){//Get port Histogram
		/*DNS server identification*/

		debug("Controller Mode: PortHist");

		//inet_aton("192.168.0.0", &LOCAL_IP_PREFIX); //store Local IP
		//IPmask=16;

		//char* nonIoT[7] = {"08:21:ef:3b:fc:e3","ac:bc:32:d4:6f:2f","74:2f:68:81:69:42","f4:5c:89:93:cc:85","b4:ce:f6:a7:a3:c2","40:f3:08:ff:1e:da","d0:a6:37:df:a1:e1"};//IoT Devices
		char* IoT[28] = {"00:62:6e:51:27:2e", "e8:ab:fa:19:de:4f", "00:0d:88:7e:2f:82", 
						"00:16:6c:ab:6b:88", "00:17:88:2b:9a:25", "00:24:e4:11:18:a8", 
						"00:24:e4:10:ee:4c", "00:24:e4:1b:6f:96", "00:24:e4:20:28:c6", 
						"00:24:e4:44:68:44", "18:b4:30:25:be:e4", 
						"18:b7:9e:02:20:44", "30:8c:fb:2f:e4:b2", "30:8c:fb:b6:ea:45", 
						"44:65:0d:56:cc:d3", "50:c7:bf:00:56:39", "70:5a:0f:e4:9b:c0", 
						"70:ee:50:03:b8:ac", "70:ee:50:18:34:43", "74:6a:89:00:2e:25", 
						"74:c6:3b:29:d7:1d", "d0:52:a8:00:67:5e", "d0:73:d5:01:83:08", 
						"e0:76:d0:33:bb:85", "ec:1a:59:79:f4:89", "ec:1a:59:7a:02:c5", 
						"ec:1a:59:83:28:11", "f4:f2:6d:93:51:f1"};//IoT Devices


		for (int i=0;i<28;i++){

			dropme =  create_rule(IoT[i],"14:cc:20:51:33:ea",0,0,0,"0.0.0.0","0.0.0.0",0,0);
			flowrule_add(1,dropme,FWD_TO_CONTROLLER);

			dropme =  create_rule(IoT[i],NULL,0,0,0,"0.0.0.0","0.0.0.0",0,1900);
			flowrule_add(1,dropme,FWD_TO_CONTROLLER);

			dropme =  create_rule("14:cc:20:51:33:ea",IoT[i],0,0,0,"0.0.0.0","0.0.0.0",0,0);
			flowrule_add(100,dropme,DROP);
		}

		defaultAnyThing =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,0);
		flowrule_add(0,defaultAnyThing,DROP);	
	}
	else if(controllerMode==71){//Laptop Ports
		/*DNS server identification*/

		debug("Controller Mode: PortHist");

		//inet_aton("192.168.0.0", &LOCAL_IP_PREFIX); //store Local IP
		//IPmask=16;

		//char* nonIoT[7] = {"08:21:ef:3b:fc:e3","ac:bc:32:d4:6f:2f","74:2f:68:81:69:42","f4:5c:89:93:cc:85","b4:ce:f6:a7:a3:c2","40:f3:08:ff:1e:da","d0:a6:37:df:a1:e1"};//IoT Devices


		dropme =  create_rule("ac:bc:32:d4:6f:2f","14:cc:20:51:33:ea",0,0,0,"0.0.0.0","0.0.0.0",0,0);
		flowrule_add(1,dropme,FWD_TO_CONTROLLER);



		defaultAnyThing =  create_rule(NULL,NULL,0,0,0,"0.0.0.0","0.0.0.0",0,0);
		flowrule_add(0,defaultAnyThing,DROP);	
	}
	else{
		debug("No Mode specified");
		exit(1);
	}
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


	static int count=1;
	struct packet_meta *r;
	/* DNS */
	struct in_addr nullIP;
	 inet_aton("0.0.0.0", &nullIP);




	
	if (controllerMode==0){//Capture 5tuple IP level flows
		r =  create_ruleRawMac(p_m->ether_shost,p_m->ether_dhost,0,0,p_m->ip_p,p_m->ip_src,p_m->ip_dst,0,0);
		//r =  create_rule(NULL,NULL,0,0,p_m->ip_p,"0.0.0.0","0.0.0.0",p_m->sport,p_m->dport);
		//r =  create_ruleRawMac(p_m->ether_shost,p_m->ether_dhost,0,0,p_m->ip_p,inet_ntoa(p_m->ip_src),inet_ntoa(p_m->ip_dst),p_m->sport,p_m->dport);
		flowrule_add(10,r,DROP);		
	}
	else if(controllerMode==1 || controllerMode ==2){//NTP mode
		if (p_m->dport==53){
			r =  create_ruleRawMac(p_m->ether_shost,p_m->ether_dhost,0,0,0x11,p_m->ip_src,p_m->ip_dst,0,53);
			flowrule_add(10,r,DEEP_ANALYSIS);
		}
		else if (p_m->dport==123){
			r =  create_ruleRawMac(p_m->ether_shost,p_m->ether_dhost,0,0,0x11,p_m->ip_src,p_m->ip_dst,0,123);
			flowrule_add(10,r,DROP);
		}
		else{
			r = create_ruleRawMac(p_m->ether_shost,p_m->ether_dhost,0,0,p_m->ip_p,p_m->ip_src,p_m->ip_dst,p_m->sport,p_m->dport);
			flowrule_add(10,r,DROP);
		}

		
	}
	else if (controllerMode==7){//Capture 5tuple IP level flows
		struct	in_addr srcIPPrefix;
		struct	in_addr dstIPPrefix;
		//char str[INET_ADDRSTRLEN];

		srcIPPrefix.s_addr = ((*p_m).ip_src.s_addr<<IPmask)>>IPmask	;	
		dstIPPrefix.s_addr = ((*p_m).ip_dst.s_addr<<IPmask)>>IPmask	;	
		//inet_ntop(AF_INET, &(srcIPPrefix.s_addr), str, INET_ADDRSTRLEN);

		//printf("%s\t%x\t%x\n", str,srcIPPrefix.s_addr,LOCAL_IP_PREFIX.s_addr); // prints "192.0.2.33"

		if (srcIPPrefix.s_addr==LOCAL_IP_PREFIX.s_addr && dstIPPrefix.s_addr!=LOCAL_IP_PREFIX.s_addr){
			//fprintf(stderr, "Match\n" );
			r =  create_ruleRawMac(p_m->ether_shost,p_m->ether_dhost,0,0,p_m->ip_p,p_m->ip_src,p_m->ip_dst,0,p_m->dport);
			flowrule_add(10,r,DROP);
		}
		else{
			r =  create_ruleRawMac(p_m->ether_shost,p_m->ether_dhost,0,0,p_m->ip_p,p_m->ip_src,p_m->ip_dst,0,0);
			flowrule_add(1,r,DROP);
		}

	}
	else if (controllerMode==8){//Capture 7 tuple for IoT only

		r =  create_ruleRawMac(p_m->ether_shost,p_m->ether_dhost,0,0,p_m->ip_p,p_m->ip_src,p_m->ip_dst,0,0);
		flowrule_add(10,r,FORWARD);
	}
	else if (controllerMode==70){//Capture 7 tuple for IoT only
		r =  create_ruleRawMac(p_m->ether_shost,p_m->ether_dhost,0,0,p_m->ip_p,p_m->ip_src,p_m->ip_dst,0,p_m->dport);
		flowrule_add(10,r,FORWARD);
	}
	else if (controllerMode==71){//Capture 7 tuple for IoT only
		r =  create_ruleRawMac(p_m->ether_shost,p_m->ether_dhost,0,0,p_m->ip_p,p_m->ip_src,p_m->ip_dst,0,p_m->dport);
		flowrule_add(10,r,FORWARD);
	}
	else{
		debug("No mode specified");
		exit(0);
	}

	if (count%10==0){
	 	// fprintf(stderr,"\b\b\b\b\b\b%06d",count);
	}
	count++;
	//PrintData (packet , capture_len);

	return 1;//Ask to rematch
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

struct packet_meta *create_ruleRawMac(
					u_char *ether_shost,
					u_char *ether_dhost,
					uint16_t ether_type,

					uint8_t 	ip_tos, //Type of service. 
					uint8_t 	ip_p, //Protocol. 
					struct	in_addr	ip_src, //Source IP address. 
					struct	in_addr	ip_dst, //Destination IP address. 

					u_short	sport,		// source port
					u_short	dport		//destination port
				 )
{
	struct packet_meta *rle = (struct packet_meta*)malloc(sizeof(struct packet_meta));

	mac_copy(ether_dhost,&rle->ether_dhost);
	mac_copy(ether_shost,&rle->ether_shost);

	rle->ether_type		= ether_type;
	rle->ip_tos			= ip_tos; //Type of service. 
	rle->ip_p			= ip_p; //Protocol.
	
	
    rle->ip_src = ip_src;
	rle->ip_dst = ip_dst;       

	rle->sport=sport;		// source port
	rle->dport=dport;		//destination port
        

    return rle;
}

int mac_copy(u_char* from, u_char** to){
	if (from==NULL){
		*to=NULL;
		return 0;
	}

	*to=(u_char*)malloc(sizeof(u_char)*ETHER_ADDR_LEN);
	check(*to,"Failed to char*");

	int i;

	/* copy data*/
	for( i = 0; i < ETHER_ADDR_LEN; i++ )
		(*to)[i] = (u_char) from[i];

	return 1;

	error:
		return 0;
}

void PrintData (const unsigned char* data , int Size)
{
    int i,j;

    fprintf(stderr,"Size of the payload:%d\n",Size);
    fprintf(stderr,"Header:%c%c%c%c\n",data[0] ,data[1],data[2],data[3]);
    if(Size>0){
	    for(i=0 ; i < Size ; i++)
	    {

	            for(j=0 ; j<=16 ; j++)
	            {
	                fprintf(stderr,"%x ",(unsigned char)data[16*i+j]);
	                //else fprintf(stderr,".");
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


