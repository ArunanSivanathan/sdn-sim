
#include "equeue.h"
#include "service.h"
#include "dsetime.h"
#include "controller.h"
#include <netinet/if_ether.h>

#define SERVICE_RATE 13107200 //10Mbps *1024 *1024 /8

pcap_t *pcap;
int source(const unsigned char **packet,struct pcap_pkthdr * header);

struct packet_events c_packetevents;

int main(int argc, char *argv[]){

	displayBanner();

	const unsigned char* packet;
	struct pcap_pkthdr header;

	
	struct sim_summary full_summary;

	char errbuf[PCAP_ERRBUF_SIZE];


	/* Skip over the program name. */
	++argv; --argc;

	/* We expect exactly one argument, the name of the file to dump. */
	if ( argc != 2 ){
		fprintf(stderr, "program requires one argument, the trace file to dump and mode\n");
		exit(1);	
	}


	/* Load the pcap file in parser */
	pcap = pcap_open_offline(argv[0], errbuf);
	if (pcap == NULL){
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}


	openlogs();
	
	full_summary.count_packet=0;
	full_summary.count_data=0;
	full_summary.count_dropped=0;
	full_summary.count_fwded=0;
	full_summary.count_fwd_controller=0;



	init_controller(atoi(argv[1]));

	//traverse_flow(fr_Head);

    int servicetime = 0;
	struct timeval previousDepart;

	c_packetevents.packetno=0;
	previousDepart.tv_sec=0; previousDepart.tv_usec=0;

	//Start Simulation
	while(source(&packet,&header)){// not complete

		//Packet Arrival
		c_packetevents.arrival=header.ts;
		insertEvent(++c_packetevents.packetno,PACK_ARRIVAL,header.ts);//Packet Arrival


		//Packet Service In = Max(Packet Arrival, Last Packet depature) 
		if (compTime(&previousDepart,&(c_packetevents.arrival))==1){
			c_packetevents.service_in = previousDepart;
		}
		else{
			c_packetevents.service_in = c_packetevents.arrival;
		}
		insertEvent(c_packetevents.packetno,SERVICE_IN,c_packetevents.service_in);//Packet Arrival

		//Lookup
		do_service(c_packetevents.packetno,packet,&header,&full_summary);
		//Compute service time
		servicetime = 1000000 * header.caplen / SERVICE_RATE ;//Compute  servicetime in u_sec
		addTime(servicetime, &c_packetevents.service_in, &c_packetevents.service_out);
		insertEvent( c_packetevents.packetno,SERVICE_OUT,c_packetevents.service_out);//Packet Arrival
		

		print_packet_events(&c_packetevents,header.caplen);
		previousDepart=c_packetevents.service_out;

	}

	


	printFlowEntry();
	print_summary(&full_summary);

	closelogs();

}




//Get next Packet
int source(const unsigned char **packet, struct pcap_pkthdr * header){


	*packet = pcap_next(pcap, header);

	if (*packet!= NULL){		
		return 1;
	}
	else{
		return 0;
	}
}

