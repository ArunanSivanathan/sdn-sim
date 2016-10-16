/*
 *	equeue.c
 */ 
#include "equeue.h"

FILE *log_packet, *log_flowEntry, *log_packetevent, *log_event_traverse, *log_actions, *log_flowmatch, *log_flowCountuse,*log_flowRateuse;
struct event_node* e_Head;
struct event_node* e_Tail;;

struct event_node *insertEvent( unsigned int p_id, enum EVENT_TYPE e_t, struct timeval ts){

	struct event_node *ptr = (struct event_node*)malloc(sizeof(struct event_node));
	check(ptr, "Failed to create event node.");


	ptr->id=p_id;
	ptr->event=e_t;
	ptr->ts=ts;
	ptr->past_event=NULL;
	ptr->next_event=NULL;

	if (e_Head==NULL){
		e_Tail=e_Head = ptr;
	}
	else{
		struct event_node *cur_e;
		struct event_node *pre_e;
		cur_e = e_Head;
		pre_e = NULL;

		//Place the event as sorted by time
		while(cur_e!=NULL && (compTime ( &(cur_e->ts),&(ptr->ts) )==1)){
		    pre_e = cur_e;
		    cur_e=cur_e->past_event;
		} 
	        
		ptr->next_event=pre_e;
		if(cur_e==NULL){
			e_Tail=ptr;
		}
		else{
			cur_e->next_event=ptr;
		}

		ptr->past_event=cur_e;
		if ( pre_e ==NULL){
		    e_Head = ptr;
		}
		else{
		    pre_e->past_event= ptr;
		        
		}

	}

	if(ptr->event==PACK_ARRIVAL){
		flush_event_logs(ptr);
	}


	return ptr;

	error:
		return NULL;
}

void openlogs(){
	check(openlog_packet_event(),"Failed to create packet event log");
	check(openlog_event_traverse(),"Failed to create event traverse log");
	check(openlog_action(),"Failed to create event packet action log");
	check(openlog_flowmatch(),"Failed to create flow matching entry log");
	check(openlog_flowuse(),"Failed to create flow use entry log");
 	check(openlog_flowentry(),"Failed to create flow entry log");
 	check(openlog_packet(),"Failed to create flow entry log");
	return;

	error:
		exit(1);
}

void closelogs(){
	flush_event_logs(NULL);//Flush all remaining events
	fclose(log_event_traverse);
	fclose(log_packetevent);
	fclose(log_actions);
	fclose(log_flowmatch);
	fclose(log_flowCountuse);
	fclose(log_flowRateuse);
	fclose(log_flowEntry);
	fclose(log_packet);
	return;
}

void flush_event_logs(struct event_node *upto_this){
	struct event_node *c_e, *p_e;
	const char* event_names[] = {"PACK_ARRIVAL", "SERVICE_IN", "SERVICE_OUT" };

	c_e = e_Tail;
	while(c_e!=NULL && c_e!=upto_this){

		if (EVENTINFO==1){
			fprintf(log_event_traverse,"%s,",short_ts(&(c_e->ts)));
			fprintf(log_event_traverse,"%lu,",c_e->id);
			fprintf(log_event_traverse,"%s\n",event_names[c_e->event]);
		}

		p_e=c_e;
		c_e=c_e->next_event;

		free(p_e);
		if(c_e!=NULL){
			c_e->past_event = NULL;
			e_Tail=c_e;
		}
	} 
}

int tickTimeCallBack(struct timeval *packetTime){

	// Initialize timer
	static struct timeval *currentSec = NULL;
	static struct timeval *nextSec = NULL;
	static int secNo = 0;


	if (currentSec == NULL){
		currentSec= (struct timeval*)malloc(sizeof(struct timeval));//Allocate space for current seconds
		nextSec= (struct timeval*)malloc(sizeof(struct timeval));//Allocate space for next seconds

		// Set the first packet second as starting time
		copyTime (packetTime, currentSec);
		stripMicroSeconds(currentSec);//Round Down to Seconds
		addTime (1000000,currentSec,nextSec);//Add 1 sec
 
		for(int i=0;i<MaxFlows;i++){//Reset the flows
			noOflastPackets[i]=0;
			lastDataPassed[i]=0;

			noOfcurrentPackets[i] = 0;
			currentDataPassed[i] = 0;

		}
	}

	//Do until current packet come in frame 

	// printtime(currentSec,"Current time");
	// printtime(packetTime,"Packet time");
	// printtime(nextSec,"Next time\n");

	if (compTime(currentSec, packetTime)>0){//If wrong time Identified on packet
		// fprintf(stderr, "Wrong time on packet\n" );
		return secNo;
	}

	while(!(compTime(currentSec, packetTime)<=0 && compTime(nextSec, packetTime)>0)){

		//Move to next frame
		copyTime (nextSec, currentSec);
		addTime (1000000,currentSec,nextSec);//Add 1 sec
		secNo +=1;
		
		//If current packet falls next frame, write the current statistics of current slot

		if( compTime(currentSec, packetTime)<=0 && compTime(nextSec, packetTime)>0){
			
			//Write calculate the flow rule stats in current seconds
			struct flowrule *c_f = first_rule;
			while(c_f!=NULL){
				noOfcurrentPackets[c_f->flowId] = c_f->packetcounter - noOflastPackets[c_f->flowId];
				noOflastPackets[c_f->flowId] =c_f->packetcounter;
				currentDataPassed[c_f->flowId] = c_f->datacounter - lastDataPassed[c_f->flowId];
				lastDataPassed[c_f->flowId] =c_f->datacounter;
				c_f=c_f->next_rule;
			}
		}
		//If some seconds was idel before the packet arrive
		else{
			//Set the current Seconds as Null
			// fprintf(stderr, "(IT)\t" );
			struct flowrule *c_f = first_rule;
			while(c_f!=NULL){
				noOfcurrentPackets[c_f->flowId] = 0;
				currentDataPassed[c_f->flowId] = 0;
				c_f=c_f->next_rule;
			}
		}
		

		printFlowUse( secNo,  noOfcurrentPackets,currentDataPassed);	

 		if (secNo%(60)==0){
	 		fprintf(stderr, "\b\b\b\b\b\b\b%06d\t",secNo);
	 	}

	}

	return secNo;//Current Seconds



	// //Move the secs to current Sec
	// struct timeval *nextCurrentSec;
	// addTime (1000000,currentTime,nextCurrentSec);
	// while( compTime(nextCurrentSec,nextCheck)>0){
	// 	sec++; //Skip the seconds
	// 	struct flowrule *c_f;
	// 	c_f = first_rule;

	// 	while(c_f!=NULL){

	// 		noOfcurrentPackets[c_f->flowId] = 0;
	// 		currentDataPassed[c_f->flowId] = 0;

	// 		c_f=c_f->next_rule;
	// 	}

	// 	addTime (1000000,currentTime,nextCheck);

	// 	//Add call back functions here
	// 	printFlowUse( sec,  noOfcurrentPackets,noOflastPackets);		
	// }

	// //One Sec Call Back Trigger
	// if( compTime(currentTime,nextCheck)>0){
	// 	sec++;
	// 	struct flowrule *c_f;
	// 	//int i=0;
	// 	c_f = first_rule;

	// 	while(c_f!=NULL){

	// 		noOfcurrentPackets[c_f->flowId] = c_f->packetcounter - noOflastPackets[c_f->flowId];
	// 		noOflastPackets[c_f->flowId] =c_f->packetcounter;

	// 		currentDataPassed[c_f->flowId] = c_f->datacounter - lastDataPassed[c_f->flowId];
	// 		lastDataPassed[c_f->flowId] =c_f->datacounter;

	// 		c_f=c_f->next_rule;
	// 	}

	// 	addTime (1000000,currentTime,nextCheck);

	// 	//Add call back functions here
	// 	printFlowUse( sec,  noOfcurrentPackets,noOflastPackets);


	// }


}


void print_packet_events(struct packet_events *p_e,unsigned int pack_size){



	timersub(&(p_e->service_in), &(p_e->arrival), &(p_e->waiting));
	if (PACKETINFOPRINT==1){
		fprintf(log_packetevent,"%lu,",p_e->packetno);
		fprintf(log_packetevent,"%d,",pack_size);
		fprintf(log_packetevent,"%s,",short_ts(&(p_e->arrival)));
		fprintf(log_packetevent,"%s,",short_ts(&(p_e->waiting)));
		fprintf(log_packetevent,"%s,",short_ts(&(p_e->service_in)));
		fprintf(log_packetevent,"%s\n",short_ts(&(p_e->service_out)));
	}
}


void print_packet_action(unsigned long pid, enum ACTION_TYPE action, struct pcap_pkthdr *header){
	if (PACKETINFOPRINT==1){
		fprintf(log_actions,"%s,",timestamp_string(&(header->ts)));
		fprintf(log_actions,"%lu,",pid);
		fprintf(log_actions,"%d,",header->caplen);
		fprintf(log_actions,"%d\n",action);
	}
}

void print_flowmatch(unsigned long pid, int fid, struct pcap_pkthdr *header){
	if (PACKETINFOPRINT==1){
		fprintf(log_flowmatch,"%s,",timestamp_string(&(header->ts)));
		fprintf(log_flowmatch,"%lu,",pid);
		fprintf(log_flowmatch,"%d,",header->caplen);
		fprintf(log_flowmatch,"%d\n",fid);
	}
}

int openlog_packet_event(){
	log_packetevent=fopen("./log_packetevents.csv", "w+");
	if(log_packetevent!=NULL){
		fprintf(log_packetevent,"%s,","No");
		fprintf(log_packetevent,"%s,","Packet Size");
		fprintf(log_packetevent,"%s,","Arrival");
		fprintf(log_packetevent,"%s,","Waiting");
		fprintf(log_packetevent,"%s,","Service In");
		fprintf(log_packetevent,"%s\n","Service Out");
		return 1;
	}
	else{
		return 0;
	}
}

int openlog_event_traverse(){
	//Initialize the events;
	e_Head=NULL;
	e_Tail=NULL;
	log_event_traverse=fopen("./event_traverse.csv", "w+");
	if(log_event_traverse!=NULL){
		fprintf(log_event_traverse,"%s,","TIME");
		fprintf(log_event_traverse,"%s,","Packet ID");
		fprintf(log_event_traverse,"%s\n","Event Type");
		return 1;
	}
	else{
		return 0;
	}
}

int openlog_action(){
	log_actions=fopen("./packet_action.csv", "w+");
	if(log_actions!=NULL){
		fprintf(log_actions,"%s,","TIME");
		fprintf(log_actions,"%s,","Packet ID");
		fprintf(log_actions,"%s,","Size");
		fprintf(log_actions,"%s\n","Actions");
		return 1;
	}
	else{
		return 0;
	}
}

int openlog_flowmatch(){
	log_flowmatch=fopen("./packet_flowMatch.csv", "w+");
	if(log_flowmatch!=NULL){
		fprintf(log_flowmatch,"%s,","TIME");
		fprintf(log_flowmatch,"%s,","Packet ID");
		fprintf(log_flowmatch,"%s,","Packet Size");
		fprintf(log_flowmatch,"%s\n","Match_Flow");
		return 1;
	}
	else{
		return 0;
	}
}

void print_summary(struct sim_summary *s){
	fprintf(stderr,"\nSummary\n");
	fprintf(stderr,"Total no of packets:\t%lu\n",s->count_packet);
	fprintf(stderr,"Total data :\t%lu Bytes\n",s->count_data);
	fprintf(stderr,"No of drop:\t%lu\n",s->count_dropped);
	fprintf(stderr,"No of forwards:\t%lu\n",s->count_fwded);
	fprintf(stderr,"No of forwards to controller:\t%lu\n",s->count_fwd_controller);
}

int openlog_flowuse(){
	log_flowCountuse=fopen("./flowCount_vs_time.csv", "w+");
	log_flowRateuse=fopen("./flowRate_vs_time.csv", "w+");

	if(log_flowCountuse!=NULL && log_flowRateuse!= NULL){
		fprintf(log_flowCountuse,"%s","Sec");
		fprintf(log_flowRateuse,"%s","Sec");
		int i;
		for (i =0; i<MaxFlows;i++){
			fprintf(log_flowCountuse,",%04d",i);
			fprintf(log_flowRateuse,",%04d",i);
		}

		fprintf(log_flowCountuse,"\n");
		fprintf(log_flowRateuse,"\n");
		return 1;
	}
	else{
		return 0;
	}
}

int openlog_flowentry(){
	log_flowEntry=fopen("./flow_info.csv", "w+");
	if(log_flowEntry!=NULL){
		fprintf(log_flowEntry,"%s,","ID");
		fprintf(log_flowEntry,"%s,","eth.src");
		fprintf(log_flowEntry,"%s,","eth.dst");
		fprintf(log_flowEntry,"%s,","IP.src");
		fprintf(log_flowEntry,"%s,","IP.dst");
		fprintf(log_flowEntry,"%s,","IP.proto");
		fprintf(log_flowEntry,"%s,","port.src");
		fprintf(log_flowEntry,"%s,","port.dst");
		fprintf(log_flowEntry,"%s,","priority");
		fprintf(log_flowEntry,"%s,","action");
		fprintf(log_flowEntry,"%s,","packets");
		fprintf(log_flowEntry,"%s\n","bytes");
		return 1;	}
	else{
		return 0;
	}
}

int printFlowUse(int secs, int *CurrentCount,unsigned long long *currentRate){
	 if (FLOWUSEPRINT==0)
	 	return 0;

	fprintf(log_flowCountuse,"%d",secs);	
	fprintf(log_flowRateuse,"%d",secs);	
	int i;
	for (i =0; i<MaxFlows;i++){
		fprintf(log_flowCountuse,",%d",CurrentCount[i]);
		fprintf(log_flowRateuse,",%llu",currentRate[i]);
	}
	fprintf(log_flowCountuse,"\n");
	fprintf(log_flowRateuse,"\n");
	return 0;
}

int printFlowEntry(){
	struct flowrule *c_f;
	//int i=0;
	c_f = first_rule;

	while(c_f!=NULL){

		fprintf(log_flowEntry,"%04d,",c_f->flowId);
		fprintf(log_flowEntry,"%s,",strMac(c_f->match->ether_shost));//mac
		fprintf(log_flowEntry,"%s,",strMac(c_f->match->ether_dhost));//mac
		fprintf(log_flowEntry,"%s,",inet_ntoa(c_f->match->ip_src));//IP
		fprintf(log_flowEntry,"%s,",inet_ntoa(c_f->match->ip_dst));//IP
		fprintf(log_flowEntry,"0x%x,",c_f->match->ip_p);//IP.proto
		fprintf(log_flowEntry,"%d,",c_f->match->sport);//s.port
		fprintf(log_flowEntry,"%d,",c_f->match->dport);//d.port

		fprintf(log_flowEntry,"%d,",c_f->priority);
		fprintf(log_flowEntry,"%d,",c_f->action);
		fprintf(log_flowEntry,"%lu,",c_f->packetcounter);
		fprintf(log_flowEntry,"%lu\n",c_f->datacounter);


		c_f=c_f->next_rule;
	} 
	fprintf(log_flowEntry,"%s\n","");
	return 0;
}


int openlog_packet(){
	log_packet=fopen("./packet_tuples.csv", "w+");
	if(log_packet!=NULL){
		fprintf(log_packet,"%s,","Packet ID");
		fprintf(log_packet,"%s,","TIME");
		fprintf(log_packet,"%s,","Size");
		fprintf(log_packet,"%s,","eth.src");
		fprintf(log_packet,"%s,","eth.dst");
		fprintf(log_packet,"%s,","IP.src");
		fprintf(log_packet,"%s,","IP.dst");
		fprintf(log_packet,"%s,","IP.proto");
		fprintf(log_packet,"%s,","port.src");
		fprintf(log_packet,"%s\n","port.dst");
		return 1;
	}
	else{
		return 0;
	}
}
int printPacketTuples(unsigned long pid, struct packet_meta *c_meta, struct pcap_pkthdr *header){
	if (PACKETINFOPRINT==1){
		fprintf(log_packet,"%lu,",pid);
		fprintf(log_packet,"%s,",timestamp_string(&(header->ts)));
		fprintf(log_packet,"%d,",header->caplen);
		fprintf(log_packet,"%s,",strMac(c_meta->ether_shost));//mac
		fprintf(log_packet,"%s,",strMac(c_meta->ether_dhost));//mac
		fprintf(log_packet,"%s,",inet_ntoa(c_meta->ip_src));//IP
		fprintf(log_packet,"%s,",inet_ntoa(c_meta->ip_dst));//IP
		fprintf(log_packet,"0x%x,",c_meta->ip_p);//IP.proto
		fprintf(log_packet,"%d,",c_meta->sport);//s.port
		fprintf(log_packet,"%d\n",c_meta->dport);//d.port
	}
	return 0;
}