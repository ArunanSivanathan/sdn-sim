#include "dosCheck.h"



/*
int check_DOS(struct timeval *currentTime){
	static int sec = 1;
	if (nextCheck == NULL){
		nextCheck= (struct timeval*)malloc(sizeof(struct timeval));
		addTime (1000000,currentTime,nextCheck);//Add 1 sec

		for(int i=0;i<50;i++){
			noOflastPackets[i]=0;
		}
	}

	if( compTime(currentTime,nextCheck)>0){
		sec++;
		struct flowrule *c_f;
		//int i=0;
		c_f = first_rule;

		while(c_f!=NULL){
			if(c_f->flowId!=0&&((int)c_f->packetcounter-noOflastPackets[c_f->flowId])>200){
				fprintf(stderr,"DoS Suspicion: Time:%d \tFlow entry #%d\tsrc IP:",sec, c_f->flowId);
				printIP(c_f->match->ip_src);
				fprintf(stderr,"\n\a");
				sleep(1); 
			}
			noOflastPackets[c_f->flowId] =c_f->packetcounter;

			c_f=c_f->next_rule;
		}

		addTime (1000000,currentTime,nextCheck);
	}


	return 0;
}
*/

