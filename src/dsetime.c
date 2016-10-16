#include "dsetime.h"

//Several lines were commented to ignore real processing time
//struct timeval c_packet_time;
//struct timeval c_packet_realtime;
//struct timeval c_current_time;

//struct timeval *setPacketTime(struct timeval t_s){
//	c_packet_time = t_s;
	//gettimeofday (&c_packet_realtime, NULL);
	//printtime(&t_s,"Set Packet Time");
//	return &c_packet_time;
//}

struct timeval *addTime(int  add_usec,struct timeval *src,struct timeval *results){
	int totalusec=src->tv_usec + add_usec;
	//debug("tv_usec:%d, add_usec:%d = totalusec:%d, ",src->tv_usec,add_usec, totalusec );
	results->tv_sec = src->tv_sec + (totalusec/1000000);//Get the additional seconds
	results->tv_usec = totalusec%1000000;//Get the additional seconds

	return results;
}

int compTime ( struct timeval *x, struct timeval *y){
	/**
	If x>y return 1
	elseif x<y return -1
	elseif x==y return 0
	**/

	if(x->tv_sec  >  y->tv_sec ){
		return 1;
	}
	else if(x->tv_sec  <  y->tv_sec){
		return -1;
	}
	else { //if(x->tv_sec  ==  y->tv_sec)
		if (x->tv_usec  >  y->tv_usec){
			return 1;
		}
		else if (x->tv_usec  <  y->tv_usec){
			return -1;
		}
		else{
			return 0;
		}
	}

}

int copyTime( struct timeval *from,struct timeval *to ){
	to->tv_sec=from->tv_sec;
	to->tv_usec=from->tv_usec;
	return 0;
}

void stripMicroSeconds(struct timeval *from){
	from->tv_usec=0;

}

//struct timeval *currentEventTime(){
	//struct timeval c_tm;
	//struct timeval c_real_now;
	//gettimeofday (&c_real_now, NULL);

	//timersub(&c_real_now, &c_packet_realtime, &c_tm);
	//timeradd(&c_tm, &c_packet_time, &c_current_time);

//	return &c_packet_time;
//}