#ifndef __dsetime_h__
#define __dsetime_h__

#include "dbg.h"
#include <time.h>

//struct timeval *setPacketTime(struct timeval ts);
//struct timeval *currentEventTime();
struct timeval *addTime(int add_usec,struct timeval *src,struct timeval *results);
int compTime ( struct timeval *x, struct timeval *y);
int copyTime( struct timeval *from,struct timeval *to );
void stripMicroSeconds(struct timeval *from);
#endif