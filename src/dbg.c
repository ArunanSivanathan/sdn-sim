#include "dbg.h"

//Careful, don't use more than one function in one printf
const char *timestamp_string(struct timeval *ts) {
	static char timestamp_string_buf[256];


	struct tm *nowtm;//Time in readable format
	char tmbuf[64];


	nowtm = localtime(&(ts->tv_sec));
	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);

	sprintf(timestamp_string_buf, "%s.%06d",tmbuf, (int) ts->tv_usec);

	return timestamp_string_buf;
}

//Careful, don't use more than one function in one printf
const char *short_ts(struct timeval *ts) {
	static char timestamp_string_buf[256];

	struct tm *nowtm;//Time in readable format
	char tmbuf[64];


	nowtm = localtime(&(ts->tv_sec));
	strftime(tmbuf, sizeof tmbuf, "%M:%S", nowtm);

	sprintf(timestamp_string_buf, "%s.%06d",tmbuf, (int) ts->tv_usec);

	return timestamp_string_buf;
}

void displayBanner(){
fprintf(stderr," ____  ____  _   _   ____ ___ __  __ \n/ ___||  _ \\| \\ | | / ___|_ _|  \\/  |\n\\___ \\| | | |  \\| | \\___ \\| || |\\/| |\n ___) | |_| | |\\  |  ___) | || |  | |\n|____/|____/|_| \\_| |____/___|_|  |_|\n");

	fprintf(stderr,"\n\n--------------------------------------------------------------\n");                                     
	fprintf(stderr,"\t\t\tWarning\t\t\t\n");
	fprintf(stderr,"* Current version of simulator just work with IP4 packets only\n");
	fprintf(stderr,"* It will ignore all the other packets including ARP and IPV6\n");
	fprintf(stderr,"--------------------------------------------------------------\n\n\n\n\n");
}