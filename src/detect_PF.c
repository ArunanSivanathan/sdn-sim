#include "detect_PF.h"

/* The following is the size of a buffer to contain any error messages
   encountered when the regular expression is compiled. */

#define MAX_ERROR_MSG 0x1000

/* Compile the regular expression described by "regex_text" into
   "r". */
static int match_regex (regex_t * r, const char * to_match);
static int compile_regex (regex_t * r, const char * regex_text);

static int compile_regex (regex_t * r, const char * regex_text){
    int status = regcomp (r, regex_text, REG_EXTENDED|REG_NEWLINE);
    if (status != 0) {
	char error_message[MAX_ERROR_MSG];
	regerror (status, r, error_message, MAX_ERROR_MSG);
        printf ("Regex error compiling '%s': %s\n",
                 regex_text, error_message);
        return 1;
    }
    return 0;
}

/*
  Match the string in "to_match" against the compiled regular
  expression in "r".
 */

static int match_regex (regex_t * r, const char * to_match){
    /* "P" is a pointer into the string which points to the end of the
       previous match. */
    const char * p = to_match;
    /* "N_matches" is the maximum number of matches allowed. */
    const int n_matches = 10;
    /* "M" contains the matches found. */
    regmatch_t m[n_matches];

    while (1) {
        int i = 0;
        int nomatch = regexec (r, p, n_matches, m, 0);
        if (nomatch) {
            //printf ("No more matches.\n");
            return nomatch;
        }
        for (i = 0; i < n_matches; i++) {
            int start;
            int finish;
            if (m[i].rm_so == -1) {
                break;
            }
            start = m[i].rm_so + (p - to_match);
            finish = m[i].rm_eo + (p - to_match);
            if (i == 0) {
                printf ("$& is ");
            }
            else {
                printf ("$%d is ", i);
            }
            printf ("'%.*s' (bytes %d:%d)\n", (finish - start),
                    to_match + start, start, finish);
        }
        p += m[0].rm_eo;
    }
    return 0;
}

void findPF(const unsigned char *payload, int size){
    regex_t r;
    const char * regex_text;
    char * find_text;

    find_text = malloc(size+1);
    memcpy ( find_text, payload, size );
    find_text[size]='\0';

    regex_text = "<NewExternalPort>(.+)</NewExternalPort>";


    //debug ("Trying to find '%s' in '%s'\n", regex_text, find_text);
    compile_regex(& r, regex_text);
    match_regex(& r, find_text);
    regfree (& r);

    free(find_text);
    return ;
}

int deep_analysis(struct packet_meta *p_m, const unsigned char *packet, struct pcap_pkthdr* header,unsigned long pid){


    //debug("Packet received by controller");
    //print_pac_meta(p_m);
    //fprintf(stderr, "\n");


    unsigned int capture_len = header->caplen;
    unsigned int length;

    packet += sizeof(struct ether_header);
    capture_len -= sizeof(struct ether_header);

    struct ip *p_ip = (struct ip*) packet;
    length = p_ip->ip_hl * 4;   /* ip_hl is in 4-byte words */


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


    //struct packet_meta *r;
    /* DNS */
    struct in_addr nullIP;
     inet_aton("0.0.0.0", &nullIP);

    // fprintf(stderr, ":%lu\t",pid );
    char* macName = strMacFileName(p_m->ether_shost);
    char fileName[50];

    snprintf(fileName, sizeof(fileName), "./dnsrecords/%s_dns.csv",macName);

    //printf(stderr, "%s\n",fileName );
    FILE *dnsDump=fopen(fileName, "a+");
    if(dnsDump!=NULL){
        PrintDNS (packet , capture_len,dnsDump);
        fclose(dnsDump);
    }
    else{
        debug("DNS dump failed");
        return 1;
    }
    
    


    return 0;
}




void PrintDNS (const unsigned char* data , int Size,FILE *filePointer)
{
    int i,j;
    int Bytes=0;

    // fprintf(stderr, "Transaction ID:%02x%02x\n", data[Bytes+0],data[Bytes+1]);
    //fprintf(stderr, "%02x%02x\t", data[Bytes+0],data[Bytes+1]);
    Bytes+=2;

    // fprintf(stderr, "OpCode ID:%02x%02x\n", data[Bytes+0],data[Bytes+1]);
    //fprintf(stderr, "%02x%02x\t", data[Bytes+0],data[Bytes+1]);
    Bytes+=2;

    int qCount= (((int)data[Bytes+0]) <<8)|(int)data[Bytes+1];
    // fprintf(stderr, "Question count int:%d\n", qCount);
    //fprintf(stderr, "%04x\t", qCount);
    Bytes+=2;

    //int ansCount= (((int)data[Bytes+0]) <<8)|(int)data[Bytes+1];
    // fprintf(stderr, "Answer count int:%d\n", ansCount);
    //fprintf(stderr, "%04x\t", ansCount);
    Bytes+=2;

    //int NSCount= (((int)data[Bytes+0]) <<8)|(int)data[Bytes+1];
    // fprintf(stderr, "Name server count int:%d\n", NSCount);
    //fprintf(stderr, "%04x\t", NSCount);
    Bytes+=2;

    //int ARCount= (((int)data[Bytes+0]) <<8)|(int)data[Bytes+1];
    // fprintf(stderr, "Additional count int:%d\n", ARCount);
    //fprintf(stderr, "%04x\t", ARCount);
    Bytes+=2;

    for (i=0;i<qCount;i++){//Print the queries
        // fprintf(stderr, "Q%d->", i+1);
        while(data[Bytes+0]){//Until find a Null
            short numberchars = data[Bytes+0];
            Bytes+=1;
            for(j=0;j<numberchars;j++){
                fprintf(filePointer, "%c",data[Bytes+0]);
                Bytes+=1;
            }
            if (data[Bytes+0]!='\0') fprintf(filePointer, ".");
        }
        fprintf(filePointer, "\n" );
        Bytes+=1;
    }


    // for (i=0;i<ansCount;i++){//Print the queries
    //     fprintf(stderr, "ANS%d->", i+1);
    //     while(data[Bytes+0]){//Until find a Null
    //         short numberchars = data[Bytes+0];
    //         Bytes+=1;
    //         for(j=0;j<numberchars;j++){
    //             fprintf(stderr, "%c",data[Bytes+0]);
    //             Bytes+=1;
    //         }
    //         if (data[Bytes+0]!='\0') fprintf(stderr, ".");
    //     }
    //     fprintf(stderr, "\t" );
    //     Bytes+=1;
    // }

    // for (i=0;i<NSCount;i++){//Print the queries
    //     fprintf(stderr, "NS%d->", i+1);
    //     while(data[Bytes+0]){//Until find a Null
    //         short numberchars = data[Bytes+0];
    //         Bytes+=1;
    //         for(j=0;j<numberchars;j++){
    //             fprintf(stderr, "%c",data[Bytes+0]);
    //             Bytes+=1;
    //         }
    //         if (data[Bytes+0]!='\0') fprintf(stderr, ".");
    //     }
    //     fprintf(stderr, "\t" );
    //     Bytes+=1;
    // }

    // for (i=0;i<ARCount;i++){//Print the queries
    //     fprintf(stderr, "AR%d->", i+1);
    //     while(data[Bytes+0]){//Until find a Null
    //         short numberchars = data[Bytes+0];
    //         Bytes+=1;
    //         for(j=0;j<numberchars;j++){
    //             fprintf(stderr, "%c",data[Bytes+0]);
    //             Bytes+=1;
    //         }
    //         if (data[Bytes+0]!='\0') fprintf(stderr, ".");
    //     }
    //     fprintf(stderr, "\t" );
    //     Bytes+=1;
    // }
    // fprintf(stderr, "\n" );
}

char* strMacFileName(u_char* mac){
    static char m[13];
    if (mac == NULL){
        strncpy (m,"NULL",13);
    }
    else{
    snprintf(m, sizeof(m), "%02x%02x%02x%02x%02x%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    return m;
}