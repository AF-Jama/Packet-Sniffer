#include<stdio.h>
#include<pcap.h>
#include"config.h"

typedef unsigned short u_short;

// enum TrafficType{
//     HTTP,
//     HTTPS,
//     TCP,
//     DNS,
//     UDP,
//     ALL
// }; // traffic type enum that differentiates between different traffic types


// struct PacketData{
//     char *destination_ip; // use inet_ntoa converting network byte order to const char *
//     char *source_ip; // use inet_ntoa converting network byte order to const char *
//     unsigned int offWireLength; // packet length off wire (bytes)
//     struct timeval ts; // timestamp
//     u_short source_port; // packet source port
//     u_short destination_port; // packet destination port
// }; // packet data struct that stores all information about particular packet


void logger(FILE *fp,struct PacketData *pd){
    // logger takes file handle and packet data struct
    fprintf(fp
    ,"\n%lu, %s, %s %hu %hu %u\n"
    ,pd->ts.tv_sec,pd->source_ip,pd->destination_ip,pd->source_port,pd->destination_port,pd->offWireLength);
}