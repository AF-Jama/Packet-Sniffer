#ifndef CONFIG_H
#define CONFIG_H
#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>

typedef unsigned short u_short;

enum TrafficType{
    HTTP,
    HTTPS,
    TCP,
    DNS,
    UDP,
    ALL
}; // traffic type enum that differentiates between different traffic types


struct PacketData{
    char *destination_ip; // use inet_ntoa converting network byte order to const char *
    char *source_ip; // use inet_ntoa converting network byte order to const char *
    unsigned int offWireLength; // packet length off wire (bytes)
    struct timeval ts; // timestamp
    u_short source_port; // packet source port
    u_short destination_port; // packet destination port
}; // packet data struct that stores all information about particular packet

void logger(FILE *,struct PacketData*);





#endif