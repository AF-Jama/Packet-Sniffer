#include<stdio.h>
#include<pcap.h>
#include"config.h"
#define BUFFER_LEN 100

typedef unsigned short u_short;

// enum TrafficType{
//     HTTP,
//     HTTPS,
//     DNS,
//     FTP,
//     SSH
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

char * userPrompt(){
    // returns filter expression based on user stdin
    char BUFFER[BUFFER_LEN]; // declare buffer 
    int i; // define int

    printf("What type of packets would you like to sniff:\n 1 - HTTP \n 2 - HTTPS \n 3 - DNS \n 4 - FTP \n 5 - SSH \n 6 - ALL:\n");

    scanf("%d",&i); // takes user stdin

    switch (i)
    {
    case 1:
        /* code */
        printf("Sniffing HTTP packets\n");
        return "port 80";

    case 2:
    /* code */
    printf("Sniffing HTTPS packets\n");
    return "port 443";

    case 3:
        /* code */
        printf("Sniffing DNS packets\n");
        return "port 53";

    case 4:
        /* code */
        printf("Sniffing FTP packets\n");
        return "port 21";

    case 5:
        /* code */
        printf("Sniffing SSH packets\n");
        return "port 22";

    case 6:
        /* code */
        printf("Sniffing ALL packets\n");
        return "port 80 or port 443 or port 53 or port 21 or port 22";
    
    default:
        return NULL;
    }


}


void logger(FILE *fp,struct PacketData *pd){
    // logger takes file handle and packet data struct
    fprintf(fp
    ,"\n%lu, %s, %s %hu %hu %u\n"
    ,pd->ts.tv_sec,pd->source_ip,pd->destination_ip,pd->source_port,pd->destination_port,pd->offWireLength);
}