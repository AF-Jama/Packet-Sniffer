#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap.h>
#include"config.h"
#include "./structure.h"

typedef unsigned char u_char;

void got_packet(u_char*,const struct pcap_pkthdr *,const u_char*);

// void logger(const struct sniff_ip *,const struct pcap_pkthdr *, FILE *);



int main(){
    char *dev = "wlo1"; // wireless interface
    char *dev1; // define char pointer
    char errbuff[PCAP_ERRBUF_SIZE]; // define error buffer
    pcap_t *handler; // define handler session
    int mode; // define sniffing mode, promiscous or non promicous
    int timeout = 1000; // initialising  timeout
    int compile; // define compile 
    struct bpf_program fp; // define compiled filter expression
    char *filter_rule; // define filter rule char pointer (memory address of char) 
    bpf_u_int32 net; // define netmask
    bpf_u_int32 mask; // define mask
    int filter;
    __u_char *packet; // define packet pointer
    struct pcap_pkthdr header; // define packet header
    int pcap_loop_value; // define pcap loop value
    FILE *file_handle; // define file pointer handle
    char *file = "logs.txt";
    char *file_mode = "w";

    file_handle = fopen(file,file_mode); // assign file handle pointer

    if(file_handle==NULL){
        printf("Cannot open file so cannot sniff and log data");
        return 1;
    }

    printf("File %s has been opened\n",file);

    filter_rule = userPrompt();

    if(filter_rule==NULL){
        printf("Invalid filter rule.\n");
        return 1;
    }

    // printf("Filter rule is %s\n",filter_rule);

    mode = 0; // assigning sniffing mode

    printf("%s\n",dev);

    handler = pcap_open_live(dev,BUFSIZ,mode,timeout,errbuff);

    if(handler==NULL){
        printf("Cannot handle sniffer session - %s\n",errbuff);
        return 1;
    }

    printf("Session created and handle created\n");

    // checks if handle provides link layer headers

    if(pcap_datalink(handler)!=DLT_EN10MB){
        // triggered if handler does not provide required link layer headers
        printf("Device %s does not provide IEEE802_11 header types\n",dev);
        return 1;
    }

    compile = pcap_compile(handler,&fp,filter_rule,1,net);

    if(compile!=0){
        printf("Cannot compile fliter rules\n");
        return 1;
    }

    printf("Filter compiled succesfully\n");

    filter = pcap_setfilter(handler,&fp);

    if(filter!=0){
        printf("Filter cannot be set\n");
        return 1;
    }

    if(pcap_lookupnet(dev,&net,&mask,errbuff)==PCAP_ERROR){
        printf("Could not lookup network information using device %s\n",dev);
        return 1;
    }

    printf("%d\n",net);
    printf("%d\n",mask);

    // packet = (__u_char *) pcap_next(handler,&header);

    // printf("Header length is %d bytes\n",header.len);
    // printf("Header timestamp is %lu\n",header.ts.tv_sec);

    int cnt=-1; // initialising packet count

    u_char *fp_handle = (u_char *) file_handle; // file handle typecasted to u_char *

    pcap_loop_value = pcap_loop(handler,cnt,got_packet,fp_handle);








    return 0;
}

void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet){
    // triggers call back when packet is recieved by interface
    static int counter=0; // counter that is persistant throughout whole program rather than automatic storage allocation. Stored in static memory segment
    char source_buffer[100]; // source ip buffer
    char destination_buffer[100]; // destination ip buffer

    FILE *file_handler = (FILE *) args; // typecasts u_char pointer to FILE pointer
    
    if(counter==0) fprintf(file_handler,"%s | %s | %s | %s | %s | %s",
    "Timestamp","Source IP","Destination IP","Source Port","Destination Port","Protocol\n");

    const struct sniff_ethernet *ethernet; // define ethernet pointer
    const struct sniff_ip *ip; // define ip pointer
    const struct sniff_tcp *tcp; // define tcp pointer
    const char *payload; // define payload pointer
    __u_int size_ip; // define size ip header
    __u_int size_tcp; // define size tcp header
    char srcip[100]; // define src ip buffer


    ethernet = (struct sniff_ethernet*) packet; // ethernet header pointer

    ip = (struct sniff_ip*) (packet+ETHER_ADDR_LEN); // ip header pointer

    size_ip = IP_HL(ip)*4;

    if(size_ip<20){
        printf("Ip header is too small\n");
        return;
    }

    tcp = (struct sniff_tcp*) (packet+ETHER_ADDR_LEN+size_ip);

    size_tcp = TH_OFF(tcp)*4;

    if(size_tcp<20){
        // printf("TCP IS VALID\n");
        return;
    }

    printf("Valid packet sniffed\n");

    payload = (const char*) (packet+ETHER_ADDR_LEN+size_ip+size_tcp);

    printf("Source address is %s\n",inet_ntoa(ip->ip_src));
    printf("Destination address is %s\n",inet_ntoa(ip->ip_dst));

    strcpy(source_buffer,inet_ntoa(ip->ip_src));
    strcpy(destination_buffer,inet_ntoa(ip->ip_dst));

    struct PacketData *pd; // declare packet data struct pointer (stores memory address of a struct PacketData)

    pd = (struct PacketData*) malloc(sizeof(struct PacketData)); // assign pointer, returns void pointer (memory address to to no specific datatype) and typecasted to struct PacketData pointer (stores memory address of struct PacketData)

    pd->source_ip= source_buffer;
    pd->destination_ip= destination_buffer;
    pd->source_port= tcp->th_sport;
    pd->destination_port= tcp->th_dport;
    pd->offWireLength=header->len;
    pd->ts=header->ts;

    logger(file_handler,pd);

    free(pd);

    // logger(ip,header,file_handler);

    counter++; // increments counter


    // printf("Header length is %d\n",header->len);
}

// void logger(const struct sniff_ip *ip,const struct pcap_pkthdr *header, FILE *fp){
//     printf("Logged\n");
//     fprintf(fp,"\n%lu  %d  %s  %s\n",header->ts.tv_sec,header->len,inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst));
// }

// Timestamp|Source IP | Destination IP | Source Port | Destination Port | Protocol | packet size