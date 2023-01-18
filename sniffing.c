#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>

//#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version            // opposite!!!
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

/* TCP Header */
// struct tcpheader {
//     unsigned short int  source_port;   // Source port
//     unsigned short int dest_port;  // Destination port
//     unsigned int       sequence_number;    // Sequence number
//     unsigned int       ack_num;    // Acknowledgment number
//     unsigned char      reserved:4,// Reserved
//                        d_offset:4;  // Data offset
//     unsigned char      flags;     // Flags
//     unsigned short int window;       // Window
//     unsigned short int checksum;    // Checksum
//     unsigned short int urg_ptr;    // Urgent pointer
// };


//app
struct calculatorHeader {
    uint32_t timestamp;
    uint16_t total_length;
    uint16_t flags;//reserved:3, cache_flag:1, steps_flag:1, type_flag:1, status_code:10;
    uint16_t cache_control;
    uint16_t padding;
};
// struct calculatorHeader
// {
//     uint32_t timestamp;
//     uint16_t total_length;

//     union
//     {
//         uint16_t flags;
//         uint16_t _reserved:3, cache_flag:1, steps_flag:1, type_flag:1, status_code:10;
//     };
    
//     uint16_t cache_control;
//     uint16_t padding;
// };

//     { source_ip: <input>,
// dest_ip: <input>, source_port: <input>, dest_port: <input>, timestamp: <input>, total_length:
// <input>, cache_flag: <input>, steps_flag: <input>, type_flag: <input>, status_code: <input>,
// cache_control: <input>, data: <input> }


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  FILE *fp;
  fp = fopen("322953308_315138693", "a"); // open file for writing
  if (fp == NULL) {
      printf("Error opening file!\n");
      return;
  }
  
  struct ethheader *eth = (struct ethheader *)packet;
  struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
  //unsigned short iphdrlen = (ip->iph_ihl)*4;
  struct tcphdr * tcp = (struct tcphdr *)(packet + sizeof(struct ethheader)+ ((ip->iph_ihl)*4));
  //unsigned int data_offset = ((tcp->doff)* 4);
  if (tcp->psh != 1)
        return; 
  struct calculatorHeader * app_h = (struct calculatorHeader *) (packet + sizeof(struct ethheader)+ ((ip->iph_ihl)*4) + ((tcp->doff)* 4));
  
  //struct calculatorHeader * app_h = (struct calculatorHeader *) (packet + sizeof(struct ethheader)+ sizeof(struct ipheader)+sizeof(struct tcpheader));
  
  u_char * data = (u_char * )(packet + sizeof(struct ethheader)+ ((ip->iph_ihl)*4) + ((tcp->doff)* 4) + sizeof(struct calculatorHeader));//12);//
  unsigned int data_size = ntohs(ip->iph_len) - (((ip->iph_ihl)*4) + ((tcp->doff)* 4));
  if(ip->iph_protocol == IPPROTO_TCP)
  {
    fprintf(fp,"{ source_ip: %s, ", inet_ntoa(ip->iph_sourceip));
    fprintf(fp,"dest_ip: %s, \n", inet_ntoa(ip->iph_destip));

    fprintf(fp,"  source_port: %hu, ", ntohs(tcp->source));
    fprintf(fp,"dest_port: %hu, \n", ntohs(tcp->dest));


    fprintf(fp,"  timestamp: %u, ", ntohl(app_h->timestamp));//(int)(header->ts.tv_sec));
    fprintf(fp,"total_length: %hu, \n", ntohs(ip->iph_len));
    fprintf(fp,"  cache_flag: %hu, ", (app_h->flags>>12)&1);//cache_flag);
    fprintf(fp,"steps_flag: %hu, ", (app_h->flags>>11)&1);//steps_flag);
    fprintf(fp,"type_flag: %hu, \n", (app_h->flags>>10)&1);//type_flag);
    fprintf(fp,"  status_code: %hu, ", (app_h->flags)&1023);//status_code);
    fprintf(fp,"cache_control: %hu, ", app_h->cache_control);
    fprintf(fp,"\n  data:");
    if (data_size > 0)
    {
      for (int i = 0; i < data_size; i++ )
      {
        if ( !(i & 15) ) fprintf(fp,"\n%04X:  ", i);
        fprintf(fp,"%02X ", ((unsigned char*)data)[i]);
      }
    }else{
      fprintf(fp,"there is no data!");
    }
    fprintf(fp,"}\n");
    fprintf(fp,"\n");
  }
  fclose(fp);
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp port 9998-9999";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name lo
  handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);  

  FILE * fp1 = fopen("322953308_315138693", "w"); // open file for writing
  if (fp1 == NULL) {
      printf("Error opening file!\n");
      return -1;
  }
  fclose(fp1); 
  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);             
  //Close the handle
  pcap_close(handle); 

  return 0;
}