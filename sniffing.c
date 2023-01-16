#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 16

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

//tcp 

//s_port
//d_port

/* TCP Header */
struct tcpheader {
    unsigned short int  source_port;   // Source port
    unsigned short int dest_port;  // Destination port
    unsigned int       sequence_number;    // Sequence number
    unsigned int       ack_num;    // Acknowledgment number
    unsigned char      reserved:4;// Reserved
    unsigned char      d_offset:4;  // Data offset
    unsigned char      flags;     // Flags
    unsigned short int window;       // Window
    unsigned short int checksum;    // Checksum
    unsigned short int urg_ptr;    // Urgent pointer
};


//app
typedef struct calculatorPacket {
    uint32_t timestamp;
    uint16_t total_length;
    uint16_t reserved:3;
    uint16_t cache_flag:1;
    uint16_t steps_flag:1;
    uint16_t type_flag:1;
    uint16_t status_code:10;
    uint16_t cache_control;
    uint16_t padding;
} cpack, *pcpack;

//payload


    // printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));  
    // printf("         To: %s\n", inet_ntoa(ip->iph_destip)); 

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Got a packet\n");
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
    struct tcpheader * tcp_h = (struct tcpheader *)(packet + sizeof(struct ethheader)+ sizeof(struct ipheader)); 

    printf("{ source_ip: %s, ", inet_ntoa(ip->iph_sourceip));
    printf("dest_ip: %s, ", inet_ntoa(ip->iph_destip));

    printf("source_port: %d, ", tcp_h->source_port);
    printf("dest_port: %d, ", tcp_h->dest_port);


  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    //app

    //data

    /* determine protocol */
    switch(ip->iph_protocol) {                               
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}