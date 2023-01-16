#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6

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
    unsigned char      reserved:4,// Reserved
                       d_offset:4;  // Data offset
    unsigned char      flags;     // Flags
    unsigned short int window;       // Window
    unsigned short int checksum;    // Checksum
    unsigned short int urg_ptr;    // Urgent pointer
};


//app
struct calculatorHeader {
    uint32_t timestamp;
    uint16_t total_length;
    uint16_t reserved:3, cache_flag:1, steps_flag:1, type_flag:1, status_code:10;
    uint16_t cache_control;
    uint16_t padding;
};

//payload


    // printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));  
    // printf("         To: %s\n", inet_ntoa(ip->iph_destip)); 


//     { source_ip: <input>,
// dest_ip: <input>, source_port: <input>, dest_port: <input>, timestamp: <input>, total_length:
// <input>, cache_flag: <input>, steps_flag: <input>, type_flag: <input>, status_code: <input>,
// cache_control: <input>, data: <input> }


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Got a packet\n");
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
    unsigned short iphdrlen = (ip->iph_ihl)*4;
    struct tcpheader * tcp_h = (struct tcpheader *)(packet + sizeof(struct ethheader)+ iphdrlen);
    unsigned int data_offset = (tcp_h->d_offset)* 4; 
    struct calculatorHeader * app_h = (struct calculatorHeader *) (packet + sizeof(struct ethheader)+ iphdrlen + data_offset);
    u_char * data = (u_char * )(packet + sizeof(struct ethheader)+ iphdrlen + data_offset + sizeof(app_h));
    // printf("{ source_ip: %s, ", inet_ntoa(ip->iph_sourceip));
    // printf("dest_ip: %s, ", inet_ntoa(ip->iph_destip));

    // printf("source_port: %hu, ", ntohs(tcp_h->source_port));
    // printf("dest_port: %hu, ", ntohs(tcp_h->dest_port));

    // printf("timestamp: %u, ", ntohl(app_h->timestamp));
    // printf("total_length: %u, ", ntohs(app_h->total_length));
    // printf("cache_flag: %d, ", ntohs(app_h->cache_flag));
    // printf("steps_flag: %d, ", ntohs(app_h->steps_flag));
    // printf("type_flag: %d, ", ntohs(app_h->type_flag));
    // printf("status_code: %u, ", ntohs(app_h->status_code));
    // printf("cache_control: %u, ", ntohs(app_h->cache_control));




  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type


    /* determine protocol */
    switch(ip->iph_protocol) {                               
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");

            printf("{ source_ip: %s, ", inet_ntoa(ip->iph_sourceip));
            printf("dest_ip: %s, ", inet_ntoa(ip->iph_destip));

            printf("source_port: %u, ", ntohs(tcp_h->source_port));
            printf("dest_port: %u, ", ntohs(tcp_h->dest_port));

            printf("timestamp: %u, ", ntohl(app_h->timestamp));
            printf("total_length: %u, ", ntohs(app_h->total_length));
            printf("cache_flag: %hu, ", app_h->cache_flag);
            printf("steps_flag: %hu, ", app_h->steps_flag);
            printf("type_flag: %hu, ", app_h->type_flag);
            printf("status_code: %u, ", ntohs(app_h->status_code));
            printf("cache_control: %u, ", ntohs(app_h->cache_control));
            printf("data: \n");

            for (int i = 0; i < sizeof(data); i++ )
            {
              if ( !(i & 15) ) printf("\n%04X:  ", i);
              printf("%02X ", ((unsigned char*)data)[i]);
            }
            printf("\n");
        default:
            return;
    }
  }
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

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}