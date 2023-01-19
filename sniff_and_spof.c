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

struct ipheader {
    unsigned int ip_hl:4;          /* header length */
    unsigned int ip_v:4;           /* version */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                /* total length */
    u_short ip_id;                 /* identification */
    u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000              /* reserved fragment flag */
#define IP_DF 0x4000              /* don't fragment flag */
#define IP_MF 0x2000              /* more fragments flag */
#define IP_OFFMASK 0x1fff         /* mask for fragmenting bits */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                /* checksum */
    struct in_addr ip_src,ip_dst;  /* source and dest address */
};


/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

unsigned short in_cksum(unsigned short *paddress, int len);

void send_raw_ip_packet(struct ipheader* ip)
{

    struct sockaddr_in dest_info;
    int enable = 1;
    
    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;

    dest_info.sin_addr = ip->ip_dst;//ip->iph_destip;
    printf("sending packet... \n");
    // Step 4: Send the packet out.
    int sent = sendto(sock, ip, ntohs(ip->ip_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    if(sent <= 0)
    {
    printf("error!!\n");
    printf("socket() failed with error: %d\n", errno);
    }
    printf("send = %d\n", sent);
    close(sock);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  //pointers
  struct ipheader * got_packet_ip_header = (struct ipheader *)(packet+ 14); 
  struct icmpheader *icmp = (struct icmpheader *) (packet + 14 + sizeof(struct ipheader));
  //only icmp request packet
  if(got_packet_ip_header->ip_p == IPPROTO_ICMP && icmp->icmp_type == 8)
  {

    char buffer[1500];

    memset(buffer, 0, 1500);
    struct ipheader *ip1 = (struct ipheader *) buffer;
    ip1->ip_v= 4;
    ip1->ip_hl = 5;
    ip1->ip_ttl = 20;
    //replace ip source and ip dest
    ip1->ip_dst.s_addr = got_packet_ip_header->ip_src.s_addr;
    ip1->ip_src.s_addr = got_packet_ip_header->ip_dst.s_addr;
    struct icmpheader *icmp_our = (struct icmpheader *) (buffer + sizeof(struct ipheader));
    icmp_our->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.
    // Calculate the checksum for integrity
    icmp_our->icmp_chksum = 0;
    icmp_our->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));
    icmp_our->icmp_id = icmp->icmp_id;
    icmp_our->icmp_seq = icmp->icmp_seq;
    ip1->ip_p = IPPROTO_ICMP; 
    ip1->ip_len = htons(sizeof(struct ipheader) + 
                       sizeof(struct icmpheader));
    send_raw_ip_packet (ip1);
  }
  
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  //filter only icmp
  char filter_exp[] = "icmp";
  bpf_u_int32 net;
  
  // Step 1: Open live pcap session on NIC 
  //listen to the attack id by ifconfig 
  handle = pcap_open_live("br-a39d62a9d71e", BUFSIZ, 1, 1000, errbuf); 
  
  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);  
  printf("ready to sniff\n");
  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL); 
       
  //Close the handle
  pcap_close(handle); 

  return 0;
}

// Compute checksum (RFC 1071).

unsigned short in_cksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}
