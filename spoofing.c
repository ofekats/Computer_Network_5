#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <time.h>
#include <pcap/pcap.h>

/* UDP Header */
struct udpheader
{
  u_int16_t udp_sport;           /* source port */
  u_int16_t udp_dport;           /* destination port */
  u_int16_t udp_ulen;            /* udp length */
  u_int16_t udp_sum;             /* udp checksum */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4,  // IP header length
                     iph_ver:4;  // IP version (usually 4)
  unsigned char      iph_tos;    // Type of service
  unsigned short int iph_len;    // IP Packet length (data + header)
  unsigned short int iph_ident;  // Identification
  unsigned short int iph_flag:3, // Fragmentation flags
                     iph_offset:13; // Flags offset
  unsigned char      iph_ttl;    // Time to Live
  unsigned char      iph_protocol; // Protocol type (usually 1 for ICMP)
  unsigned short int iph_chksum; // IP datagram checksum
  struct  in_addr    iph_sourceip; // Source IP address 
  struct  in_addr    iph_destip;   // Destination IP address 
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
    dest_info.sin_addr = ip->iph_destip;
    printf("sending packet... %d, %ld\n", ntohs(ip->iph_len), sizeof(dest_info));
    // Step 4: Send the packet out.
    int sent = sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    if(sent <= 0)
    {
    printf("error!!\n");
    printf("socket() failed with error: %d\n", errno);
    }
    printf("send = %d\n", sent);
    close(sock);
}

//icmp
void icmp(char * buffer, struct ipheader *ip)
{

  struct icmpheader *icmp = (struct icmpheader *) (buffer + sizeof(struct ipheader));
  icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

  // Calculate the checksum for integrity
  icmp->icmp_chksum = 0;
  icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));
  ip->iph_protocol = IPPROTO_ICMP; 
  ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
  send_raw_ip_packet (ip);
}

//udp
void udp(char * buffer, struct ipheader *ip)
{

  struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
  char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader);
  const char *msg = "Hello Server!\n";
  int data_len = strlen(msg);
  strncpy (data, msg, data_len);
  udp->udp_sport = htons(12345);
  udp->udp_dport = htons(9090);
  udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
  udp->udp_sum =  0; /* Many OSes ignore this field, so we do not calculate it. */
  ip->iph_protocol = IPPROTO_UDP; // The value is 17.
  ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader) + data_len);
  send_raw_ip_packet (ip);
}

//tcp
void tcp(char * buffer, struct ipheader *ip)
{
  struct tcphdr * tcp = (struct tcphdr *) (buffer + sizeof(struct ipheader));
  char *data = buffer + sizeof(struct ipheader) + ((tcp->doff)* 4);
  const char *msg = "Hello Server!\n";
  int data_len = strlen(msg);
  strncpy (data, msg, data_len);
  tcp->source = htons(12345);
  tcp->dest = htons(9090);
  tcp->seq = 1;
  tcp->ack_seq = 0;
  ip->iph_protocol = IPPROTO_TCP;
  ip->iph_len = htons(sizeof(struct ipheader) + ((tcp->doff)* 4) + data_len);
  tcp->check =0;
  send_raw_ip_packet (ip);
  

}

int main() {

  char buffer[1500];

  memset(buffer, 0, 1500);
  struct ipheader *ip = (struct ipheader *) buffer;
  ip->iph_ver = 4;
  ip->iph_ihl = 5;
  ip->iph_ttl = 20;
  ip->iph_sourceip.s_addr = inet_addr("8.8.8.8");
  ip->iph_destip.s_addr = inet_addr("10.0.2.15");
  

  //icmp
  icmp(buffer,ip);
  
  //udp
  //udp(buffer,ip);
  
  //tcp
  //tcp(buffer, ip);
  
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
