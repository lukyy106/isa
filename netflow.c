#define __FAVOR_BDS
typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;
#define ETHERNET_HEADER_LENGH 14
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
//#include <netinet/icmp.h>
#include <arpa/inet.h>
#include<unistd.h>


struct data_s{
  struct data_s *next;
  u_int len;
  char *data;
};

struct flow_s{
  u_int packets;
  time_t time;
  time_t last_chng;
  u_char protocol;
  u_short source_port;
  u_short dst_port;
  u_int8_t tos;
  unsigned long source_addr;
  unsigned long dst_addr;
  struct data_s *data;
};


struct list_s{
  struct list_s *next;
  struct list_s *prev;
  struct flow_s flow;
};

struct NF5_header{
  u_int16_t version, count;
  u_int32_t uptime_ms, time_sec, time_nanosec;
  u_int32_t flow_sequence;
  u_int8_t engine_type, engine_id;
  u_int16_t sampling_interval;
};

struct NF5_flow{
  u_int32_t src_ip, dest_ip, nexthop_ip;
  u_int16_t if_index_in, if_index_out;
  u_int32_t flow_packets, flow_octets;
  u_int32_t flow_start, flow_finish;
  u_int16_t src_port, dest_port;
  u_int8_t pad1;
  u_int8_t tcp_flags, protocol, tos;
  u_int16_t src_as, dest_as;
  u_int8_t src_mask, dst_mask;
  u_int16_t pad2;
};

struct toto_posli{
  struct NF5_header header;
  struct NF5_flow flow;
};

//#include <argp.h>

FILE *file;
bool file_flag = false;
char *collector = "127.0.0.1:2055";
int active_timer = 60;
int inactive_timer = 10;
int count_size = 1024;
char errbuf[PCAP_ERRBUF_SIZE];
u_char protocol;
struct list_s *list;
struct pcap_pkthdr header;
struct ether_header *eth_h;
struct ip *ip_h;
struct tcphdr *tcp_h;
struct udphdr *udp_h;
struct icmphdr *icmp_h;
const u_char *packet;
//struct NF5_header *nf_header;
//struct NF5_flow *nf_flow;
struct toto_posli *morebu;


void parse_arguments(int args, char*argv[]){
  for(int i = 1; i < args; i+=2){
    if(!strcmp(argv[i], "-f")){
      file = fopen(argv[i+1], "r");
      if(file == NULL){
        fprintf(stderr, "Can not open %s\n", argv[i+1]);
        exit(1);
      }
      file_flag = true;
    }else if(!strcmp(argv[i], "-c")){
      collector = argv[i+1];
    }else if(!strcmp(argv[i], "-a")){
      active_timer = atoi(argv[i+1]);
    }else if(!strcmp(argv[i], "-i")){
      inactive_timer = atoi(argv[i+1]);
    }else if(!strcmp(argv[i], "-m")){
      count_size = atoi(argv[i+1]);
    }
  }
}

void initialize_values(){
  eth_h = (struct ether_header *) packet;
  ip_h = (struct ip *)(packet + sizeof(struct ether_header));
  protocol = *(packet + ETHERNET_HEADER_LENGH + 9); // protocol is stored in packet as 10th byte
  tcp_h = (struct tcphdr *)(packet + ip_h->ip_hl + sizeof(struct ether_header));
}

void new_packet(time_t time, u_short source_port, u_short dst_port, u_int8_t tos, unsigned long source_addr, unsigned long dst_addr, struct list_s *list_2, unsigned int packet_lengh){
  printf("source_addr :: %ld\n", source_addr);
  printf("dst_addr :: %ld\n", dst_addr);
  printf("tos :: %d\n", tos);
  printf("source_port :: %d\n", source_port);
  printf("dst_port :: %d\n", dst_port);
  printf("lengh :: %d\n", packet_lengh);
  printf("########################################################\n" );
  while(list_2->next != NULL){
    if(protocol == list_2->flow.protocol){
      if(source_port == list_2->flow.source_port){
        if(dst_port == list_2->flow.dst_port){
          if(tos == list_2->flow.tos){
            if(source_addr == list_2->flow.source_addr){
              if(dst_addr == list_2->flow.dst_addr){
                list_2->flow.last_chng = time;
                printf("flow\n" );
                return;
              }
            }
          }
        }
      }
    }
    list_2 = list_2->next;
  }
  printf("new flow\n" );
  list_2->flow.protocol = protocol;
  list_2->flow.source_port = source_port;
  list_2->flow.dst_port = dst_port;
  list_2->flow.tos = tos;
  list_2->flow.source_addr = source_addr;
  list_2->flow.dst_addr = dst_addr;
  list_2->flow.time = time;
  list_2->next = malloc(sizeof(struct list_s));
  list_2->next->prev = list_2;

}


int main(int args, char*argv[]){
  parse_arguments(args, argv);
  pcap_t *handle;
  list = malloc(sizeof(struct list_s));
  list->next = NULL;
  list->prev = NULL;

  if(file_flag){
    handle = pcap_fopen_offline(file, errbuf);
  }else{
    handle = pcap_open_offline("-", errbuf);
  }
  while(1){
    packet = pcap_next(handle, &header);

    if(packet == NULL)
      break;

    initialize_values();



    if(htons(eth_h->ether_type) != ETHERTYPE_IP) // not en IP packet
      continue;


    if(protocol == IPPROTO_TCP){
      //printf("TCP protocol\n");
      tcp_h = (struct tcphdr*)(packet + ETHERNET_HEADER_LENGH + ip_h->ip_hl * 4);
      //unsigned int header_lengh = 0;
      //printf("port ::  %d\n", htons(tcp_h->th_sport));
      new_packet(header.ts.tv_sec, htons(tcp_h->th_sport), htons(tcp_h->th_dport), ip_h->ip_tos, ip_h->ip_src.s_addr, ip_h->ip_dst.s_addr, list, htons(ip_h->ip_len));
    }
    if(protocol == IPPROTO_UDP){
      //printf("UDP protocol\n");

      udp_h = (struct udphdr*)(packet + ETHERNET_HEADER_LENGH + ip_h->ip_hl * 4);
      //printf("ip hl = %lu\n", sizeof(*ip_h));
      //printf("udp hl = %lu\n", sizeof(*udp_h));
      //printf("eth hl = %lu\n", sizeof(*eth_h));
      //unsigned int header_lengh = sizeof(*ip_h) + sizeof(*udp_h) + sizeof(*eth_h);
      //printf("protocol ::  %d\n", protocol);
      //printf("hlava ::  %d\n", ip_h->ip_hl);
      //printf("port ::  %d\n", htons(udp_h->uh_sport));
      new_packet(header.ts.tv_sec, htons(udp_h->uh_sport), htons(udp_h->uh_dport), ip_h->ip_tos, ip_h->ip_src.s_addr, ip_h->ip_dst.s_addr, list, htons(ip_h->ip_len));
    }

    if(protocol == IPPROTO_ICMP){
      icmp_h = (struct icmphdr*)(packet + ETHERNET_HEADER_LENGH + ip_h->ip_hl * 4);
      new_packet(header.ts.tv_sec, 0, 0, ip_h->ip_tos, ip_h->ip_src.s_addr, ip_h->ip_dst.s_addr, list, htons(ip_h->ip_len));
    }



    //for(bpf_u_int32 loop = 0; loop < header.len; loop++)
    //    printf("%c", packet[loop]);

    //printf("\nJacked a packet with length of [%d]\n", header.len);
    //printf("Jacked a packet with captured length of [%d]\n", header.caplen);
    //printf("time [%ld]\n", header.ts.tv_sec);
    //printf("eth type [%d]\n", eth_h->ether_type);
    //printf("src addr [%uld]\n", ip_h->ip_src.s_addr);

    //unsigned char bytes[4];
    //bytes[0] = ip_h->ip_src.s_addr & 0xFF;
    //bytes[1] = (ip_h->ip_src.s_addr >> 8) & 0xFF;
    //bytes[2] = (ip_h->ip_src.s_addr >> 16) & 0xFF;
    //bytes[3] = (ip_h->ip_src.s_addr >> 24) & 0xFF;
    //printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);

    //printf("dst addr [%uld]\n", ip_h->ip_dst.s_addr);
  }
  while(list->next != NULL){
    list = list->next;
    printf("1\n" );
  }

  if(file_flag){
    fclose(file);
  }
  pcap_close(handle);

  free(list);
  int sock;
  struct sockaddr_in server;
  memset(&server,0,sizeof(server)); // erase the server structure
  server.sin_family = AF_INET;
  server.sin_port = 2055;
  server.sin_addr.s_addr = 2130706433;
  if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
      printf("errorororororoororor1234\n");
  if(connect(sock, (struct sockaddr *)&server, sizeof(server)) == -1){
    printf("errorororororoororor\n");
  }
  morebu = malloc(sizeof(struct NF5_header)+sizeof(struct NF5_flow));

  morebu->header.version = 5;
  morebu->header.count = 1;
  morebu->header.uptime_ms = 0;
  morebu->header.time_sec = 0;
  morebu->header.time_nanosec = 0;
  morebu->header.flow_sequence = 0;
  morebu->header.engine_type = 0;
  morebu->header.engine_id = 0;
  morebu->header.sampling_interval = 0;


  morebu->flow.src_ip = 2130706433;
  morebu->flow.dest_ip = 2130706434;
  morebu->flow.nexthop_ip = 0;
  morebu->flow.if_index_in = 0;
  morebu->flow.if_index_out = 0;
  morebu->flow.flow_packets = 0;
  morebu->flow.flow_octets = 0;
  morebu->flow.flow_start = 0;
  morebu->flow.flow_finish = 0;
  morebu->flow.pad1 = 0;
  morebu->flow.tcp_flags = 0;
  morebu->flow.protocol = 0;
  morebu->flow.tos = 0;
  morebu->flow.src_as = 0;
  morebu->flow.dest_as = 0;
  morebu->flow.src_mask = 0;
  morebu->flow.dst_mask = 0;
  morebu->flow.pad2 = 0;

  int i = write(sock, morebu, 72);
  if(i == -1){
    printf("chybicka\n");
  }


  close(sock);
  free(morebu);

  //printf("Date first seen          Event  XEvent Proto      Src IP Addr:Port          Dst IP Addr:Port     X-Src IP Addr:Port        X-Dst IP Addr:Port   In Byte Out Byte\n");

  return 0;
}
