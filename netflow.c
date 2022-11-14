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
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>
#include "netflow.h"
//#include "udp_client.c"




//#include <argp.h>

FILE *file;
bool file_flag = false;
char *collector_addr = "127.0.0.1";
char *port = "2055";
unsigned int active_timer = 60;
unsigned int inactive_timer = 10;
int count_size = 1024;
int flow_counter = 0;
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
struct toto_posli *morebu;
int sock;
struct sockaddr_in server;
struct hostent *servent;
socklen_t len;

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
      if(strchr(argv[i+1], ':') != NULL){
        char* input = ":";
        collector_addr = strtok(argv[i+1], input);
        port = strtok(NULL, ":");
      }else{
        collector_addr = argv[i+1];
      }

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

void new_packet(time_t time_s, suseconds_t time_us, u_short source_port, u_short dst_port, u_int8_t tos, unsigned long source_addr, unsigned long dst_addr, struct list_s *list_2, unsigned int packet_lengh){

  //printf("source_addr :: %ld\n", source_addr);
  //printf("dst_addr :: %ld\n", dst_addr);
  //printf("tos :: %d\n", tos);
  //printf("source_port :: %d\n", source_port);
  //printf("dst_port :: %d\n", dst_port);
  //printf("lengh :: %d\n", packet_lengh);
  //printf("########################################################\n" );
  struct list_s *prev = list_2;
  while(list_2 != NULL){
    /*printf("protocol %d == %d\n", protocol, list_2->c_flow.flow.protocol);
    printf("source_port %d == %d\n", source_port, list_2->c_flow.flow.src_port);
    printf("dst_port %hu == %d\n", dst_port, list_2->c_flow.flow.dest_port);
    printf("tos %d == %d\n", tos, list_2->c_flow.flow.tos);
    printf("source_addr %lu == %d\n", source_addr, list_2->c_flow.flow.src_ip);
    printf("dst_addr %lu == %d\n", dst_addr, list_2->c_flow.flow.dest_ip);*/
    if(!list_2->filled){
      break;
    }

    if(protocol == list_2->c_flow.flow.protocol){
      if(source_port == list_2->c_flow.flow.src_port){
        if(dst_port == list_2->c_flow.flow.dest_port){
          if(tos == list_2->c_flow.flow.tos){
            if(source_addr == list_2->c_flow.flow.src_ip){
              if(dst_addr == list_2->c_flow.flow.dest_ip){
                list_2->c_flow.flow.flow_packets += htonl(1);
                list_2->c_flow.flow.flow_finish = time_s;
                list_2->c_flow.header.uptime_ms = time_s;
                list_2->c_flow.flow.flow_octets += htonl(packet_lengh);
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
  flow_counter++;
  while(prev->next != NULL){
    prev = prev->next;
  }
  if(list_2 == NULL){
    printf("maloooooooooooooooc\n" );
    list_2 = malloc(sizeof(struct list_s));
    list_2->prev = prev;
    list_2->prev->next = list_2;
  }

  list_2->c_flow.header.version = htons(5);
  list_2->c_flow.header.count = htons(1);
  list_2->c_flow.header.uptime_ms = time_s;
  list_2->c_flow.header.time_sec = time_s;
  list_2->c_flow.header.time_nanosec = htonl(htonl(time_us) * 1000);
  list_2->c_flow.header.engine_type = 0;
  list_2->c_flow.header.engine_id = 0;
  list_2->c_flow.header.sampling_interval = 0;
  list_2->c_flow.flow.src_ip = source_addr;
  list_2->c_flow.flow.dest_ip = dst_addr;
  list_2->c_flow.flow.nexthop_ip = 0;
  list_2->c_flow.flow.if_index_in = 0;
  list_2->c_flow.flow.if_index_out = 0;
  list_2->c_flow.flow.flow_packets = htonl(1);
  list_2->c_flow.flow.flow_octets = htonl(packet_lengh);
  list_2->c_flow.flow.flow_start = time_s;
  list_2->c_flow.flow.flow_finish = time_s;
  list_2->c_flow.flow.src_port = source_port;
  list_2->c_flow.flow.dest_port = dst_port;
  list_2->c_flow.flow.pad1 = 0;
  list_2->c_flow.flow.tcp_flags = 0;
  list_2->c_flow.flow.protocol = protocol;
  list_2->c_flow.flow.tos = tos;
  list_2->c_flow.flow.src_as = 0;
  list_2->c_flow.flow.dest_as = 0;
  list_2->c_flow.flow.src_mask = 0;
  list_2->c_flow.flow.dst_mask = 0;
  list_2->c_flow.flow.pad2 = 0;
  list_2->filled = 1;
  list_2->next = NULL;



}

void export(struct list_s *list_2){
  flow_counter--;
  struct list_s *next = list_2->next;
  struct list_s *prev = list_2->prev;
  int i = send(sock,&list_2->c_flow,sizeof(struct complete_flow),0);     // send data to the server
  if (i == -1)                   // check if data was sent correctly
    err(1,"send() failed");
  if(next != NULL){
    next->prev = prev;
  }
  if(prev != NULL){
    prev->next = next;
  }
  if(list_2 == list){
    list = list_2->next;
  }
  free(list_2);

}


void timer(struct list_s *list_2, time_t time){
  while(list_2 != NULL){
    if(!list_2->filled)
      return;
      //printf("porovnanvam %d a %u\n",htonl(list_2->c_flow.flow.flow_start), htonl(time) );
    if(htonl(time) - htonl(list_2->c_flow.flow.flow_start) >= active_timer || time - htonl(list_2->c_flow.flow.flow_finish) - htonl(time) >= inactive_timer){
      export(list_2);
      list_2 = list;
      continue;
    }
    list_2 = list_2->next;
  }

}


int main(int args, char*argv[]){
  int app = 0;
  parse_arguments(args, argv);
  pcap_t *handle;
  list = malloc(sizeof(struct list_s));
  list->next = NULL;
  list->prev = NULL;
  list->filled = 0;
  memset(&server,0,sizeof(server));
  server.sin_family = AF_INET;
  if ((servent = gethostbyname(collector_addr)) == NULL) // check the first parameter
    errx(1,"gethostbyname() failed\n");
  memcpy(&server.sin_addr,servent->h_addr,servent->h_length);
  server.sin_port = htons(atoi(port));
  if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
    err(1,"socket() failed\n");
  printf("* Server socket created\n");
  if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
    err(1, "connect() failed");

  if(file_flag){
    handle = pcap_fopen_offline(file, errbuf);
  }else{
    handle = pcap_open_offline("-", errbuf);
  }
  while(1){
    packet = pcap_next(handle, &header);



    if(packet == NULL)
      break;

    timer(list, htonl(header.ts.tv_sec));

    if(list == NULL){
      list = malloc(sizeof(struct list_s));
      list->next = NULL;
      list->prev = NULL;
      list->filled = 0;
    }
    initialize_values();



    if(htons(eth_h->ether_type) != ETHERTYPE_IP) // not en IP packet
      continue;


    if(protocol == IPPROTO_TCP){
      //printf("TCP protocol\n");
      tcp_h = (struct tcphdr*)(packet + ETHERNET_HEADER_LENGH + ip_h->ip_hl * 4);
      //unsigned int header_lengh = 0;
      //printf("port ::  %d\n", htons(tcp_h->th_sport));
      new_packet(htonl(header.ts.tv_sec), htonl(header.ts.tv_usec), tcp_h->th_sport, tcp_h->th_dport, htons(ip_h->ip_tos), ip_h->ip_src.s_addr, ip_h->ip_dst.s_addr, list, htons(ip_h->ip_len));
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
      printf("dlzka    %d\n", htons(ip_h->ip_len));
      new_packet(htonl(header.ts.tv_sec), htonl(header.ts.tv_usec), udp_h->uh_sport, udp_h->uh_dport, htons(ip_h->ip_tos), ip_h->ip_src.s_addr, ip_h->ip_dst.s_addr, list, htons(ip_h->ip_len));
    }

    if(protocol == IPPROTO_ICMP){
      icmp_h = (struct icmphdr*)(packet + ETHERNET_HEADER_LENGH + ip_h->ip_hl * 4);
      printf("seKUNDY %u\n", htonl(header.ts.tv_usec));
      new_packet(htonl(header.ts.tv_sec), htonl(header.ts.tv_usec), 0, 0, htons(ip_h->ip_tos), ip_h->ip_src.s_addr, ip_h->ip_dst.s_addr, list, htons(ip_h->ip_len));

    }

    if(flow_counter == count_size){
      export(list);
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

  if(file_flag){
    fclose(file);
  }
  pcap_close(handle);


  while(list != NULL){
    void *next = list->next;
    int i = send(sock,&list->c_flow,sizeof(struct complete_flow),0);     // send data to the server
    if (i == -1)                   // check if data was sent correctly
      err(1,"send() failed");
    free(list);
    list = next;
  }

  close(sock);

  return 0;
}
