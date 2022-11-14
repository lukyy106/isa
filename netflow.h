#define __FAVOR_BDS
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
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>




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

struct complete_flow{
  struct NF5_header header;
  struct NF5_flow flow;
};


struct list_s{
  struct list_s *next;
  struct list_s *prev;
  struct complete_flow c_flow;
  time_t last_change;
  bool filled;
};
