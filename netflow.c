#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <stdbool.h>
//#include <argp.h>

FILE *file;
bool file_flag = false;
//char *file = "-";
char *collector = "127.0.0.1:2055";
int active_timer = 60;
int inactive_timer = 10;
int count_size = 1024;
char errbuf[PCAP_ERRBUF_SIZE];

void parse_arguments(int args, char*argv[]){
  for(int i = 1; i < args; i+=2){
    if(!strcmp(argv[i], "-f")){
      file = fopen(argv[i+1], "r");
      file_flag = true;
      //file = argv[i+1];
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


int main(int args, char*argv[]){
  //file = fopen("udp.pcap", "r");
  //parse_arguments(args, argv);
  //char *dev;
  pcap_if_t **iface = NULL;
  printf("%s\n", pcap_lib_version());
  pcap_t *i = pcap_fopen_offline("-", errbuf);
  //pcap_t *morebu;
  //morebu = pcap_fopen_offline(file, errbuf);
  return 0;
}
