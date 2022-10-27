#include <iostream>
#include <pcap/pcap.h>
using namespace std;

string file = "STDIN";
string collector = "127.0.0.1:2055";
int active_timer = 60;
int inactive_timer = 10;
int count_size = 1024;

void parse_arguments(int args, char*argv[]){
  for(int i = 1; i < args; i+=2){
    cout << argv[i] << endl;
    if(string(argv[i]) == "-f"){
        file = string(argv[i+1]);
    }else if(string(argv[i]) == "-c"){
        collector = string(argv[i+1]);
    }else if(string(argv[i]) == "-a"){
        active_timer = atoi(argv[i+1]);
    }else if(string(argv[i]) == "-i"){
        inactive_timer = atoi(argv[i+1]);
    }else if(string(argv[i]) == "-m"){
        count_size = atoi(argv[i+1]);
    }
  }
}

int main(int args, char*argv[]){
  parse_arguments(args, argv);
  pcap/pcap.h::pcap_create();
  cout << file << endl;
  cout << collector << endl;
  cout << active_timer << endl;
  cout << inactive_timer << endl;
  cout << count_size << endl;
  return 0;
}
