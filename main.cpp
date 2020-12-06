#pragma once

#include <iostream>
#include <string>
#include <pcap.h>
#include <map>
#include <vector>
#include <cstring>
//#include <thread>
#include "ip.h"
#include <arpa/inet.h>
#include "initial.h"
//#include "network.h"
#define VECTOR std::vector<uint32_t>
#define SVECTOR std::vector<std::string>
#define MAP std::map<Ip, Mac>
SVECTOR scontrol_ip;  //제어 목록 type string
VECTOR control_ip;    //제어 목록 type uint32_t
MAP control_mac;    //제어할 ip의 mac주소

bool ARPcontroler = true;
bool packetcontroler = true;

char* server = "localhost";
char* username = "mp";
char* password = "123";
char* db = "dbinfosec";

std::thread t1;
std::thread t2;
std::thread t3;

void usage() {
    printf("syntax: pcap-test <control ip 1> < ... > <control MB>\n");
    printf("sample: pcap-test 192.168.0.3 192.168.0.5 1\n");
}

int main(int argc, char* argv[]) {
    //for DB connection
    
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;

    if(!(conn = mysql_init((MYSQL*)NULL))){        //초기화 함수
        printf("init fail\n");
        return -1;
    }
    printf("mysql_init sucsess.\n");

    if(!mysql_real_connect(conn, server, username, password, db, 8000, NULL, 0)){
        printf("connect error.\n");     //DB접속 (MYSQL*, host, id, pw, database name, port, null, 0)
        return -1;
    }
    printf("mysql_real_connect suc.\n");


    if (argc < 3) {
        usage();
        return -1;
    }
    // ip db에서 가져오기 
    int ctrl_bytes = std::stoi(argv[argc-1]) * 1000000;
    const int ip_count = argc-2;
    SVECTOR::iterator it;
    for(int i=0; i<ip_count; i++)
        scontrol_ip.push_back(argv[i+1]);

    for(it = scontrol_ip.begin(); it!=scontrol_ip.end(); it++)
        control_ip.push_back(Ip(*it));

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle =pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live eth0 return nullptr - %s\n", errbuf);
        return -1;
    }
    
    forMAC_ARPreq(handle);  //네트워크 상에 arp requst보내기
    int reply_count = 0;//controlled ip해당 reply 받은 개수 
    while(reply_count<control_ip.size()){    //request받은거에 대한 arp reply 받는 작업
        printf("main : arp reply ready\n");
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        EthArpPacket reply_packet= *(EthArpPacket*)packet;
        if (reply_packet.eth_.type_ == htons(EthHdr::Arp)){
            if(reply_packet.arp_.op_== htons(ArpHdr::Reply)){
                //arp request가 control ip 꺼인건지 확인해야함(문제 되었을 때 하기)
                printf("main : arp reply!!!\n");
                reply_count++;  //controlled ip 개수 만큼 받기 위함
                control_mac.insert(std::make_pair(ntohl(reply_packet.arp_.sip_), reply_packet.arp_.smac_));
                }
            }
        printf("main : arp reply reeeeeeeady\n");
    }
    //flow와 독립적으로 이루어져야 하기 때문에 스레드 처리하기
    t2=std::thread(sendARP, handle);
    t3=std::thread(time_check, conn, ctrl_bytes, handle); 

    while(packetcontroler){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        //printf("main : thread 1 begin\n");
        t1=std::thread(packetProcess, ctrl_bytes, packet, header);
        t1.join();
    }

    pcap_close(handle);
    
    t2.join();
    t3.join();

    mysql_close(conn);
    system("pause");
    return 0;
}

