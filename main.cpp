#pragma once

#include <iostream>
#include <string>
#include <pcap.h>
#include <map>
#include <vector>
#include <cstring>
#include "ip.h"
#include <arpa/inet.h>
#include "initial.h"
#define VECTOR std::vector<uint32_t>
#define SVECTOR std::vector<std::string>
#define MAP std::map<Ip, Mac>
SVECTOR scontrol_ip;  //제어 목록 type string
VECTOR control_ip;    //제어 목록 type uint32_t
MAP control_mac;    //제어할 ip의 mac주소

bool ARPcontroler = true;
bool packetcontroler = true;

char* server = "localhost";     //db connection을 위한 db정보
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
    int ctrl_bytes = std::stoi(argv[argc-1]) * 1000000;     //MB -> Byte
    const int ip_count = argc-2;
    SVECTOR::iterator it;
    for(int i=0; i<ip_count; i++)                //string으로 받아온 ip vector
        scontrol_ip.push_back(argv[i+1]);

    for(it = scontrol_ip.begin(); it!=scontrol_ip.end(); it++)  //string-> uint32_t
        control_ip.push_back(Ip(*it));

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle =pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf); //packet capture를 위한 pcap open
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live eth0 return nullptr - %s\n", errbuf);
        return -1;
    }
    
    forMAC_ARPreq(handle);      // mac 주소를 얻기위해 네트워크 상에 arp requst보내기
    int reply_count = 0;        //controlled ip 대한 reply 받은 개수 
    while(reply_count<control_ip.size()){    //request 보낸 것에 대한 arp reply 받는 작업
        printf("main : arp reply ready\n");
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);       // 흘러들어오는 패킷 하나씩 받아오기
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        EthArpPacket reply_packet= *(EthArpPacket*)packet;
        if (reply_packet.eth_.type_ == htons(EthHdr::Arp)){ 
            if(reply_packet.arp_.op_== htons(ArpHdr::Reply)){       // 들어온 패킷이 arp reply인경우
                printf("main : arp reply!!!\n");
                reply_count++;  //받아온 arp reply 개수
                control_mac.insert(std::make_pair(ntohl(reply_packet.arp_.sip_), reply_packet.arp_.smac_));  //해당 ip와 mac주소 저장
            }
        }
        printf("main : arp reply reeeeeeeady\n");
    }
    //flow와 독립적으로 이루어져야 하기 때문에 스레드 처리하기
    t2=std::thread(sendARP, handle);     //controlled ip의 데이터 누적량이 ctrl byte를 초과할 경우 arp redirection
    t3=std::thread(time_check, conn, ctrl_bytes, handle);   //주기적으로 시간 check 해서 날짜가 바뀔경우 초기화

    while(packetcontroler){ //packetcontroler가 true일경우만 thread1 돌리기
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        //printf("main : thread 1 begin\n");
        t1=std::thread(packetProcess, ctrl_bytes, packet, header);
        t1.join();
    }
    //프로그램 종료 준비
    pcap_close(handle);
    
    t2.join();
    t3.join();

    mysql_close(conn);
    system("pause");
    return 0;
}

