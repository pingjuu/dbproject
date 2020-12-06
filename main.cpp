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

bool ARPcontroler = true;
bool packetcontroler = true;

char* server = "localhost";
char* username = "mp";
char* password = "123";
char* db = "dbinfosec";
SVECTOR scontrol_ip;  //제어 목록
VECTOR control_ip;
MAP control_mac;    //제어할 ip의 mac주소

std::thread t1;
std::thread t2;
std::thread t3;

void usage() {
    printf("syntax: pcap-test <control ip 1> < ... > <control MB>\n");
    printf("sample: pcap-test 192.168.0.3 192.168.0.5 1\n");
}

int main(int argc, char* argv[]) {
    //DB connection
    /*
    sql::Driver *driver;
    sql::Connection *con;
    sql::PreparedStatement *pstmt;
    sql::ResultSet *result;
    */
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;

    if(!(conn = mysql_init((MYSQL*)NULL))){        //초기화 함수
        printf("init fail\n");
        return -1;
    }
    printf("mysql_init sucsess.\n");

    if(!mysql_real_connect(conn, server, username, password, db, 8000, NULL, 0)){
        printf("connect error.\n");     //DB접속 (MYSQL*, host, id, pw, null, port, 0)
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
    for(int i=0; i<ip_count; i++){
        scontrol_ip.push_back(argv[i+1]);

    }
    //printf("control_ip size : %d",scontrol_ip.size() );
    for(it = scontrol_ip.begin(); it!=scontrol_ip.end(); it++){
        std::cout<<"control ip ! : "<<*it<<std::endl;
    }
    //printf("scontrol_ip size : %d\n",scontrol_ip.size() );
    //printf("control_ip size : %d\n",control_ip.size() );
    for(it = scontrol_ip.begin(); it!=scontrol_ip.end(); it++){
        control_ip.push_back(Ip(*it));
    }
    //printf("control_ip size : %d",control_ip.size() );
    //printf("ok \n");
    VECTOR::iterator iter;
    //printf("ok \n");
    for(iter = control_ip.begin(); iter!=control_ip.end(); iter++){
        std::cout<<"control ip ! : "<<Ip(*iter)<<std::endl;

    }


    //pcap_open_live로 나중에 바꿀거임
    //const char* fname = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    //pcap_t* handle = pcap_open_offline(fname, errbuf);

    pcap_t* handle =pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live eth0 return nullptr - %s\n", errbuf);
        return -1;
    }
    
    forMAC_ARPreq(handle);  //네트워크 상에 arp requst보내기
    printf("main : arp request ok\n");
    int reply_count = 0;
    printf("main : control ip : %d", control_ip.size());
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
                reply_count++;
                control_mac.insert(std::make_pair(ntohl(reply_packet.arp_.sip_), reply_packet.arp_.smac_));
                //break;
                }
            }
        printf("main : arp reply reeeeeeeady\n");
        //sleep(1);
    }
    printf("control mac size :  %d \n", control_mac.size());
    printf("main : thread 2 begin\n");
    t2=std::thread(sendARP, handle);
    printf("thread 3 begin\n");
    t3=std::thread(time_check, conn, ctrl_bytes, handle); //flow와 독립적으로 이루어져야 하기 때문에 스레드 처리하기


    while(packetcontroler){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        //printf("main : thread 1 begin\n");
        t1=std::thread(packetProcess, ctrl_bytes, packet, header);
        t1.join();
    }



    pcap_close(handle);
    
    //t1.join();
    t2.join();
    t3.join();

    mysql_close(conn);
    system("pause");
    return 0;
}

