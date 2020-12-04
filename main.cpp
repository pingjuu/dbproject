#pragma once

#include <iostream>
#include <string>
#include <pcap.h>
#include <map>
#include <vector>
#include <cstring>
#include <thread>
#include "ip.h"

#include "initial.h"
//#include "network.h"
#define VECTOR std::vector<uint32_t>
#define MAP std::map<Ip, Mac>

bool ARPcontroler = true;
bool packetcontroler = true;

char* server = "localhost";
char* username = "root";
char* password = "123";
char* db = "databases";
VECTOR control_ip;  //제어 목록
MAP control_mac;    //제어할 ip의 mac주소

std::thread t1;
std::thread t2;
std::thread t3;

void usage() {
    printf("syntax: pcap-test <packetfile.pcap> <control ip 1> < ... > <control MB>\n");
    printf("sample: pcap-test gilgil.pcap 192.168.0.3 192.168.0.5 1\n");
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

    if(!mysql_real_connect(conn, server, username, password, db, 3306, NULL, 0)){
        printf("connect error.\n");     //DB접속 (MYSQL*, host, id, pw, null, port, 0)
        return -1;
    }
    printf("mysql_real_connect suc.\n");

    /*try
    {
        driver = get_driver_instance();
        //for demonstration only. never save password in the code!
        con = driver->connect(server, username, password);
    }
    catch (sql::SQLException e)
    {
        cout << "Could not connect to server. Error message: " << e.what() << endl;
        system("pause");
        exit(1);
    }
    
    con->setSchema("quickstartdb");

    */


    if (argc < 3) {
        usage();
        return -1;
    }
    // ip db에서 가져오기 
    int ctrl_bytes = std::stoi(argv[argc-1]) * 1000000;
    const int ip_count = argc-3;

    for(int i=0; i<ip_count; i++)
        control_ip.push_back(Ip(argv[i+2]));
    

    //pcap_open_live로 나중에 바꿀거임
    const char* fname = argv[1];
    printf("file name : %s\n",fname);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(fname, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) return nullptr - %s\n", fname, errbuf);
        return -1;
    }
    
    forMAC_ARPreq(handle);  //네트워크 상에 arp requst보내기
    int reply_count = 0;

    while(reply_count<control_ip.size()){    //request받은거에 대한 arp reply 받는 작업
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
                printf("arp reply!!!\n");
                reply_count++;
                control_mac.insert(std::make_pair(reply_packet.arp_.sip_, reply_packet.arp_.smac_));
                break;
                }
            }
        sleep(1);
    }

    t1=std::thread(packetProcess, fname, ctrl_bytes, handle);
    t2=std::thread(sendARP, handle);
    t3=std::thread(time_check, conn, fname, ctrl_bytes, handle); //flow와 독립적으로 이루어져야 하기 때문에 스레드 처리하기
    pcap_close(handle);
    
    t1.join();
    t2.join();
    t3.join();

    mysql_close(conn);
    system("pause");
    return 0;
}

