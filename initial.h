#pragma once

#include <iostream>
//#include <map>
//#include <vector>
#include <chrono>
#include <thread>
#include <time.h>
#include <stdlib.h>
#include <string>
#include "network.h"
#include "ip.h"
#include "/usr/include/mariadb/mysql.h"

//#define VECTOR std::vector<uint32_t>
//#define FLOW_MAP std::map<flowInfo, flowContent>

extern bool ARPcontroler;
extern bool packetcontroler;
extern std::thread t1;
extern std::thread t2;
extern std::thread t3;

void time_check(MYSQL *conn, int ctrl_bytes, pcap_t* handle);
//void time_check(MYSQL *conn);
void dbupdate(MYSQL *conn);

