#pragma once

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <chrono>
#include <thread>
#include <sys/types.h>
#include <net/if.h>
#include <unistd.h>
#include <map>
#include "flow.h"
#include "ethhdr.h"
#include "arphdr.h"

#define VECTOR std::vector<uint32_t>
#define MAP std::map<Ip, Mac>

struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};


int getMy_Ip(char *my_ip);  // 라파 ip 가져오기
void forMAC_ARPreq(pcap_t* handle);
int getMacAddress(uint8_t *mac);
void sendARP(pcap_t* handle);
extern bool ARPcontroler;