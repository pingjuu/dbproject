#pragma once

#include <stdint.h>
#include <vector>
#include <pcap.h>
#include <string>
#include <arpa/inet.h>
#include <map>
#include <arpa/inet.h>
#include "headers.h"
#include "ip.h"

#define VECTOR std::vector<uint32_t>
#define FLOW_MAP std::map<flowInfo, flowContent>

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

extern bool packetcontroler;

class flowInfo{
private:
    uint32_t address;
public:
    flowInfo();
    uint32_t _address();
    void flowinsert(uint32_t ipPacket);
    bool operator<(const flowInfo flow) const;
    bool operator==(const flowInfo flow) const;
};

class flowContent{
private:
    bpf_u_int32 bytes;
    bool network;

public:
    flowContent();
    ~flowContent();
    bpf_u_int32 _bytes();
    void flowAdd(bpf_u_int32 bytes);
    bool bytes_ToCompare(uint32_t ctrl_bytes);
    void bytes_initial();
};


void network_stop();
uint32_t address_ToCompare(const u_char* packet);
void flow(const u_char* packet, struct pcap_pkthdr* header, int ctrl_bytes);
int packetProcess(int ctrl_bytes, const u_char* packet, struct pcap_pkthdr* header);
