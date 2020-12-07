#include "flow.h"

FLOW_MAP ipmap;         //받아온 인자 넣은 것
VECTOR control_vector(1,0);  //데이터 량을 초과하여 네트워크를 제한할 ip가 들어있는 vector
extern VECTOR control_ip;

flowInfo::flowInfo(){};
void flowInfo::flowinsert(uint32_t insertIP){
    this->address = insertIP;
}

bool flowInfo::operator==(const flowInfo flow) const{
    return (this->address == flow.address);
}
bool flowInfo::operator<(const flowInfo flow) const{
    return this->address < flow.address;
}
u_int32_t flowInfo::_address(){return this->address;}

flowContent::flowContent(){
    this->bytes = 0;
    this->network = false;
}
flowContent::~flowContent(){};

void flowContent::flowAdd(bpf_u_int32 bytes){
    this->bytes += bytes;
}
bpf_u_int32 flowContent::_bytes(){return bytes;}

bool flowContent::bytes_ToCompare(uint32_t ctrl_bytes){
    if(ctrl_bytes<=this->bytes)    //참일경우 네트워크 제한
        this->network = true;                           //네트워크 제한
        //arpredirect
    return this->network;
}
void flowContent::bytes_initial(){
    this->bytes = 0;
    this->network = false;
}

void flow(const u_char* packet, struct pcap_pkthdr* header, int ctrl_bytes){
    
    uint32_t insertIP = address_ToCompare(packet);  // 들어온 패킷의 ip와 제어할 ip 비교
    if(insertIP != -1){      // 들어온 패킷의 ip와 제어할 ip가 일치하는 경우

        flowInfo f;
        f.flowinsert(ntohl(insertIP));
        FLOW_MAP::iterator iter= ipmap.find(f);
        if(iter == ipmap.end()){   // ipmap에 없으면 (즉 받아오는 패킷이 첫 control ip의 패킷이면 ipmap에 넣기)
            flowContent content;
            ipmap.insert(std::make_pair(f, content));
            iter=ipmap.find(f);
        }

        flowInfo add = iter->first;
        uint32_t a = add._address();
            //지정해둔 제한 데이터량 비교
        if(iter->second.bytes_ToCompare(ctrl_bytes)){   //ctrl bytes 초과할 경우 
            printf("control _ vector PUSH!!!\n");       //해당 ip를 control vector에 넣는다
            control_vector.push_back(a);
        }//TRUE일경우 네트워크 제한
        else{                                           //아닐경우 ip의 해당 데이터 누적
            iter->second.flowAdd(header->caplen);
            std::cout<<a<<":"<< iter->second._bytes()<<std::endl;
            std::cout<<"thread1 : second flow add ok \n";
        }

    }
}

uint32_t address_ToCompare(const u_char* packet){   //들어온 패킷의 ip와 제어할 ip가 일치하는지 비교
    std::cout<<"thread1 : address to compare begine \n";
    struct ipv4_hdr *ipPacket = (struct ipv4_hdr*)(packet + 14);
    VECTOR::iterator iter;
    for(iter=(control_ip).begin();iter!=(control_ip).end(); iter++){
        if((ntohl(ipPacket->ip_src)==*iter)||(ntohl(ipPacket->ip_dst)==*iter))
            return *iter;
    }
    return -1;
}

int packetProcess(int ctrl_bytes, const u_char* packet, struct pcap_pkthdr* header){
    struct ethernet_hdr *etherPacket = (struct ethernet_hdr *)packet;
    if((ntohs(etherPacket->ether_type)==ETHERTYPE_IP)){
        struct ipv4_hdr *ipPacket = (struct ipv4_hdr*)(packet + 14);
        if((ipPacket->ip_p == P_TCP)||(ipPacket->ip_p == P_UDP))             //packet이 tcp udp일 경우에만
           flow(packet, header, ctrl_bytes);    //packet flow 처리하기
    }
    return 0;
}
