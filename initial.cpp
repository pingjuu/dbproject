#include "initial.h"

extern VECTOR control_vector;
extern FLOW_MAP ipmap;

void time_check(MYSQL *conn, int ctrl_bytes, pcap_t* handle){
    std::this_thread::sleep_for(std::chrono::seconds(5));  //처음 프로그램 시작할 때 앞의 작업들을 위해 5초 정도 기다렸다 시작한다. 
    time_t StartcurTime = time(NULL);
    struct tm *startpLocal = localtime(&StartcurTime);
    int curday = startpLocal->tm_mday;
    FLOW_MAP::iterator iter;
    while(1){
        //현재시간 비교 해서 초기화
        std::cout<<"thread3 : ingggggggggggggg\n";
        time_t curTime = time(NULL);
        struct tm *pLocal = localtime(&curTime);
        if(curday != pLocal->tm_mday){  //날짜가 바뀌면
            std::cout<<"thread3 : curday compare INICIAL!!! \n";
            ARPcontroler = false;
            packetcontroler = false;
                t2.join();
            //해당 바이트 다 초기화조지깅
            control_vector.clear();
            control_vector.insert(0,0);
            for(iter=ipmap.begin(); iter!=ipmap.end(); iter++)
                iter->second.bytes_initial();
            ARPcontroler = true;
            packetcontroler = true;
            t2=std::thread(sendARP, handle);
            curday = pLocal->tm_mday;
        }
        dbupdate(conn);
        std::this_thread::sleep_for(std::chrono::seconds(5));  //스레드 낭비 씹오짐 담에 다시 생각하기
    }
}
void dbupdate(MYSQL *conn){
    FLOW_MAP::iterator it;
    for(it=ipmap.begin(); it!=ipmap.end(); it++){
        flowInfo f = it->first;
        std::string command = "UPDATE testmin_candidate SET data_byte = " + std::to_string(it->second._bytes())+" WHERE ip_index = '"+ipp(f._address())+"';";
        mysql_query(conn, command.c_str());
    }
}
