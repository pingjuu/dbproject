#include "initial.h"

extern VECTOR control_vector;
extern FLOW_MAP ipmap;

void time_check(MYSQL *conn, int ctrl_bytes, pcap_t* handle){
    std::cout<<"thread3 : time chech func start \n";
    std::this_thread::sleep_for(std::chrono::seconds(5));  //스레드 낭비 씹오짐 담에 다시 생각하기
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
            /*
                thread1, thread2 종료시키고  <- 이 부분만 짜면 됌
                초기화 시키기(뮤텍스 해야할거가틈)
            */
            std::cout<<"thread3 : curday compare INICIAL!!! \n";
            ARPcontroler = false;
            packetcontroler = false;
                t2.join();
            //해당 바이트 다 초기화조지깅
            control_vector.clear();
            for(iter=ipmap.begin(); iter!=ipmap.end(); iter++)
                iter->second.bytes_initial();
            ARPcontroler = true;
            packetcontroler = true;
             //t1=std::thread(packetProcess, ctrl_bytes, handle);
            t2=std::thread(sendARP, handle);
            curday = pLocal->tm_mday;
        }
        std::cout<<"thread3 : dbupdate start\n";
        dbupdate(conn);
        std::cout<<"thread3 : dbupdate end\n";
        std::this_thread::sleep_for(std::chrono::seconds(5));  //스레드 낭비 씹오짐 담에 다시 생각하기
    }
}
void dbupdate(MYSQL *conn){
    std::cout<<"thread3 : dbupdate func start\n";
    FLOW_MAP::iterator it;
    printf("ipmap size : %d\n", ipmap.size());
    for(it=ipmap.begin(); it!=ipmap.end(); it++){
        flowInfo f = it->first;
        std::cout<<"192.0.0.2 address : "<< ipp(f._address())<<std::endl;
        std::cout<<"byte is : "<<std::to_string(it->second._bytes())<<std::endl;
        std::string command = "UPDATE testmin_candidate SET data_byte = " + std::to_string(it->second._bytes())+" WHERE ip_index = '"+ipp(f._address())+"';";
        //std::cout<<"sql query : "+command<<std::endl;
        mysql_query(conn, command.c_str());
        std::cout<<"thread3 : querey sending\n";
    }
}
