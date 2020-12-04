#include "initial.h"

extern VECTOR control_vector;
extern FLOW_MAP ipmap;

void time_check(MYSQL *conn, const char* fname, int ctrl_bytes, pcap_t* handle){
    int curday = 0;
    FLOW_MAP::iterator iter;
    while(1){
        //현재시간 비교 해서 초기화
        time_t curTime = time(NULL);
        struct tm *pLocal = localtime(&curTime);
        if(curday)
            if(curday != pLocal->tm_mday){  //날짜가 바뀌면
            /*
                thread1, thread2 종료시키고  <- 이 부분만 짜면 됌
                초기화 시키기(뮤텍스 해야할거가틈)
            */
                ARPcontroler = false;
                packetcontroler = false;
                    t1.join();
                    t2.join();  
                //해당 바이트 다 초기화조지깅
                control_vector.clear();
                for(iter=ipmap.begin(); iter!=ipmap.end(); iter++)
                    iter->second.bytes_initial();
                ARPcontroler = true;
                packetcontroler = true;

                t1=std::thread(packetProcess, fname, ctrl_bytes, handle);
                t2=std::thread(sendARP, handle);
            }
        dbupdate(conn);
        std::this_thread::sleep_for(std::chrono::seconds(5));  //스레드 낭비 씹오짐 담에 다시 생각하기
    }
}
void dbupdate(MYSQL *conn){

    FLOW_MAP::iterator it;
    for(it=ipmap.begin(); it!=ipmap.end(); it++){
        //it->first._address();
        flowInfo f = it->first;
        std::string command = "UPDATE CtrlNetwork SET data_bytes = " + ipp(f._address())+"WHERE ip_index = "+std::to_string(it->second._bytes());
        mysql_query(conn, command.c_str());

    }
}