all: packet_processor

packet_processor: main.o mac.o ip.o arphdr.o ethhdr.o initial.o network.o flow.o
	g++ -o packet_processor main.o mac.o ip.o arphdr.o ethhdr.o initial.o network.o flow.o -lpcap -lmysqlclient -pthread

main.o: main.cpp initial.h 
	g++ -c -o main.o main.cpp -lpcap

flow.o: flow.cpp flow.h headers.h
	g++ -c -o flow.o flow.cpp -lpcap

mac.o: mac.cpp mac.h
	g++ -c -o mac.o mac.cpp -lpcap

ip.o: ip.cpp ip.h
	g++ -c -o ip.o ip.cpp -lpcap

arphdr.o: arphdr.cpp arphdr.h mac.h ip.h
	g++ -c -o arphdr.o arphdr.cpp -lpcap

ethhdr.o: ethhdr.cpp ethhdr.h mac.h
	g++ -c -o ethhdr.o ethhdr.cpp -lpcap

initial.o: initial.cpp initial.h network.h ip.h
	g++ -c -o initial.o initial.cpp -lpcap

network.o: network.cpp network.h ethhdr.h arphdr.h flow.h
	g++ -c -o network.o network.cpp -lpcap

clean:
	rm -f packet_processor *.o
