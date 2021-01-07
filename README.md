# Network Control System
## 파일 정보 및 목록(File Manifest)
  동일 네트워크(LAN)를 이용하는 Devices중 제한할 IP와 원하는 데이터 제한량을 웹페이지에 입력하면, 정의된  Devices의 네트워크 데이터량이 정의된 데이터 제한량을 초과 했을 시 네트워크를  ARP rediection으로 제한

## 사용법
  - 라즈베리파이에 포트미러링이 지원되는 공유기에 랜선으로 연결한다.
  - pcap library가 없다면 설치
  - sql client 가 없다면 설치
  - git clone으로 해당 프로그램을 받아 실행
  - 제한할 IP(여러개 입력 가능), 데이터 제한량(MB단위)을 인자로 실행
