FROM ubuntu:18.04

RUN apt update && apt install libpcap-dev iputils-ping net-tools iproute2 ssh -y
RUN apt install vlan -y
RUN apt install python python3-pip vim -y
RUN apt install git -y
RUN python3 -m pip install scapy~=2.4.5
RUN python3 -m pip install python-dotenv~=0.17.1 
RUN python3 -m pip install netaddr~=0.8.0
RUN python3 -m pip install vymgmt
RUN python3 -m pip install pyeapi 
RUN python3 -m pip install requests~=2.25.1
ARG CACHEBUST=1
RUN git clone https://github.com/krzepka/random-host-mutation.git /home