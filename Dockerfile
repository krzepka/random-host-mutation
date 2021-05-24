FROM ubuntu:18.04

RUN apt update && apt install iputils-ping net-tools iproute2 module-init-tools -y
RUN apt-get update && apt-get install vlan -y
RUN apt-get install git -y
RUN apt install python python3-pip vim -y
RUN python3 -m pip install scapy~=2.4.5
RUN python3 -m pip install python-dotenv~=0.17.1
RUN python3 -m pip install schedule~=1.1.0
RUN python3 -m pip install netaddr~=0.8.0
RUN python3 -m pip install requests~=2.25.1
