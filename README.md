# random-host-mutation

RANDOM HOST MUTATION project recreation using GNS3 network emulation.

GNS3 VM installation:

- download from (TODO: provide a link to download GNS3 VM)
- Add a network connection
  - mark name as "Nowy przełącznik wirtualny"
  - check connection type as "external network"
  - check option "allow OS to share network card management"
  - save connection
- import package from the link as a Virtual Machine in Hyper-V
- run GNS3 VM and wait until it is up (may take few minutes)

GNS3 VM setup:

- connect to GNS3 VM from ssh client (connection options visible on the GNS3 VM screen)
- git clone https://github.com/AJNOURI/Quagga_docker_gns3
- git clone https://github.com/krzepka/random-host-mutation/
- rm ./Quagga_docker_gns3/Dockerfile
- cp ./random-host-mutation/Dockerfile_MTG ./Quagga_docker_gns3/Dockerfile
- docker build -t mtg ./Quagga_docker_gns3
- docker build -t mtc ./random-host-mutation

To install topology to GNS3:

- run GNS3 All-in-one tool as administrator
- Edit->preferences
  - GNS3 VM
    - check enable
    - select virtualization engine as Hyper-V
    - select VM as GNS3 VM with name from above
  - Docker -> Docker containers
    - create new
    - run on GNS3 VM
    - existing image: mtg:latest
    - write "MTG" as container name
    - enable 3 network adapters
    - the rest is default
  - Docker -> Docker containers
    - create new
    - run on GNS3 VM
    - existing image: mtc:latest
    - write "MTC" as container name
    - enable 1 network adapters
    - the rest is default

Network configuration:

- add machines to GNS3 according to ./topology.png
- each machine has its network configuration in ./configs folder, apply them to machines' configs respectively
- each MTG machine requires RIP configuration, execute respective scripts from ./rip_configs folder to setup the machines (if you see permission denied to run scripts, use command "chmod -x home/rip_configs/setup_MTG\_<MTG-number>.txt)

Setup Env variables:

- create file with env variables ".env". Example can be accessed in ".env.example"

Run (MTC must be run before MTG's):

- MTC: python3 home/MTC.py
- MTG_1: python3 home/run_mtg.py --adjacent_host_ip=192.168.1.1
- MTG_2: python3 home/run_mtg.py --source_host --adjacent_host_ip=192.168.3.4
