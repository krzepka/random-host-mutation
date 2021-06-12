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
- git clone <this-repository-location.git>
- cd ./random-host-mutation
- docker build -t test/ubuntu-python .

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
    - existing image: test/ubuntu-python
    - write <machine-name> as container name (May be MTC/MTG)
    - enable 2 network adapters
    - the rest is default

Note: If you want, you can differentiate MTC from MTG by creating a second identical container with different name and 1 network adapter for MTC, 2 network adapters for MTG.

Network configuration:
<TODO: insert image with network configuration>
<TODO: add scripts for each machine: EndHost, MTG, MTC, VyOS-Router>
