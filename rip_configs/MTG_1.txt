sed -i 's/yes/no/g' /etc/quagga/daemons
sed -i 's/ripd=no/ripd=yes/g' /etc/quagga/daemons

echo "router rip
  network 192.168.1.0/24
  neighbor 192.168.2.3" > /etc/quagga/ripd.conf

/etc/init.d/quagga start