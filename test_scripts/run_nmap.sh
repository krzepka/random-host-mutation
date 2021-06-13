for i in {1..10}
  do
    for t in 4 5
      do
        nmap 192.168.1.0/24 -v1 -oN "T$t:$i" -T$t
      done
  done
