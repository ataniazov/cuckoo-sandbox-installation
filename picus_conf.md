### Simple Global Routing

```
sudo iptables -t nat -A POSTROUTING -o enp3s0 -s 192.168.59.0/24 -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o wlp4s0 -s 192.168.59.0/24 -j MASQUERADE

# Default drop.
sudo iptables -P FORWARD DROP

# Existing connections.
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# Accept connections from vboxnet to the whole internet.
sudo iptables -A FORWARD -s 192.168.59.0/24 -j ACCEPT

# Internal traffic.
sudo iptables -A FORWARD -s 192.168.59.0/24 -d 192.168.59.0/24 -j ACCEPT

# Log stuff that reaches this point (could be noisy).
sudo iptables -A FORWARD -j LOG
```

### packet forwarding

```
echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
sudo sysctl -w net.ipv4.ip_forward=1
```

### Snapshot

```
VBoxManage snapshot "Windows7x64SP1BaseAntiVM" take "cuckoo1" --pause

VBoxManage controlvm "Windows7x64SP1BaseAntiVM" poweroff
VBoxManage snapshot "Windows7x64SP1BaseAntiVM" restorecurrent
```