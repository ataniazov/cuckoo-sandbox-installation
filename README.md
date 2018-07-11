# cuckoo-sandbox-installation
Cuckoo Sandbox Installation Guide

## Requirements installation

### System clean, update, upgrade

```
sudo apt update
sudo apt upgrade
sudo apt dist-upgrade
sudo apt autoremove
sudo apt autoclean
sudo apt clean
sudo apt update

sudo apt install python python-dev
sudo apt install libjpeg-dev zlib1g-dev swig

wget -qO- https://bootstrap.pypa.io/get-pip.py | python - --user

pip check

pip install enum34 six --user
pip install virtualenv --user

virtualenv cuckoo_venv
. cuckoo_venv/bin/activate

sudo apt install mongodb

#mkdir yara
#wget -qO- https://github.com/plusvic/yara/archive/v3.4.0.tar.gz | tar -zxf - -C yara --strip-components 1

git clone https://github.com/plusvic/yara

cd yara/

sudo apt install automake libtool make gcc

sudo apt install libssl1.0-dev libjansson-dev libmagic-dev

./bootstrap.sh

./configure --prefix=$HOME/.local/ --with-crypto --enable-cuckoo --enable-magic
./configure --prefix=$HOME/cuckoo-2.0.5_venv/local --with-crypto --enable-cuckoo --enable-magic

make && make check
make install

yara -v

cd ..

mkdir ssdeep
wget -qO- https://github.com/ssdeep-project/ssdeep/archive/release-2.14.1.tar.gz | tar -zxf - -C ssdeep --strip-components 1

cd ssdeep

./bootstrap && ./configure --prefix=$HOME/.local/

make && make check
make install

ssdeep -V

cd ..

git clone https://github.com/bunzen/pySSDeep.git
cd pySSDeep
python setup.py build
python setup.py install
cd ..

git clone --recursive https://github.com/kbandla/pydeep.git

cd pydeep

python setup.py build
python setup.py test
python setup.py install

pip show pydeep

cd ..

sudo apt install mitmproxy

sudo apt install tcpdump apparmor-utils
sudo aa-disable /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
sudo getcap /usr/sbin/tcpdump

pip install distorm3
pip install pycrypto
pip install pillow
pip install openpyxl
pip install ujson

pip install pytz

git clone https://github.com/volatilityfoundation/volatility.git

cd volatility/

python setup.py build
python setup.py install

vol.py -h

cd ..

sudo apt install swig

pip install m2crypto
pip install cuckoo
pip install cuckoo==2.0.5

```

### Libraries

```
sudo apt install python python-pip python-dev libffi-dev libssl-dev python-virtualenv python-setuptools libjpeg-dev zlib1g-dev swig mongodb
#postgresql libpq-dev
qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils python-libvirt
XenAPI
```

```
git build-essential
python-pil python-sqlalchemy
```

```
python-django python-bson python-dpkt python-jinja2 python-magic python-pymongo python-gridfs python-bottle python-pefile python-chardet tcpdump
```

### Yara

```
sudo apt install automake libtool make gcc
sudo apt install libssl-dev
sudo apt install libjansson-dev
sudo apt install libmagic-dev

mkdir yara

wget -qO- https://github.com/VirusTotal/yara/archive/v3.7.1.tar.gz | tar -zxf - -C yara --strip-components 1

cd yara
./bootstrap.sh

./configure --prefix=$HOME/.local/ --with-crypto --enable-cuckoo --enable-magic

make && make check
make install

yara -v
```

#### yara-python

```
#pip install yara-python

git clone --recursive https://github.com/VirusTotal/yara-python
cd yara-python
python setup.py build
python setup.py install --user

#python setup.py install --dynamic-linking

pip show yara-python

cd ..
```

### Pydeep

#### ssdeep

```
mkdir ssdeep
wget -qO- https://github.com/ssdeep-project/ssdeep/archive/release-2.14.1.tar.gz | tar -zxf - -C ssdeep --strip-components 1

cd ssdeep

./bootstrap && ./configure --prefix=$HOME/.local/

make && make check
make install

ssdeep -V

cd ..
```

#### pydeep

```
sudo apt install libfuzzy-dev

#pip install pydeep

git clone --recursive https://github.com/kbandla/pydeep.git

cd pydeep

python setup.py build
python setup.py test
python setup.py install --user

pip show pydeep

cd ..
```

### mitmproxy

```
sudo apt install mitmproxy
mitmproxy + ctrl-c
cp $HOME/.mitmproxy/mitmproxy-ca-cert.p12 $HOME/.cuckoo/analyzer/windows/bin/cert.p12
```

### tcpdump

```
sudo apt install tcpdump apparmor-utils
sudo aa-disable /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

getcap /usr/sbin/tcpdump

#sudo apt install libcap2-bin
#sudo chmod +s /usr/sbin/tcpdump
```

### M2Crypto

```
sudo apt install swig

pip install m2crypto --user
#pip install m2crypto==0.24.0
```

### WeasyPrint

```
pip install weasyprint --user
```

### guacd

```
sudo apt install libguac-client-rdp0 libguac-client-vnc0 libguac-client-ssh0 guacd
```

### Volatility

Volatility is an optional tool to do forensic analysis on memory dumps. In combination with Cuckoo, it can automatically provide additional visibility into deep modifications in the operating system as well as detect the presence of rootkit technology that escaped the monitoring domain of Cuckoo’s analyzer.

```
sudo apt install pcregrep libpcre++-dev python-dev

pip install distorm3 --user
pip install pycrypto
pip install pillow
pip install openpyxl --user
pip install ujson --user

pip install pytz


git clone https://github.com/volatilityfoundation/volatility.git

cd volatility

python setup.py build
python setup.py install --user

python vol.py -h

cd ..
```

## Virtualbox

### apt

```
sudo apt install virtualbox virtualbox-ext-pack
```

### Manual
```
sudo add-apt-repository "https://download.virtualbox.org/virtualbox/debian bionic contrib"

wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add -

sudo apt update
sudo apt install virtualbox-5.2
```

## Cuckoo installation

```
virtualenv venv
. venv/bin/activate
pip install -U pip setuptools
pip install -U cuckoo
```

## Cuckoo Configurations

### create cuckoo user (optional)

```
sudo adduser cuckoo
sudo usermod -a -G vboxusers cuckoo
#sudo usermod -a -G libvirtd cuckoo
```

### Increase “Open Files Limit”

/etc/sysctl.conf

```
fs.file-max = 2097152

sysctl -p
```

### Cuckoo Working Directory (CWD)

```
auxiliary.conf
cuckoo.conf
memory.conf
processing.conf
reporting.conf
virtualbox.conf
```

### Simple Global Routing

```
sudo iptables -t nat -A POSTROUTING -o enp3s0 -s 192.168.56.0/24 -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o wlp4s0 -s 192.168.56.0/24 -j MASQUERADE

# Default drop.
sudo iptables -P FORWARD DROP

# Existing connections.
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# Accept connections from vboxnet to the whole internet.
sudo iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT

# Internal traffic.
sudo iptables -A FORWARD -s 192.168.56.0/24 -d 192.168.56.0/24 -j ACCEPT

# Log stuff that reaches this point (could be noisy).
sudo iptables -A FORWARD -j LOG
```

#### packet forwarding

```
echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
sudo sysctl -w net.ipv4.ip_forward=1
```

## Installing the Linux host

```
sudo apt install uml-utilities bridge-utils
```

## Sandbox

### OS

```
Windows 7 SP1 64-bit

```

### Software

```
Python with PIL & Cuckoo agent
Google Chrome
Adobe Reader
Microsoft Office 2010
Adobe Flash
Java JRE
.Net Framework
```

### Settings

```
Disable UAC
Disable Firewall
Disable Auto-Update for Windows and all installed software
Change network settings (Static IP address and private DNS server) 
```

### Snapshot

```
VBoxManage snapshot "cuckoo1" take "cuckoo1" --pause

VBoxManage controlvm "cuckoo1" poweroff
VBoxManage snapshot "cuckoo1" restorecurrent
```

## Moloch

Moloch is an open source, large scale, full packet capturing, indexing, and database system. Moloch augments your current security infrastructure to store and index network traffic in standard PCAP format, providing fast, indexed access.

### ElasticSearch

```
sudo apt install default-jre curl

sudo systemctl start elasticsearch.service

curl -X PUT -d @'/home/cuckoo/.cuckoo/elasticsearch/template.json' 'http://localhost:9200/_template/cuckoo'

```

```
sudo apt install ethtool libyaml-dev 

wget https://files.molo.ch/builds/ubuntu-16.04/moloch_1.1.1-1_amd64.deb

sudo dpkg -i moloch_1.1.1-1_amd64.deb

sudo /data/moloch/db/db.pl http://localhost:9200 init
sudo /data/moloch/bin/moloch_add_user.sh cuckoo cuckoo cuckoosandbox --admin
```