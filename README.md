# cuckoo-sandbox-installation
Cuckoo Sandbox Installation Guide

## Requirements installation

### Libraries
```
sudo apt install 
python python-pip python-dev libffi-dev libssl-dev
python-virtualenv python-setuptools
libjpeg-dev zlib1g-dev swig
mongodb
#postgresql libpq-dev
qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils python-libvirt
XenAPI
```

```
git build-essential
python-pil python-sqlalchemy
```

```
python-django python-bson python-dpkt python-jinja2 python-magic python-pymongo python-gridfs python-bottle python-pefile python-chardet tcpdump -y
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

./configure  --prefix=$HOME/.local/ --with-crypto --enable-cuckoo --enable-magic

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
wget -qO- https://snapshots.mitmproxy.org/4.0.3/mitmproxy-4.0.3-linux.tar.gz | tar -zxf - -C mitmproxy --strip-components 1
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

### Volatility

```
wget -q http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip
unzip volatility_2.6_lin64_standalone.zip
```

### M2Crypto

```
sudo apt install swig

pip install m2crypto
#pip install m2crypto==0.24.0
```
### guacd

```
sudo apt install libguac-client-rdp0 libguac-client-vnc0 libguac-client-ssh0 guacd
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
sudo adduser cuckoo

pip install -U pip setuptools
pip install -U cuckoo
```