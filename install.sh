#!/bin/sh

echo "Installing BCC..."
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
echo "deb https://repo.iovisor.org/apt/bionic bionic main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)
echo "deb [trusted=yes] https://repo.iovisor.org/apt/bionic bionic-nightly main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)

sudo apt install -y bison build-essential cmake flex git libedit-dev python zlib1g-dev libelf-dev libllvm7 llvm-7-dev libclang-7-dev

git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. 
make
sudo make install
popd

sudo apt install python-pip
pip install pyinotify
pip install Jinja2
echo "Installing ParseMail..."
cd /usr/share/bcc/examples/networking/
sudo git clone https://github.com/ipgonzalez2/ParseMail
cd /usr/share/bcc/examples/networking/ParseMail
sudo rm -r parse-mail/test parse-mail/utils_test.py
echo "Installation completed"



