#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

#for logging and error checking
set -o pipefail

OS=`cat /etc/*release | grep "^ID="`
VERSION_ID=`cat /etc/*release | grep "^VERSION_ID="`

if [[ $OS == *"debian"* ]]; then
	echo "Debian"
elif [[ $OS == *"ubuntu"* ]]; then
	echo "Ubuntu"
else
	echo "OS is not Debian or Ubuntu! Exiting!"
	exit
fi

#if [[ -z "$VIKINGOS_LOG" ]]; then
#	if [ $OS == *"ubuntu"* ] && [ $VERSION_ID=*"22.04"* ]; then
#		script vikingos.log /bin/bash -c "VIKINGOS_LOG=1 $0 $*"
#	else
#		script -c "VIKINGOS_LOG=1 $0 $*" vikingos.log 
#	fi
#	echo "Logfile: vikingos.log"
#	exit
#fi

apt-get update

export DEBIAN_FRONTEND=noninteractive

apt-get install -y dialog

IMPACKET_INSTALLED=0


#scanning

install_nmap() {
	echo "nmap" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/scanning
	git clone https://github.com/nmap/nmap.git |& tee -a /opt/vikingos/logs/nmap.err
	if [ $? -ne 0 ]; then return 1; fi
	cd nmap
	./configure --without-zenmap |& tee -a /opt/vikingos/logs/nmap.err
	if [ $? -ne 0 ]; then return 1; fi
	make |& tee -a /opt/vikingos/logs/nmap.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/nmap.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/nmap.err
}

install_masscan() {
	echo "masscan" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/scanning
	git clone https://github.com/robertdavidgraham/masscan.git |& tee -a /opt/vikingos/logs/masscan.err
	if [ $? -ne 0 ]; then return 1; fi
	cd masscan
	make |& tee -a /opt/vikingos/logs/masscan.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/masscan.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/masscan.err
}

install_nbtscan() {
	echo "nbtscan" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/scanning
	git clone https://github.com/resurrecting-open-source-projects/nbtscan |& tee -a /opt/vikingos/logs/nbtscan.err
	if [ $? -ne 0 ]; then return 1; fi
	cd nbtscan
	./autogen.sh |& tee -a /opt/vikingos/logs/nbtscan.err
	if [ $? -ne 0 ]; then return 1; fi
	./configure |& tee -a /opt/vikingos/logs/nbtscan.err
	if [ $? -ne 0 ]; then return 1; fi
	make |& tee -a /opt/vikingos/logs/nbtscan.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/nbtscan.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/nbtscan.err
}


#bruteforce

install_netexec() {
	echo "netexec" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/bruteforce
	mkdir netexec
	cd netexec
	curl -s https://api.github.com/repos/Pennyw0rth/NetExec/releases/latest | grep browser_download_url | grep "nxc\"" | cut -f 4 -d '"' | xargs -L1 curl -L -O -J |& tee -a /opt/vikingos/logs/netexec.err
	chmod 755 nxc
	ln -s /opt/vikingos/bruteforce/netexec/nxc /usr/local/bin/nxc
	ln -s /opt/vikingos/bruteforce/netexec/nxc /usr/local/bin/netexec
	rm /opt/vikingos/logs/netexec.err
}

install_medusa() {
	echo "medusa" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/bruteforce
	git clone https://github.com/jmk-foofus/medusa.git |& tee -a /opt/vikingos/logs/medusa.err
	if [ $? -ne 0 ]; then return 1; fi
	cd medusa
	./configure |& tee -a /opt/vikingos/logs/medusa.err
	if [ $? -ne 0 ]; then return 1; fi
	make |& tee -a /opt/vikingos/logs/medusa.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/medusa.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/medusa.err
}

install_hydra() {
	echo "hydra" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/bruteforce
	git clone https://github.com/vanhauser-thc/thc-hydra.git |& tee -a /opt/vikingos/logs/hydra.err
	if [ $? -ne 0 ]; then return 1; fi
	cd thc-hydra
	./configure |& tee -a /opt/vikingos/logs/hydra.err
	if [ $? -ne 0 ]; then return 1; fi
	make |& tee -a /opt/vikingos/logs/hydra.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/hydra.err
	if [ $? -ne 0 ]; then return 1; fi
	cd hydra-gtk
	apt-get install -y libgtk2.0-dev
	./configure |& tee -a /opt/vikingos/logs/hydra.err
	if [ $? -ne 0 ]; then return 1; fi
	make |& tee -a /opt/vikingos/logs/hydra.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/hydra.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/hydra.err
}

install_ncrack() {
	echo "ncrack" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/bruteforce
	git clone https://github.com/nmap/ncrack |& tee -a /opt/vikingos/logs/ncrack.err
	if [ $? -ne 0 ]; then return 1; fi
	cd ncrack
	#ubuntu 24 broke this, need to ignore zlib version check
	./configure --without-zlib-version-check |& tee -a /opt/vikingos/logs/ncrack.err
	if [ $? -ne 0 ]; then return 1; fi
	make |& tee -a /opt/vikingos/logs/ncrack.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/ncrack.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/ncrack.err
}

#exploit

install_metasploit() {
	echo "metasploit" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/exploit
	mkdir metasploit
	cd metasploit
	curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall |& tee -a /opt/vikingos/logs/metasploit.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/metasploit.err
}

install_responder() {
	echo "responder" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/exploit
	git clone https://github.com/lgandx/Responder |& tee -a /opt/vikingos/logs/responder.err
	if [ $? -ne 0 ]; then return 1; fi
	cd Responder
	/usr/share/.pvenv/bin/pip3 install -r requirements.txt |& tee -a /opt/vikingos/logs/responder.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/responder.err
	echo '/usr/share/.pvenv/bin/python3 /opt/vikingos/exploit/Responder/Responder.py "$@"' > /usr/local/bin/responder && chmod 555 /usr/local/bin/responder
}

install_keystoreexplorer() {
	echo "keystoreexplorer" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/exploit
	mkdir keystore_explorer
	keystore_explorer_link=`curl -s https://api.github.com/repos/kaikramer/keystore-explorer/releases/latest | grep browser_download_url | grep ".deb" | cut -d '"' -f 4 | xargs -n 1 curl -L -O`
	curl -L -O -J $keystore_explorer_link |& tee -a /opt/vikingos/logs/keystoreexplorer.err
	if [ $? -ne 0 ]; then return 1; fi
	dpkg -i *.deb |& tee -a /opt/vikingos/logs/keystoreexplorer.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/keystoreexplorer.err
}

install_flamingo() {
	echo "flamingo" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/exploit
	git clone https://github.com/atredispartners/flamingo |& tee -a /opt/vikingos/logs/flamingo.err
	if [ $? -ne 0 ]; then return 1; fi
	cd flamingo
	go build -o flamingo |& tee -a /opt/vikingos/logs/flamingo.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/flamingo.err
	ln -s /opt/vikingos/exploit/flamingo/flamingo /usr/local/bin/flamingo
}

#sql

install_sqlmap() {
	echo "sqlmap" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/sql
	git clone https://github.com/sqlmapproject/sqlmap |& tee -a /opt/vikingos/logs/sqlmap.err
	if [ $? -ne 0 ]; then return 1; fi
	cd sqlmap
	echo 'python3 /opt/vikingos/sql/sqlmap/sqlmap.py "$@"' > /usr/local/bin/sqlmap && chmod 555 /usr/local/bin/sqlmap
	rm /opt/vikingos/logs/sqlmap.err
}

#relay

install_mitm6() {
	echo "mitm6" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/relay
	git clone https://github.com/dirkjanm/mitm6 |& tee -a /opt/vikingos/logs/mitm6.err
	if [ $? -ne 0 ]; then return 1; fi
	apt-get install -y python3-scapy python3-netifaces python3-twisted |& tee -a /opt/vikingos/logs/mitm6.err
	if [ $? -ne 0 ]; then return 1; fi
	echo 'python3 /opt/vikingos/relay/mitm6/mitm6/mitm6.py "$@"' > /usr/local/bin/mitm6 && chmod 555 /usr/local/bin/mitm6
	rm /opt/vikingos/logs/mitm6.err
}

install_bettercap() {
	echo "bettercap" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/relay
	apt-get install -y libpcap-dev libusb-1.0-0-dev libnetfilter-queue-dev |& tee -a /opt/vikingos/logs/bettercap.err
	if [ $? -ne 0 ]; then return 1; fi
	git clone https://github.com/bettercap/bettercap |& tee -a /opt/vikingos/logs/bettercap.err
	if [ $? -ne 0 ]; then return 1; fi
	cd bettercap
	make build |& tee -a /opt/vikingos/logs/bettercap.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/bettercap.err
	if [ $? -ne 0 ]; then return 1; fi
	bettercap -eval "caplets.update; ui.update; q" |& tee -a /opt/vikingos/logs/bettercap.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/bettercap.err
}

install_ettercap() {
	echo "ettercap" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/relay
	git clone https://github.com/Ettercap/ettercap |& tee -a /opt/vikingos/logs/ettercap.err
	if [ $? -ne 0 ]; then return 1; fi
	apt-get install -y build-essential debhelper bison check cmake flex groff libbsd-dev libcurl4-openssl-dev libmaxminddb-dev libgtk-3-dev libltdl-dev libluajit-5.1-dev libncurses5-dev libnet1-dev libpcap-dev libpcre2-dev libssl-dev |& tee -a /opt/vikingos/logs/ettercap.err
	if [ $? -ne 0 ]; then return 1; fi
	cd ettercap
	mkdir build && cd build
	cmake .. |& tee -a /opt/vikingos/logs/ettercap.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/ettercap.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/ettercap.err
}

#web

install_burpsuite() {
	echo "burpsuite" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/web
	mkdir burpsuite
	cd burpsuite
	BURPAPPEND=`curl -L https://portswigger.net/burp/releases/community/latest | grep "Burp Suite Community Edition - Linux<" | grep -Eo "/[a-zA-Z0-9?=/&;.*-]*" | head -1 | sed -e "s/amp;//g"`
	curl -L -o install_burpsuite.sh https://portswigger.net$BURPAPPEND |& tee -a /opt/vikingos/logs/burpsuite.err
	if [ $? -ne 0 ]; then return 1; fi
	chmod 544 install_burpsuite.sh
	./install_burpsuite.sh |& tee -a /opt/vikingos/logs/burpsuite.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/burpsuite.err
}

install_zap() {
	echo "zap" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/web
	mkdir zap
	cd zap
	ZAPAPPEND=`curl -L https://zaproxy.org/download | grep "unix.sh" | grep -Eo "https://[a-zA-Z0-9*/&=?;_.]*"`
	curl -L -o zap.sh $ZAPAPPEND |& tee -a /opt/vikingos/logs/zap.err
	if [ $? -ne 0 ]; then return 1; fi
	chmod 544 zap.sh
	./zap.sh |& tee -a /opt/vikingos/logs/zap.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/zap.err
}

install_nikto() {
	echo "nikto" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/web
	git clone https://github.com/sullo/nikto |& tee -a /opt/vikingos/logs/nikto.err
	if [ $? -ne 0 ]; then return 1; fi
	echo 'perl /opt/vikingos/web/nikto/program/nikto.pl "$@"' > /usr/local/bin/nikto && chmod 555 /usr/local/bin/nikto
	rm /opt/vikingos/logs/nikto.err
}

install_wpscan() {
	echo "wpscan" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/web
	git clone https://github.com/wpscanteam/wpscan |& tee -a /opt/vikingos/logs/wpscan.err
	if [ $? -ne 0 ]; then return 1; fi
	cd wpscan
	gem install wpscan |& tee -a /opt/vikingos/logs/wpscan.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/wpscan.err
}

install_feroxbuster() {
	echo "feroxbuster" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/web
	mkdir feroxbuster && cd feroxbuster
	curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash |& tee -a /opt/vikingos/logs/feroxbuster.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/feroxbuster.err
	ln -s /opt/vikingos/web/feroxbuster/feroxbuster /usr/local/bin/feroxbuster
}

install_gobuster() {
	echo "gobuster" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/web
	git clone https://github.com/OJ/gobuster |& tee -a /opt/vikingos/logs/gobuster.err
	if [ $? -ne 0 ]; then return 1; fi
	cd gobuster 
	go get |& tee -a /opt/vikingos/logs/gobuster.err
	if [ $? -ne 0 ]; then return 1; fi
	go build |& tee -a /opt/vikingos/logs/gobuster.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/gobuster.err
	ln -s /opt/vikingos/web/gobuster/gobuster /usr/local/bin/gobuster
}

install_cewl() {
	echo "cewl" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/web
	git clone https://github.com/digininja/CeWL |& tee -a /opt/vikingos/logs/cewl.err
	if [ $? -ne 0 ]; then return 1; fi
	cd CeWL
	gem install bundler |& tee -a /opt/vikingos/logs/cewl.err
	if [ $? -ne 0 ]; then return 1; fi
	bundle install |& tee -a /opt/vikingos/logs/cewl.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/cewl.err
	echo 'ruby /opt/vikingos/web/CeWL/cewl.rb "$@"' > /usr/local/bin/cewl && chmod 555 /usr/local/bin/cewl
}

install_cadaver() {
	echo "cadaver" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/web
	git clone --recurse-submodules https://github.com/notroj/cadaver |& tee -a /opt/vikingos/logs/cadaver.err
	if [ $? -ne 0 ]; then return 1; fi
	cd cadaver
	./autogen.sh |& tee -a /opt/vikingos/logs/cadaver.err
	if [ $? -ne 0 ]; then return 1; fi
	apt-get install -y libneon27-dev
	./configure |& tee -a /opt/vikingos/logs/cadaver.err
	if [ $? -ne 0 ]; then return 1; fi
	make |& tee -a /opt/vikingos/logs/cadaver.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/cadaver.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/cadaver.err
}

install_webcheck() {
	echo "web-check" >> /etc/vikingos/vikingos.config
	curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash |& tee -a /opt/vikingos/logs/webcheck.err
	if [ $? -ne 0 ]; then return 1; fi
	export NVM_DIR="$HOME/.nvm"
	[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" 
	nvm install node |& tee -a /opt/vikingos/logs/webcheck.err
	if [ $? -ne 0 ]; then return 1; fi
	\. "$NVM_DIR/nvm.sh" && npm install --global yarn |& tee -a /opt/vikingos/logs/webcheck.err
	if [ $? -ne 0 ]; then return 1; fi
	cd /opt/vikingos/web
	git clone https://github.com/Lissy93/web-check.git
	cd web-check
	\. "$NVM_DIR/nvm.sh" && yarn install |& tee -a /opt/vikingos/logs/webcheck.err
	if [ $? -ne 0 ]; then return 1; fi  
	\. "$NVM_DIR/nvm.sh" && yarn build |& tee -a /opt/vikingos/logs/webcheck.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/webcheck.err
	echo 'if [ "$EUID" -ne 0 ]; then echo "Please run as root by either using sudo su or su root" && exit; fi; export NVM_DIR="$HOME/.nvm" && [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" && cd /opt/vikingos/web/web-check && yarn serve' > /usr/local/bin/web-check && chmod 555 /usr/local/bin/web-check
}

install_firefoxtools() {
	echo "firefoxtools" >> /etc/vikingos/firefoxtools.config
	cd /opt/vikingos/web
    mkdir firefoxtools
	wget -O multi-account-containers.xpi "https://addons.mozilla.org/firefox/downloads/latest/multi-account-containers/addon-5993-latest.xpi" |& tee -a /opt/vikingos/logs/firefoxtools.err
	if [ $? -ne 0 ]; then return 1; fi
	wget -O foxyproxy.xpi "https://addons.mozilla.org/firefox/downloads/latest/foxyproxy-standard/addon-2464-latest.xpi" |& tee -a /opt/vikingos/logs/firefoxtools.err
    if [ $? -ne 0 ]; then return 1; fi
    wget -O trufflehog.xpi "https://addons.mozilla.org/firefox/downloads/file/4035826/trufflehog-0.0.1.xpi" |& tee -a /opt/vikingos/logs/firefoxtools.err
    if [ $? -ne 0 ]; then return 1; fi
  	rm /opt/vikingos/logs/firefoxtools.err


#snmp

install_onesixtyone() {
	echo "onesixtyone" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/snmp
	git clone https://github.com/trailofbits/onesixtyone |& tee -a /opt/vikingos/logs/onesixtyone.err
	if [ $? -ne 0 ]; then return 1; fi  
	cd onesixtyone
	make |& tee -a /opt/vikingos/logs/onesixtyone.err
	if [ $? -ne 0 ]; then return 1; fi  
	make install |& tee -a /opt/vikingos/logs/onesixtyone.err
	if [ $? -ne 0 ]; then return 1; fi  
	rm /opt/vikingos/logs/onesixtyone.err
}

install_snmp() {
	echo "snmp" >> /etc/vikingos/vikingos.config
	apt-get install -y snmp |& tee -a /opt/vikingos/logs/snmp.err
	if [ $? -ne 0 ]; then return 1; fi  
	rm /opt/vikingos/logs/snmp.err
}

#dns

install_dnsrecon() {
	echo "dnsrecon" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/dns
	git clone https://github.com/darkoperator/dnsrecon |& tee -a /opt/vikingos/logs/dnsrecon.err
	if [ $? -ne 0 ]; then return 1; fi  
	cd dnsrecon
	/usr/share/.pvenv/bin/pip3 install -r requirements.txt |& tee -a /opt/vikingos/logs/dnsrecon.err
	if [ $? -ne 0 ]; then return 1; fi  
	rm /opt/vikingos/logs/dnsrecon.err
	echo '/usr/share/.pvenv/bin/python3 /opt/vikingos/dns/dnsrecon/dnsrecon.py "$@"' > /usr/local/bin/dnsrecon && chmod 555 /usr/local/bin/dnsrecon
}

install_dnsenum() {
	echo "dnsenum" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/dns
	git clone https://github.com/SparrowOchon/dnsenum2 |& tee -a /opt/vikingos/logs/dnsenum.err
	if [ $? -ne 0 ]; then return 1; fi  
	cd dnsenum2
	apt-get install -y cpanminus
	make |& tee -a /opt/vikingos/logs/dnsenum.err
	if [ $? -ne 0 ]; then return 1; fi  
	make install |& tee -a /opt/vikingos/logs/dnsenum.err
	if [ $? -ne 0 ]; then return 1; fi  
	rm /opt/vikingos/logs/dnsenum.err
}

#forensics

install_sleuthkit() {
	echo "sleuthkit" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/forensics
	git clone https://github.com/sleuthkit/sleuthkit |& tee -a /opt/vikingos/logs/sleuthkit.err
	if [ $? -ne 0 ]; then return 1; fi
	cd sleuthkit
	./bootstrap |& tee -a /opt/vikingos/logs/sleuthkit.err
	if [ $? -ne 0 ]; then return 1; fi  
	./configure |& tee -a /opt/vikingos/logs/sleuthkit.err
	if [ $? -ne 0 ]; then return 1; fi  
	make |& tee -a /opt/vikingos/logs/sleuthkit.err
	if [ $? -ne 0 ]; then return 1; fi  
	make install |& tee -a /opt/vikingos/logs/sleuthkit.err
	if [ $? -ne 0 ]; then return 1; fi  
	rm /opt/vikingos/logs/sleuthkit.err
}

install_volatility() {
	echo "volatility" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/forensics
	git clone https://github.com/volatilityfoundation/volatility3 |& tee -a /opt/vikingos/logs/volatility.err
	if [ $? -ne 0 ]; then return 1; fi  
	cd volatility3
	python3 -m venv /usr/share/.volatility
	/usr/share/.volatility/bin/pip3 install setuptools
	/usr/share/.volatility/bin/pip3 install -r requirements.txt |& tee -a /opt/vikingos/logs/volatility.err
	if [ $? -ne 0 ]; then return 1; fi  
	/usr/share/.volatility/bin/python3 setup.py build |& tee -a /opt/vikingos/logs/volatility.err
	if [ $? -ne 0 ]; then return 1; fi
	/usr/share/.volatility/bin/python3 setup.py install |& tee -a /opt/vikingos/logs/volatility.err
	if [ $? -ne 0 ]; then return 1; fi
	echo '/usr/share/.volatility/bin/python3 /opt/vikingos/forensics/volatility3/vol.py "$@"' > /usr/local/bin/volatility && chmod 555 /usr/local/bin/volatility
	rm /opt/vikingos/logs/volatility.err
}

install_binwalk() {
	echo "binwalk" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/forensics
	git clone https://github.com/ReFirmLabs/binwalk |& tee -a /opt/vikingos/logs/binwalk.err
	if [ $? -ne 0 ]; then return 1; fi 
	cd binwalk
	#python3.12 removed imp, replacement for it
	apt-get install -y python3-zombie-imp 
	python3 setup.py install |& tee -a /opt/vikingos/logs/binwalk.err
	if [ $? -ne 0 ]; then return 1; fi  
	rm /opt/vikingos/logs/binwalk.err
}

install_ghidra() {
	echo "ghidra" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/forensics
	ghidra_link=`curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | grep browser_download_url | cut -d '"' -f 4`
	curl -L -O -J $ghidra_link |& tee -a /opt/vikingos/logs/ghidra.err
	if [ $? -ne 0 ]; then return 1; fi
	unzip ghidra*
	rm *.zip
	ghidra_dir=`find /opt/vikingos/forensics -name *ghidra*`
	ln -s $ghidra_dir/ghidraRun /usr/local/bin/ghidra
	rm /opt/vikingos/logs/ghidra.err
}

install_radare2() {
	echo "radare2" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/forensics
	mkdir radare2
	cd radare2
	radare2_link=`curl -s https://api.github.com/repos/radareorg/radare2/releases/latest | grep browser_download_url | egrep -v "dev" | grep "amd64" | cut -d '"' -f 4`
	curl -L -O -J $radare2_link |& tee -a /opt/vikingos/logs/radare2.err
	if [ $? -ne 0 ]; then return 1; fi
	dpkg -i * |& tee -a /opt/vikingos/logs/radare2.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/radare2.err
}

install_gdbpeda() {
	echo "peda" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/forensics
	git clone https://github.com/longld/peda |& tee -a /opt/vikingos/logs/gdbpeda.err
	if [ $? -ne 0 ]; then return 1; fi 
	echo "source /opt/vikingos/forensics/peda/peda.py" >> /etc/gdb/gdbinit
	rm /opt/vikingos/logs/gdbpeda.err
}

install_jadx() {
	echo "jadx" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/forensics
	git clone https://github.com/skylot/jadx |& tee -a /opt/vikingos/logs/jadx.err
	if [ $? -ne 0 ]; then return 1; fi 
	cd jadx
	./gradlew dist |& tee -a /opt/vikingos/logs/jadx.err
	if [ $? -ne 0 ]; then return 1; fi 
	ln -s /opt/vikingos/forensics/jadx/build/jadx/bin/jadx /usr/local/bin/jadx
	ln -s /opt/vikingos/forensics/jadx/build/jadx/bin/jadx-gui /usr/local/bin/jadx-gui
	rm /opt/vikingos/logs/jadx.err
}

#resources

install_seclists() {
	echo "seclists" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/resources
	git clone https://github.com/danielmiessler/SecLists |& tee -a /opt/vikingos/logs/seclists.err
	if [ $? -ne 0 ]; then return 1; fi 
	ln -s /opt/vikingos/resources/SecLists/Web-Shells /usr/share/vikingos-resources/webshells
	rm /opt/vikingos/logs/seclists.err
}

install_hacktricks() {
	echo "hacktricks" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/resources
	git clone https://github.com/HackTricks-wiki/hacktricks |& tee -a /opt/vikingos/logs/hacktricks.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/hacktricks.err
}

install_payloadallthethings() {
	echo "payloadallthethings" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/resources
	git clone https://github.com/swisskyrepo/PayloadsAllTheThings |& tee -a /opt/vikingos/logs/payloadallthethings.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/payloadallthethings.err
}

install_rockyou() {
	echo "rockyou" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/resources/wordlists
	curl -L -O -J https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt |& tee -a /opt/vikingos/logs/rockyou.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/rockyou.err
}

install_kwprocessor() {
	echo "kwprocessor(" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/password-cracking
    mkdir keyboardwalk_generator
    cd keyboardwalk_generator
	kwprocessor_download=`curl -s https://api.github.com/repos/hashcat/kwprocessor/releases/latest | grep "browser_download_url" | cut -d '"' -f 4 | wget -i -`
	curl -L -O -J $kwprocessor |& tee -a /opt/vikingos/logs/kwprocessor.err
	if [ $? -ne 0 ]; then return 1; fi 
	7z x kwprocessor-1.00.7z
    if [ $? -ne 0 ]; then return 1; fi 
    curl -s https://api.github.com/repos/hashcat/kwprocessor/releases/latest | grep "browser_download_url.*tar.gz" | cut -d '"' -f 4 | wget -i - 
    if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/kwprocessor.err
}

install_crackstationwordlists() {
	echo "crackstation-wordlists" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/resources/wordlists
	curl -L -O -J https://crackstation.net/files/crackstation.txt.gz |& tee -a /opt/vikingos/logs/crackstation-wordlists.err
	if [ $? -ne 0 ]; then return 1; fi 
	echo "Running gunzip on crackstation...."
	gunzip crackstation.txt.gz
	curl -L -O -J https://crackstation.net/files/crackstation-human-only.txt.gz |& tee -a /opt/vikingos/logs/crackstation-wordlists.err
	if [ $? -ne 0 ]; then return 1; fi 
	gunzip crackstation-human-only.txt.gz
	rm /opt/vikingos/logs/crackstation-wordlists.err
}

install_cyberchef() {
	echo "cyberchef" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/resources
	curl -s https://api.github.com/repos/gchq/CyberChef/releases/latest | grep browser_download_url | grep "CyberChef" | cut -f 4 -d '"' | xargs -L1 curl -L -O -J |& tee -a /opt/vikingos/logs/cyberchef.err
	if [ $? -ne 0 ]; then return 1; fi 
	unzip -d cyberchef CyberChef*.zip
	rm -f CyberChef*.zip
	rm /opt/vikingos/logs/cyberchef.err
}

#crunch
install_crunch() {
	echo "crunch" >> /etc/vikingos/vikingos.config
	apt-get install -y crunch |& tee -a /opt/vikingos/logs/crunch.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/crunch.err
}

#password cracking

install_johntheripper() {
	echo "john-the-ripper" >> /etc/vikingos/vikingos.config
	wget -O- https://apt.repos.intel.com/intel-gpg-keys/GPG-PUB-KEY-INTEL-SW-PRODUCTS.PUB | gpg --dearmor | sudo tee /usr/share/keyrings/oneapi-archive-keyring.gpg > /dev/null
	echo "deb [signed-by=/usr/share/keyrings/oneapi-archive-keyring.gpg] https://apt.repos.intel.com/oneapi all main" | sudo tee /etc/apt/sources.list.d/oneAPI.list
	apt update
	apt-get -y install intel-oneapi-runtime-opencl-2024 |& tee -a /opt/vikingos/logs/johntheripper.err
	if [ $? -ne 0 ]; then return 1; fi 
	cd /opt/vikingos/password-cracking
	git clone https://github.com/openwall/john |& tee -a /opt/vikingos/logs/johntheripper.err
	if [ $? -ne 0 ]; then return 1; fi 
	cd john/src
	apt-get install -y libpcap-dev libbz2-dev |& tee -a /opt/vikingos/logs/johntheripper.err
	if [ $? -ne 0 ]; then return 1; fi 
	./configure |& tee -a /opt/vikingos/logs/johntheripper.err
	if [ $? -ne 0 ]; then return 1; fi 
	make -s clean |& tee -a /opt/vikingos/logs/johntheripper.err
	if [ $? -ne 0 ]; then return 1; fi 
	make -sj4 |& tee -a /opt/vikingos/logs/johntheripper.err
	if [ $? -ne 0 ]; then return 1; fi  
	make install|& tee -a /opt/vikingos/logs/johntheripper.err
	if [ $? -ne 0 ]; then return 1; fi 
	echo '/opt/vikingos/password-cracking/john/run/john "$@"' > /usr/local/bin/john && chmod 555 /usr/local/bin/john
	ls /opt/vikingos/password-cracking/john/run | egrep -v "\." | grep "2john" | xargs -I {} ln -s /opt/vikingos/password-cracking/john/run/{} /usr/local/bin/{}
	rm /opt/vikingos/logs/johntheripper.err
}

install_hashcat() {
	echo "hashcat" >> /etc/vikingos/vikingos.config
	wget -O- https://apt.repos.intel.com/intel-gpg-keys/GPG-PUB-KEY-INTEL-SW-PRODUCTS.PUB | gpg --dearmor | sudo tee /usr/share/keyrings/oneapi-archive-keyring.gpg > /dev/null
	echo "deb [signed-by=/usr/share/keyrings/oneapi-archive-keyring.gpg] https://apt.repos.intel.com/oneapi all main" | sudo tee /etc/apt/sources.list.d/oneAPI.list
	apt update
	apt-get -y install intel-oneapi-runtime-opencl-2024 |& tee -a /opt/vikingos/logs/hashcat.err
	if [ $? -ne 0 ]; then return 1; fi 
	cd /opt/vikingos/password-cracking
	git clone https://github.com/hashcat/hashcat |& tee -a /opt/vikingos/logs/hashcat.err
	if [ $? -ne 0 ]; then return 1; fi 
	cd hashcat
	apt-get install -y opencl-c-headers opencl-headers |& tee -a /opt/vikingos/logs/hashcat.err
	if [ $? -ne 0 ]; then return 1; fi 
	make |& tee -a /opt/vikingos/logs/hashcat.err
	if [ $? -ne 0 ]; then return 1; fi 
	make install |& tee -a /opt/vikingos/logs/hashcat.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/hashcat.err
}

install_hashcatrules() {
	echo "hashcat-rules" >> /etc/vikingos/vikingos.config
	mkdir /opt/vikingos/resources/hashcat-rules
	cd /opt/vikingos/resources/hashcat-rules
	git clone https://github.com/NotSoSecure/password_cracking_rules |& tee -a /opt/vikingos/logs/hashcat-rules.err
	if [ $? -ne 0 ]; then return 1; fi 
	git clone https://github.com/praetorian-inc/Hob0Rules |& tee -a /opt/vikingos/logs/hashcat-rules.err
	if [ $? -ne 0 ]; then return 1; fi 
	cp -r /opt/vikingos/password-cracking/hashcat/rules/* .
	rm /opt/vikingos/logs/hashcat-rules.err
}

#windows

install_impacket() {
	echo "impacket" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows
	git clone https://github.com/fortra/impacket |& tee -a /opt/vikingos/logs/impacket.err
	if [ $? -ne 0 ]; then return 1; fi 
	cd impacket
	/usr/share/.pvenv/bin/pip3 install dsinternals |& tee -a /opt/vikingos/logs/impacket.err
	if [ $? -ne 0 ]; then return 1; fi 
	/usr/share/.pvenv/bin/pip3 install . |& tee -a /opt/vikingos/logs/impacket.err
	if [ $? -ne 0 ]; then return 1; fi 
	ls /usr/share/.pvenv/bin | grep '.py$' | egrep -v "jp.py" | cut -f 1 -d . | xargs -I {} bash -c 'echo "/usr/share/.pvenv/bin/python3 /usr/share/.pvenv/bin/{}.py \"\$@\" " > /usr/local/bin/impacket-{} && chmod 555 /usr/local/bin/impacket-{}' 
	IMPACKET_INSTALLED=1
	rm /opt/vikingos/logs/impacket.err
}

install_bloodhound() {
	echo "bloodhound" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows
	mkdir BloodHound
	cd BloodHound
	curl -L -O -J https://ghst.ly/getbhce |& tee -a /opt/vikingos/logs/bloodhound.err
	if [ $? -ne 0 ]; then return 1; fi 
	echo "cat /opt/vikingos/windows/BloodHound/getbhce | docker compose -f - up" > BloodHound
	chmod +x BloodHound
	ln -s /opt/vikingos/windows/BloodHound/BloodHound /usr/local/bin/BloodHound
	rm /opt/vikingos/logs/bloodhound.err
}

install_nidhogg() {
	echo "nidhogg" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	git clone https://github.com/Idov31/Nidhogg |& tee -a /opt/vikingos/logs/nidhogg.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/nidhogg.err
}

install_openldap() {
	echo "openldap" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows
	git clone https://github.com/openldap/openldap |& tee -a /opt/vikingos/logs/openldap.err
	if [ $? -ne 0 ]; then return 1; fi 
	cd openldap
	./configure |& tee -a /opt/vikingos/logs/openldap.err
	if [ $? -ne 0 ]; then return 1; fi 
	make depend |& tee -a /opt/vikingos/logs/openldap.err
	if [ $? -ne 0 ]; then return 1; fi 
	make |& tee -a /opt/vikingos/logs/openldap.err
	if [ $? -ne 0 ]; then return 1; fi 
	make install |& tee -a /opt/vikingos/logs/openldap.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/openldap.err
}

install_mimikatz() {
	echo "mimikatz" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	mimikatz_download=`curl -s https://api.github.com/repos/gentilkiwi/mimikatz/releases/latest | grep browser_download_url | grep zip | cut -d '"' -f 4`
	curl -L -O -J $mimikatz_download |& tee -a /opt/vikingos/logs/mimikatz.err
	if [ $? -ne 0 ]; then return 1; fi 
	unzip mimikatz* -d mimikatz
	rm mimikatz*.zip
	rm /opt/vikingos/logs/mimikatz.err
}

install_kekeo() {
	echo "kekeo" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	kekeo_download=`curl -s https://api.github.com/repos/gentilkiwi/kekeo/releases/latest | grep browser_download_url | grep zip | cut -d '"' -f 4`
	curl -L -O -J $kekeo_download |& tee -a /opt/vikingos/logs/kekeo.err
	if [ $? -ne 0 ]; then return 1; fi 
	unzip kekeo* -d kekeo
	rm kekeo*.zip
	rm /opt/vikingos/logs/kekeo.err
}

install_lazagne() {
	echo "lazagne" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	lazagne_download=`curl -s https://api.github.com/repos/AlessandroZ/LaZagne/releases/latest | grep browser_download_url | cut -d '"' -f 4`
	curl -L -O -J $lazagne_download |& tee -a /opt/vikingos/logs/lazagne.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/lazagne.err
}

install_sharpcollection() {
	echo "sharpcollection" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	git clone https://github.com/Flangvik/SharpCollection |& tee -a /opt/vikingos/logs/sharpcollection.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/sharpcollection.err
}

install_powersploit() {
	echo "powersploit" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	git clone https://github.com/PowerShellMafia/PowerSploit |& tee -a /opt/vikingos/logs/powersploit.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/powersploit.err
}

install_evilwinrm() {
	echo "evil-winrm" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows
	gem install evil-winrm |& tee -a /opt/vikingos/logs/evil-winrm.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/evil-winrm.err
}

install_enum4linux() {
	echo "enum4linux" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows
	git clone https://github.com/CiscoCXSecurity/enum4linux |& tee -a /opt/vikingos/logs/enum4linux.err
	if [ $? -ne 0 ]; then return 1; fi 
	echo 'perl /opt/vikingos/windows/enum4linux/enum4linux.pl "$@"' > /usr/local/bin/enum4linux && chmod 555 /usr/local/bin/enum4linux
	rm /opt/vikingos/logs/enum4linux.err
}

install_pingcastle() {
	echo "pingcastle" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	pingcastle_download=`curl -s https://api.github.com/repos/vletoux/pingcastle/releases/latest | grep browser_download_url | cut -d '"' -f 4`
	curl -L -O -J $pingcastle_download |& tee -a /opt/vikingos/logs/pingcastle.err
	if [ $? -ne 0 ]; then return 1; fi 
	unzip PingCastle* -d PingCastle
	rm PingCastle*.zip
	rm /opt/vikingos/logs/pingcastle.err
}

install_nanodump() {
	echo "nanodump" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	git clone https://github.com/fortra/nanodump |& tee -a /opt/vikingos/logs/nanodump.err
	if [ $? -ne 0 ]; then return 1; fi 
	cd nanodump
	apt-get install -y mingw-w64 clang 
	make -f Makefile.mingw || make -f Makefile.clang |& tee -a /opt/vikingos/logs/nanodump.err
	if [ $? -ne 0 ]; then return 1; fi 
	rm /opt/vikingos/logs/nanodump.err
}

install_kerbrute() {
	echo "kerbrute" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows
	git clone https://github.com/ropnop/kerbrute |& tee -a /opt/vikingos/logs/kerbrute.err
	if [ $? -ne 0 ]; then return 1; fi 
	cd kerbrute
	make linux |& tee -a /opt/vikingos/logs/kerbrute.err
	if [ $? -ne 0 ]; then return 1; fi 
	ln -s /opt/vikingos/windows/kerbrute/dist/kerbrute_linux_amd64 /usr/local/bin/kerbrute
	rm /opt/vikingos/logs/kerbrute.err
}

install_krbrelayx() {
	echo "krbrelayx" >> /etc/vikingos/vikingos.config
	if [[ $IMPACKET_INSTALLED -eq 0 ]]; then
		install_impacket
	fi
	cd /opt/vikingos/windows
	git clone https://github.com/dirkjanm/krbrelayx  |& tee -a /opt/vikingos/logs/krbrelayx.err
	if [ $? -ne 0 ]; then return 1; fi
	cd krbrelayx
	ls * | grep '.py' | egrep -v '^_' | cut -f 1 -d . | xargs -I {} bash -c 'echo "/usr/share/.pvenv/bin/python3  /opt/vikingos/windows/krbrelayx/{}.py \"\$@\" " > /usr/local/bin/{} && chmod 555 /usr/local/bin/{}'
	rm /opt/vikingos/logs/krbrelayx.err
}

install_certipy() {
	echo "certipy" >> /etc/vikingos/vikingos.config
	if [[ $IMPACKET_INSTALLED -eq 0 ]]; then
		install_impacket
	fi
	cd /opt/vikingos/windows
	git clone https://github.com/ly4k/Certipy |& tee -a /opt/vikingos/logs/certipy.err
	if [ $? -ne 0 ]; then return 1; fi
	cd Certipy
	/usr/share/.pvenv/bin/pip3 install . |& tee -a /opt/vikingos/logs/certipy.err
	if [ $? -ne 0 ]; then return 1; fi
	echo '/usr/share/.pvenv/bin/python3 /usr/share/.pvenv/bin/certipy "$@"'> /usr/local/bin/certipy && chmod 555 /usr/local/bin/certipy
	rm /opt/vikingos/logs/certipy.err
}

install_incognito() {
	echo "incognito" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	git clone https://github.com/FSecureLABS/incognito |& tee -a /opt/vikingos/logs/incognito.err
	if [ $? -ne 0 ]; then return 1; fi
	cd incognito
	git checkout -b test-branch 394545ffb844afcc18e798737cbd070ff3a4eb29 |& tee -a /opt/vikingos/logs/incognito.err
	if [ $? -ne 0 ]; then return 1; fi
	ls | egrep -v "\.exe" | xargs rm 
	rm /opt/vikingos/logs/incognito.err
}

install_sysinternals() {
	echo "sysinternals" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	curl -L -O -J https://download.sysinternals.com/files/SysinternalsSuite.zip |& tee -a /opt/vikingos/logs/sysinternals.err
	if [ $? -ne 0 ]; then return 1; fi
	unzip -d sysinternals SysinternalsSuite.zip 
	rm SysinternalsSuite.zip
	rm /opt/vikingos/logs/sysinternals.err
}

install_godpotato() {
	echo "godpotato" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	mkdir godpotato && cd godpotato
	curl -s https://api.github.com/repos/BeichenDream/GodPotato/releases/latest |  grep browser_download_url | grep "NET2" | cut -d '"' -f 4 | xargs -L1 curl -L -O -J |& tee -a /opt/vikingos/logs/godpotato.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -s https://api.github.com/repos/BeichenDream/GodPotato/releases/latest |  grep browser_download_url | grep "NET35" | cut -d '"' -f 4 | xargs -L1 curl -L -O -J |& tee -a /opt/vikingos/logs/godpotato.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -s https://api.github.com/repos/BeichenDream/GodPotato/releases/latest |  grep browser_download_url | grep "NET4" | cut -d '"' -f 4 | xargs -L1 curl -L -O -J |& tee -a /opt/vikingos/logs/godpotato.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/godpotato.err
}

install_juicypotato() {
	echo "juicypotato" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	git clone https://github.com/ohpe/juicy-potato |& tee -a /opt/vikingos/logs/juicypotato.err
	if [ $? -ne 0 ]; then return 1; fi
	cd juicy-potato
	curl -s https://api.github.com/repos/ohpe/juicy-potato/releases/latest | grep browser_download_url | grep "JuicyPotato.exe" | cut -d '"' -f 4 | xargs -L1 curl -L -O -J |& tee -a /opt/vikingos/logs/juicypotato.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/juicypotato.err
}

install_printspoofer() {
	echo "printspoofer" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	mkdir printspoofer && cd printspoofer
	curl -s https://api.github.com/repos/itm4n/PrintSpoofer/releases/latest | grep browser_download_url | grep "PrintSpoofer" | cut -d '"' -f 4 | xargs -L1 curl -L -O -J |& tee -a /opt/vikingos/logs/printspoofer.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/printspoofer.err
}

install_roguepotato() {
	echo "roguepotato" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	curl -s https://api.github.com/repos/antonioCoco/RoguePotato/releases/latest | grep browser_download_url | grep "RoguePotato" | cut -d '"' -f 4 | xargs -L1 curl -L -O -J |& tee -a /opt/vikingos/logs/roguepotato.err
	if [ $? -ne 0 ]; then return 1; fi
	unzip -d RoguePotato RoguePotato.zip
	rm RoguePotato.zip
	rm /opt/vikingos/logs/roguepotato.err
}

install_powershell() {
	echo "powershell" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	apt install -y wget apt-transport-https software-properties-common
	wget -q "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb"
	if [ $? -ne 0 ]; then return 1; fi
	dpkg -i packages-microsoft-prod.deb
	if [ $? -ne 0 ]; then return 1; fi
	apt update
	if [ $? -ne 0 ]; then return 1; fi
	sudo apt install -y powershell
	if [ $? -ne 0 ]; then return 1; fi
}

install_winscp() {
	echo "winscp" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	wget -q -O WinSCP_portable.exe "https://cdn.winscp.net/files/WinSCP-6.3.4-Portable.zip?secure=hx8AyUXSE7bflXNSE5UbeQ==,1725135861"
	if [ $? -ne 0 ]; then return 1; fi
}

install_7zip() {
	echo "7zip" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/windows-uploads
	wget -q -O 7zip.exe "https://7-zip.org/a/7z2408-x64.exe"
	if [ $? -ne 0 ]; then return 1; fi
}


#linux

install_pspy() {
	echo "pspy" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/linux-uploads
	mkdir pspy
	cd pspy
	curl -s https://api.github.com/repos/DominicBreuker/pspy/releases/latest | grep browser_download_url | cut -d '"' -f 4 | xargs -L1 curl -L -O -J |& tee -a /opt/vikingos/logs/pspy.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/pspy.err
}

install_sshsnake() {
	echo "sshsnake" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/linux-uploads
	git clone https://github.com/MegaManSec/SSH-Snake |& tee -a /opt/vikingos/logs/sshsnake.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/sshsnake.err
}

install_reptile() {
	echo "reptile" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/linux-uploads
	git clone https://github.com/f0rb1dd3n/Reptile |& tee -a /opt/vikingos/logs/reptile.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/reptile.err
}

install_busybox() {
	echo "busybox" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/linux-uploads
	mkdir busybox
	cd busybox
	curl -L -O -J https://www.busybox.net/downloads/binaries/1.21.1/busybox-binaries.tar.bz2 |& tee -a /opt/vikingos/logs/busybox.err
	if [ $? -ne 0 ]; then return 1; fi
	tar xjvf busybox-binaries.tar.bz2
	rm busybox-binaries.tar.bz2
	cd ..
	mkdir busybox-musl-x64
	cd busybox-musl-x64
	curl -L -O -J https://www.busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox |& tee -a /opt/vikingos/logs/busybox.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/busybox.err
}

#cloud

install_awsbucketdump() {
	echo "awsbucketdump" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/cloud
	git clone https://github.com/jordanpotti/AWSBucketDump |& tee -a /opt/vikingos/logs/awsbucketdump.err
	if [ $? -ne 0 ]; then return 1; fi
	cd AWSBucketDump
	python3 -m venv /usr/share/.awsbucketdump
	/usr/share/.awsbucketdump/bin/pip3 install -r requirements.txt |& tee -a /opt/vikingos/logs/awsbucketdump.err
	if [ $? -ne 0 ]; then return 1; fi
	echo '/usr/share/.awsbucketdump/bin/python3 /opt/vikingos/cloud/AWSBucketDump/AWSBucketDump.py "$@"' > /usr/local/bin/awsbucketdump && chmod 555 /usr/local/bin/awsbucketdump
	rm /opt/vikingos/logs/awsbucketdump.err
}

install_awsconsoler() {
	echo "aws-consoler" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/cloud
	git clone https://github.com/NetSPI/aws_consoler |& tee -a /opt/vikingos/logs/awsconsoler.err
	if [ $? -ne 0 ]; then return 1; fi
	cd aws_consoler
	python3 -m venv /usr/share/.aws_consoler
	/usr/share/.aws_consoler/bin/pip3 install -r requirements.txt |& tee -a /opt/vikingos/logs/awsconsoler.err
	if [ $? -ne 0 ]; then return 1; fi
	/usr/share/.aws_consoler/bin/pip3 install setuptools |& tee -a /opt/vikingos/logs/awsconsoler.err
	if [ $? -ne 0 ]; then return 1; fi
	/usr/share/.aws_consoler/bin/python3 setup.py install |& tee -a /opt/vikingos/logs/awsconsoler.err
	if [ $? -ne 0 ]; then return 1; fi
	echo '/usr/share/.aws_consoler/bin/python3 /opt/vikingos/cloud/aws_consoler/aws_consoler/cli.py "$@"' > /usr/local/bin/aws-consoler && chmod 555 /usr/local/bin/aws-consoler
	rm /opt/vikingos/logs/awsconsoler.err
}

install_pacu() {
	echo "pacu" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/cloud
	git clone https://github.com/RhinoSecurityLabs/pacu |& tee -a /opt/vikingos/logs/pacu.err
	if [ $? -ne 0 ]; then return 1; fi
	cd pacu
	python3 -m venv /usr/share/.pacu
	/usr/share/.pacu/bin/pip3 install -r requirements.txt |& tee -a /opt/vikingos/logs/pacu.err
	if [ $? -ne 0 ]; then return 1; fi
	echo '/usr/share/.pacu/bin/python3 /opt/vikingos/cloud/pacu/cli.py "$@"' > /usr/local/bin/pacu && chmod 555 /usr/local/bin/pacu
	rm /opt/vikingos/logs/pacu.err
}

install_enumerateiam() {
	echo "enumerate-iam" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/cloud
	git clone https://github.com/andresriancho/enumerate-iam |& tee -a /opt/vikingos/logs/enumerate-iam.err
	if [ $? -ne 0 ]; then return 1; fi
	cd enumerate-iam
	/usr/share/.pvenv/bin/pip3 install -r requirements.txt |& tee -a /opt/vikingos/logs/enumerate-iam.err
	if [ $? -ne 0 ]; then return 1; fi
	echo '/usr/share/.pvenv/bin/python3 /opt/vikingos/cloud/enumerate-iam/enumerate-iam.py "$@"' > /usr/local/bin/enumerate-iam && chmod 555 /usr/local/bin/enumerate-iam
	rm /opt/vikingos/logs/enumerate-iam.err
}

install_awscli() {
	echo "awscli" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/cloud
	curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" |& tee -a /opt/vikingos/logs/awscli.err
	if [ $? -ne 0 ]; then return 1; fi
	unzip awscliv2.zip
	rm awscliv2.zip
	./aws/install  |& tee -a /opt/vikingos/logs/awscli.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/awscli.err
}

install_boto3() {
    echo "boto3" >> /etc/vikingos/vikingos.config
    LOG_FILE="/opt/vikingos/logs/boto3.err"

    # Install boto3 using pip within the virtual environment
    /usr/share/.pvenv/bin/pip3 install boto3 |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    # Clean up the log file upon successful installation
    rm "$LOG_FILE"
}

install_googlecli() {
	echo "googlecli" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/cloud
	apt-get install -y apt-transport-https ca-certificates gnupg curl |& tee -a /opt/vikingos/logs/googlecli.err
	if [ $? -ne 0 ]; then return 1; fi
	curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg |& tee -a /opt/vikingos/logs/googlecli.err
	if [ $? -ne 0 ]; then return 1; fi
	echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" |& tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
	apt-get update && apt-get install -y google-cloud-cli |& tee -a /opt/vikingos/logs/googlecli.err
	if [ $? -ne 0 ]; then return 1; fi
	gcloud init |& tee -a /opt/vikingos/logs/googlecli.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/googlecli.err
}

install_azurecli() {
	echo "azure-cli" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/cloud
	curl -sL https://aka.ms/InstallAzureCLIDeb | bash |& tee -a /opt/vikingos/logs/azurecli.err
	if [ $? -ne 0 ]; then return 1; fi
	apt-get install ca-certificates curl apt-transport-https lsb-release gnupg |& tee -a /opt/vikingos/logs/azurecli.err
	if [ $? -ne 0 ]; then return 1; fi
	mkdir -p /etc/apt/keyrings
	curl -sLS https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | tee /etc/apt/keyrings/microsoft.gpg > /dev/null
	chmod go+r /etc/apt/keyrings/microsoft.gpg
	AZ_DIST=$(lsb_release -cs)
	echo "deb [arch=`dpkg --print-architecture` signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ $AZ_DIST main" | tee /etc/apt/sources.list.d/azure-cli.list
	apt-get update
	apt-get install -y azure-cli |& tee -a /opt/vikingos/logs/azurecli.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/azurecli.err
}

#github

install_trufflehog() {
	echo "trufflehog" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/github
	mkdir trufflehog
	cd trufflehog
	curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | grep browser_download_url | grep "linux_amd64" | cut -d '"' -f 4 | xargs -L1 curl -L -O -J |& tee -a /opt/vikingos/logs/trufflehog.err
	if [ $? -ne 0 ]; then return 1; fi
	gunzip truffle*
	tar xf truffle*
	chown root:root trufflehog
	ln -s /opt/vikingos/github/trufflehog/trufflehog /usr/local/bin/trufflehog
	rm /opt/vikingos/logs/trufflehog.err
}

#phishing

install_set() {
	echo "social-engineer-toolkit" >> /etc/vikingos/vikingos.config
	python_header=`curl -L https://www.python.org/ftp/python | grep 3.11 | tail -1 | cut -f 2 -d '"'`
	curl -L https://www.python.org/ftp/python/$python_header | grep tar.xz | head -1 | cut -f 2 -d '"' | xargs -I {} curl -L -o /tmp/python.tar.xz https://www.python.org/ftp/python/$python_header/{} |& tee -a /opt/vikingos/logs/social-engineer-toolkit.err
	if [ $? -ne 0 ]; then return 1; fi
	cd /tmp
	tar xf python.tar.xz --one-top-level=Python3.11 --strip-components 1
	cd Python3.11
	mkdir /usr/share/.set
	./configure --prefix=/usr/share/.set |& tee -a /opt/vikingos/logs/social-engineer-toolkit.err
	if [ $? -ne 0 ]; then return 1; fi
	make |& tee -a /opt/vikingos/logs/social-engineer-toolkit.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/social-engineer-toolkit.err
	if [ $? -ne 0 ]; then return 1; fi
	cp /usr/share/.set/include/python3.11/cpython/longintrepr.h /usr/share/.set/include/python3.11/
	cd /opt/vikingos/phishing
	git clone https://github.com/trustedsec/social-engineer-toolkit |& tee -a /opt/vikingos/logs/social-engineer-toolkit.err
	if [ $? -ne 0 ]; then return 1; fi
	cd social-engineer-toolkit
	/usr/share/.set/bin/pip3 install -r requirements.txt |& tee -a /opt/vikingos/logs/social-engineer-toolkit.err
	if [ $? -ne 0 ]; then return 1; fi
	/usr/share/.set/bin/python3 setup.py |& tee -a /opt/vikingos/logs/social-engineer-toolkit.err
	if [ $? -ne 0 ]; then return 1; fi
	echo "cd /usr/local/share/setoolkit && /usr/share/.set/bin/python3 /usr/local/share/setoolkit/setoolkit" > /usr/local/bin/setoolkit && chmod 555 /usr/local/bin/setoolkit
	rm /opt/vikingos/logs/social-engineer-toolkit.err
}

install_evilginx2() {
    echo "evilginx2" >> /etc/vikingos/vikingos.config
    LOG_FILE="/opt/vikingos/logs/evilginx2.err"
    TARGET_DIR="/opt/vikingos/phishing/evilginx2"

    # Create the target directory
    mkdir -p "$TARGET_DIR" |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    cd "$TARGET_DIR" |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    # Define URLs for the Windows and Linux releases
    WINDOWS_URL="https://github.com/kgretzky/evilginx2/releases/download/v3.3.0/evilginx-v3.3.0-windows-64bit.zip"
    LINUX_URL="https://github.com/kgretzky/evilginx2/releases/download/v3.3.0/evilginx-v3.3.0-linux-64bit.zip"

    # Download the Windows release
    wget -O "evilginx-v3.3.0-windows-64bit.zip" "$WINDOWS_URL" |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    # Download the Linux release
    wget -O "evilginx-v3.3.0-linux-64bit.zip" "$LINUX_URL" |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    # Extract each zip file into its own directory
    for zip_file in *.zip; do
        dir_name="${zip_file%.zip}"
        mkdir -p "$dir_name" |& tee -a "$LOG_FILE"
        if [ $? -ne 0 ]; then return 1; fi

        unzip -o "$zip_file" -d "$dir_name" |& tee -a "$LOG_FILE"
        if [ $? -ne 0 ]; then return 1; fi
    done

    # Make the Linux binary executable
    chmod +x "$TARGET_DIR/evilginx-v3.3.0-linux-64bit/evilginx" |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    # Clone phishlet repositories
    mkdir -p "$TARGET_DIR/phishlets" |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    cd "$TARGET_DIR/phishlets" |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    git clone https://github.com/An0nUD4Y/Evilginx2-Phishlets.git |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    git clone https://github.com/ArchonLabs/evilginx2-phishlets.git |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    # Clean up the log file upon successful completion
    rm "$LOG_FILE"
}

#evasion

install_donut() {
	echo "donut" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/evasion
	git clone http://github.com/thewover/donut |& tee -a /opt/vikingos/logs/donut.err
	if [ $? -ne 0 ]; then return 1; fi
	cd donut
	make |& tee -a /opt/vikingos/logs/donut.err
	if [ $? -ne 0 ]; then return 1; fi
	ln -s /opt/vikingos/evasion/donut/donut /usr/local/bin/donut
	rm /opt/vikingos/logs/donut.err
}

install_FilelessPELoader() {
	echo "FilelessPELoader" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/evasion
	git clone https://github.com/SaadAhla/FilelessPELoader.git |& tee -a /opt/vikingos/logs/filelesspeloader.err
	if [ $? -ne 0 ]; then return 1; fi

	python3 -m venv /usr/share/.FilelessPELoader
	/usr/share/.FilelessPELoader/bin/pip3 install pycryptodome pycryptodomex |& tee -a /opt/vikingos/logs/filelesspeloader.err
	if [ $? -ne 0 ]; then return 1; fi

	# Python launcher wrapper
	echo '/usr/share/.FilelessPELoader/bin/python3 /opt/vikingos/evasion/FilelessPELoader/loader.py "$@"' > /usr/local/bin/filelesspeloader-python
	chmod 555 /usr/local/bin/filelesspeloader-python

	# Add compile reminder to README
	echo "[*] modify c file to obfuscate it, then to compile, and name the file something not what it is :) :" > /opt/vikingos/evasion/FilelessPELoader/README.txt
	echo "x86_64-w64-mingw32-gcc -o FilelessPELoader.exe FilelessPELoader.c" >> /opt/vikingos/evasion/FilelessPELoader/README.txt

	rm /opt/vikingos/logs/filelesspeloader.err
}

install_scarecrow() {
	echo "scarecrow" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/evasion
	git clone https://github.com/optiv/ScareCrow |& tee -a /opt/vikingos/logs/scarecrow.err
	if [ $? -ne 0 ]; then return 1; fi
	cd ScareCrow
	apt-get install -y osslsigncode openssl mingw-w64 |& tee -a /opt/vikingos/logs/scarecrow.err
	if [ $? -ne 0 ]; then return 1; fi
	go build ScareCrow.go |& tee -a /opt/vikingos/logs/scarecrow.err
	if [ $? -ne 0 ]; then return 1; fi
	ln -s /opt/vikingos/evasion/ScareCrow/ScareCrow /usr/local/bin/ScareCrow
	rm /opt/vikingos/logs/scarecrow.err
}

install_ebowla() {
	echo "ebowla" >> /etc/vikingos/vikingos.config
	python_header=`curl -L https://www.python.org/ftp/python | grep 2.7.14 | tail -1 | cut -f 2 -d '"'`
	curl -L https://www.python.org/ftp/python/$python_header | grep tar.xz | head -1 | cut -f 2 -d '"' | xargs -I {} curl -L -o /tmp/python.tar.xz https://www.python.org/ftp/python/$python_header/{} |& tee -a /opt/vikingos/logs/ebowla.err
	if [ $? -ne 0 ]; then return 1; fi
	cd /tmp
	tar xf python.tar.xz --one-top-level=Python2.7 --strip-components 1
	cd Python2.7
	mkdir /usr/share/.ebowla
	./configure --prefix=/usr/share/.ebowla |& tee -a /opt/vikingos/logs/ebowla.err
	if [ $? -ne 0 ]; then return 1; fi
	make |& tee -a /opt/vikingos/logs/ebowla.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/ebowla.err
	if [ $? -ne 0 ]; then return 1; fi
	rm -rf /tmp/Python2.7
	curl -o /tmp/get-pip.py https://bootstrap.pypa.io/pip/2.7/get-pip.py |& tee -a /opt/vikingos/logs/ebowla.err
	if [ $? -ne 0 ]; then return 1; fi
	/usr/share/.ebowla/bin/python2.7 /tmp/get-pip.py |& tee -a /opt/vikingos/logs/ebowla.err
	if [ $? -ne 0 ]; then return 1; fi
	/usr/share/.ebowla/bin/pip2.7 install "pycrypto==2.6.1"  |& tee -a /opt/vikingos/logs/ebowla.err
	if [ $? -ne 0 ]; then return 1; fi
	/usr/share/.ebowla/bin/pip2.7 install "pyinstaller==3.6" |& tee -a /opt/vikingos/logs/ebowla.err
	if [ $? -ne 0 ]; then return 1; fi
	/usr/share/.ebowla/bin/pip2.7 install "configobj==5.0.6" |& tee -a /opt/vikingos/logs/ebowla.err
	if [ $? -ne 0 ]; then return 1; fi
	/usr/share/.ebowla/bin/pip2.7 install "pyparsing==2.4.7" |& tee -a /opt/vikingos/logs/ebowla.err
	if [ $? -ne 0 ]; then return 1; fi
	apt-get install -y wine wine64 |& tee -a /opt/vikingos/logs/ebowla.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -o /tmp/go.tar.gz https://go.dev/dl/go1.19.linux-amd64.tar.gz |& tee -a /opt/vikingos/logs/ebowla.err
	if [ $? -ne 0 ]; then return 1; fi
	tar -C /usr/share/.ebowla -xzf /tmp/go.tar.gz
	rm /tmp/go.tar.gz
	cd /opt/vikingos/evasion 
	git clone https://github.com/Genetic-Malware/Ebowla |& tee -a /opt/vikingos/logs/ebowla.err
	if [ $? -ne 0 ]; then return 1; fi
	echo '/usr/share/.ebowla/bin/python2.7 /opt/vikingos/evasion/Ebowla/ebowla.py "$@"' > /usr/local/bin/ebowla && chmod 555 /usr/local/bin/ebowla
	echo 'PATH=/usr/share/.ebowla/go/bin:$PATH cp -r /opt/vikingos/evasion/Ebowla/MemoryModule . && /opt/vikingos/evasion/Ebowla/build_x86_go.sh "$@" && rm -rf MemoryModule' > /usr/local/bin/ebowla-build-x86 && chmod 555 /usr/local/bin/ebowla-build-x86
	echo 'PATH=/usr/share/.ebowla/go/bin:$PATH cp -r /opt/vikingos/evasion/Ebowla/MemoryModule . && /opt/vikingos/evasion/Ebowla/build_x64_go.sh "$@" && rm -rf MemoryModule' > /usr/local/bin/ebowla-build-x64 && chmod 555 /usr/local/bin/ebowla-build-x64
	echo 'cp /opt/vikingos/evasion/Ebowla/genetic.config .' >  /usr/local/bin/ebowla-genetic-config-copy && chmod 555 /usr/local/bin/ebowla-genetic-config-copy
	rm /opt/vikingos/logs/ebowla.err
}

#pivoting
install_chisel() {
	echo "chisel" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/pivoting
	mkdir chisel
	cd chisel
	curl -s https://api.github.com/repos/jpillora/chisel/releases/latest | grep browser_download_url | grep "linux_amd64" | cut -d '"' -f 4 | xargs -L1 curl -L -o chisel.gz |& tee -a /opt/vikingos/logs/chisel.err
	if [ $? -ne 0 ]; then return 1; fi
	gunzip chisel.gz
	chmod 755 chisel
	ln -s /opt/vikingos/pivoting/chisel/chisel /usr/local/bin/chisel
	cd /opt/vikingos/linux-uploads
	mkdir chisel
	cd chisel
	curl -s https://api.github.com/repos/jpillora/chisel/releases/latest | grep browser_download_url | grep "linux" | cut -d '"' -f 4 | xargs -L1 curl -L -o chisel.gz |& tee -a /opt/vikingos/logs/chisel.err
	if [ $? -ne 0 ]; then return 1; fi
	gunzip *.gz
	cd /opt/vikingos/windows-uploads
	mkdir chisel
	cd chisel
	curl -s https://api.github.com/repos/jpillora/chisel/releases/latest | grep browser_download_url | grep "windows" | cut -d '"' -f 4 | xargs -L1 curl -L -o chisel.gz |& tee -a /opt/vikingos/logs/chisel.err
	if [ $? -ne 0 ]; then return 1; fi
	gunzip *.gz
	rm /opt/vikingos/logs/chisel.err
}

install_uploadserver() {
	echo "uploadserver" >> /etc/vikingos/vikingos.config
	pip3 install uploadserver |& tee -a /opt/vikingos/logs/uploadserver.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/uploadserver.err
	
}
install_ligolong()
{
	echo "ligolo-ng" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/pivoting
	mkdir ligolo-ng
	cd ligolo-ng
	curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep browser_download_url | grep "proxy" | grep "linux_amd64"  | cut -d '"' -f 4 | xargs -L1 curl -L -o ligolo-ng.tar.gz |& tee -a /opt/vikingos/logs/ligolo-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	gunzip ligolo-ng.tar.gz
	tar xf ligolo-ng.tar
	chmod +x proxy
	ln -s /opt/vikingos/pivoting/ligolo-ng/proxy /usr/local/bin/ligolong-proxy 
	cd /opt/vikingos/linux-uploads
	mkdir ligolo-ng
	cd ligolo-ng
	mkdir linux
	cd linux
	mkdir amd64
	cd amd64
	curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep browser_download_url | grep "agent" | grep "linux_amd64"  | cut -d '"' -f 4 | xargs -L1 curl -L -o ligolo-ng.tar.gz |& tee -a /opt/vikingos/logs/ligolo-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	gunzip ligolo-ng.tar.gz
	tar xf ligolo-ng.tar
	rm ligolo-ng.tar LICENSE README.md
	cd ..
	mkdir arm64
	cd arm64
	curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep browser_download_url | grep "agent" | grep "linux_arm64"  | cut -d '"' -f 4 | xargs -L1 curl -L -o ligolo-ng.tar.gz |& tee -a /opt/vikingos/logs/ligolo-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	gunzip ligolo-ng.tar.gz
	tar xf ligolo-ng.tar
	rm ligolo-ng.tar LICENSE README.md
	cd ..
	mkdir armv6
	cd armv6
	curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep browser_download_url | grep "agent" | grep "linux_armv6"  | cut -d '"' -f 4 | xargs -L1 curl -L -o ligolo-ng.tar.gz |& tee -a /opt/vikingos/logs/ligolo-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	gunzip ligolo-ng.tar.gz
	tar xf ligolo-ng.tar
	rm ligolo-ng.tar LICENSE README.md
	cd ..
	mkdir armv7
	cd armv7
	curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep browser_download_url | grep "agent" | grep "linux_armv7"  | cut -d '"' -f 4 | xargs -L1 curl -L -o ligolo-ng.tar.gz |& tee -a /opt/vikingos/logs/ligolo-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	gunzip ligolo-ng.tar.gz
	tar xf ligolo-ng.tar
	rm ligolo-ng.tar LICENSE README.md
	cd ..
	cd ..
	mkdir darwin
	cd darwin
	mkdir arm64
	cd arm64
	curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep browser_download_url | grep "agent" | grep "darwin_arm64"  | cut -d '"' -f 4 | xargs -L1 curl -L -o ligolo-ng.tar.gz |& tee -a /opt/vikingos/logs/ligolo-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	gunzip ligolo-ng.tar.gz
	tar xf ligolo-ng.tar
	rm ligolo-ng.tar LICENSE README.md
	cd ..
	mkdir amd64
	cd amd64
	curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep browser_download_url | grep "agent" | grep "darwin_amd64"  | cut -d '"' -f 4 | xargs -L1 curl -L -o ligolo-ng.tar.gz |& tee -a /opt/vikingos/logs/ligolo-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	gunzip ligolo-ng.tar.gz
	tar xf ligolo-ng.tar
	rm ligolo-ng.tar LICENSE README.md
	cd /opt/vikingos/windows-uploads
	mkdir ligolo-ng
	cd ligolo-ng 
	mkdir amd64
	cd amd64
	curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep browser_download_url | grep "agent" | grep "windows_amd64"  | cut -d '"' -f 4 | xargs -L1 curl -L -o ligolo-ng.zip |& tee -a /opt/vikingos/logs/ligolo-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	unzip -d . ligolo-ng.zip
	rm ligolo-ng.zip LICENSE README.md
	cd ..
	mkdir arm64
	cd arm64
	curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep browser_download_url | grep "agent" | grep "windows_arm64"  | cut -d '"' -f 4 | xargs -L1 curl -L -o ligolo-ng.zip |& tee -a /opt/vikingos/logs/ligolo-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	unzip -d . ligolo-ng.zip
	rm ligolo-ng.zip LICENSE README.md
	cd ..
	mkdir armv6
	cd armv6
	curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep browser_download_url | grep "agent" | grep "windows_armv6"  | cut -d '"' -f 4 | xargs -L1 curl -L -o ligolo-ng.zip |& tee -a /opt/vikingos/logs/ligolo-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	unzip -d . ligolo-ng.zip
	rm ligolo-ng.zip LICENSE README.md
	cd ..
	mkdir armv7
	cd armv7
	curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep browser_download_url | grep "agent" | grep "windows_armv7"  | cut -d '"' -f 4 | xargs -L1 curl -L -o ligolo-ng.zip |& tee -a /opt/vikingos/logs/ligolo-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	unzip -d . ligolo-ng.zip
	rm ligolo-ng.zip LICENSE README.md
	rm /opt/vikingos/logs/ligolo-ng.err
}
#c2

install_sliver() {
	echo "sliver" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/c2
	curl https://sliver.sh/install | bash |& tee -a /opt/vikingos/logs/sliver.err
	if [ $? -ne 0 ]; then return 1; fi
	cp /root/sliver-server /usr/local/bin/sliver-server
	chmod +x /usr/local/bin/sliver-server
    curl -s https://api.github.com/repos/BishopFox/sliver/releases/latest | grep browser_download_url | cut -d '"' -f 4 | xargs -n 1 curl -L -O  |& tee -a /opt/vikingos/logs/sliver.err
    rm /opt/vikingos/logs/sliver.err
}

install_mythic() {
	echo "mythic" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/c2
	git clone https://github.com/its-a-feature/Mythic |& tee -a /opt/vikingos/logs/mythic.err
	if [ $? -ne 0 ]; then return 1; fi
	cd Mythic
	make
	ln -s /opt/vikingos/c2/Mythic/mythic-cli /usr/local/bin/mythic-cli
	rm /opt/vikingos/logs/mythic.err
}

install_merlin() {
	echo "merlin" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/c2
	mkdir merlin
	cd merlin
	wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinServer-Linux-x64.7z |& tee -a /opt/vikingos/logs/merlin.err
	if [ $? -ne 0 ]; then return 1; fi
	if [[ $OS == *"ubuntu"* && $version == *"22.04"* ]]; then
		7zz x -p"merlin" merlinServer-Linux-x64.7z |& tee -a /opt/vikingos/logs/merlin.err
		if [ $? -ne 0 ]; then return 1; fi
	else
		7z x -p"merlin" merlinServer-Linux-x64.7z |& tee -a /opt/vikingos/logs/merlin.err
		if [ $? -ne 0 ]; then return 1; fi
	fi
	ln -s /opt/vikingos/c2/merlin/merlinServer-Linux-x64 /usr/local/bin/merlinServer
	ln /opt/vikingos/c2/merlin/data/bin/merlinCLI-Linux-x64 /usr/local/bin/merlinCLI
	rm /opt/vikingos/logs/merlin.err
}

install_villain() {
	echo "villain" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/c2
	git clone https://github.com/t3l3machus/Villain |& tee -a /opt/vikingos/logs/villain.err
	if [ $? -ne 0 ]; then return 1; fi
	cd Villain
	python3 -m venv /usr/share/.villain
	/usr/share/.villain/bin/pip3 install -r requirements.txt |& tee -a /opt/vikingos/logs/villain.err
	if [ $? -ne 0 ]; then return 1; fi
	echo '/usr/share/.villain/bin/python3 /opt/vikingos/c2/Villain/Villain.py' > /usr/local/bin/villain && chmod 555 /usr/local/bin/villain 
	rm /opt/vikingos/logs/villain.err
}

install_havoc() {
	echo "havoc" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/c2
	git clone https://github.com/HavocFramework/Havoc.git |& tee -a /opt/vikingos/logs/havoc.err
	if [ $? -ne 0 ]; then return 1; fi
	cd Havoc
	apt install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev qtbase5-dev libqt5websockets5-dev python3-dev libboost-all-dev mingw-w64 nasm |& tee -a /opt/vikingos/logs/havoc.err
	if [ $? -ne 0 ]; then return 1; fi
	cd teamserver
	go mod download golang.org/x/sys |& tee -a /opt/vikingos/logs/havoc.err
	if [ $? -ne 0 ]; then return 1; fi
	go mod download github.com/ugorji/go |& tee -a /opt/vikingos/logs/havoc.err
	if [ $? -ne 0 ]; then return 1; fi
	cd ..
	make ts-build |& tee -a /opt/vikingos/logs/havoc.err
	if [ $? -ne 0 ]; then return 1; fi
	make client-build |& tee -a /opt/vikingos/logs/havoc.err
	if [ $? -ne 0 ]; then return 1; fi
	echo 'cd /opt/vikingos/c2/Havoc && ./havoc "$@"' > /usr/local/bin/havoc && chmod 555 /usr/local/bin/havoc
	rm /opt/vikingos/logs/havoc.err
}

install_poshc2() {
	echo "poshc2" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/c2
	curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | bash |& tee -a /opt/vikingos/logs/poshc2.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/poshc2.err
}

#privesc

install_peassng() {
	echo "peass-ng" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/privesc
	mkdir linpeas
	cd linpeas
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_fat.sh |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_darwin_amd64 |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_darwin_arm64 |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_linux_386 |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_linux_amd64 |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_linux_arm |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_linux_arm64 |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	cd ..
	mkdir winpeas
	cd winpeas
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64_ofs.exe |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx86.exe |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx86_ofs.exe |& tee -a /opt/vikingos/logs/peass-ng.err
	if [ $? -ne 0 ]; then return 1; fi
	ln -s /opt/vikingos/privesc/linpeas /usr/share/vikingos-resources/linux-uploads/
	ln -s /opt/vikingos/privesc/winpeas /usr/share/vikingos-resources/windows-uploads/
	rm /opt/vikingos/logs/peass-ng.err
}

#hexeditor
install_okteta() {
	echo "okteta" >> /etc/vikingos/vikingos.config
	apt-get install -y okteta |& tee -a /opt/vikingos/logs/okteta.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/okteta.err
}

install_bless() {
	echo "bless" >> /etc/vikingos/vikingos.config
	apt-get install -y bless |& tee -a /opt/vikingos/logs/bless.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/bless.err
}

#browsers
install_brave() {
	echo "brave-browser" >> /etc/vikingos/vikingos.config
	apt install curl
	curl -fsSLo /usr/share/keyrings/brave-browser-archive-keyring.gpg https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg |& tee -a /opt/vikingos/logs/brave.err
	if [ $? -ne 0 ]; then return 1; fi
	echo "deb [signed-by=/usr/share/keyrings/brave-browser-archive-keyring.gpg] https://brave-browser-apt-release.s3.brave.com/ stable main"|sudo tee /etc/apt/sources.list.d/brave-browser-release.list
	apt update |& tee -a /opt/vikingos/logs/brave.err
	if [ $? -ne 0 ]; then return 1; fi
	apt install -y brave-browser |& tee -a /opt/vikingos/logs/brave.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/brave.err
}

install_chromium() {
	echo "chromium-browser" >> /etc/vikingos/vikingos.config
	if [[ $OS == *"ubuntu"* ]]; then
		apt-get install -y chromium-browser |& tee -a /opt/vikingos/logs/chromium.err
		if [ $? -ne 0 ]; then return 1; fi
	else
		apt-get install -y chromium |& tee -a /opt/vikingos/logs/chromium.err
		if [ $? -ne 0 ]; then return 1; fi
	fi
	rm /opt/vikingos/logs/chromium.err
}

#virtualization

install_incus() {
	echo "incus" >> /etc/vikingos/vikingos.config
	if [[ `curl -fsSL https://pkgs.zabbly.com/key.asc | gpg --show-keys --fingerprint | grep "4EFC 5906 96CB 15B8 7C73  A3AD 82CC 8797 C838 DCFD"` ]]
	then
		mkdir -p /etc/apt/keyrings/
		curl -fsSL https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc |& tee -a /opt/vikingos/logs/incus.err
		if [ $? -ne 0 ]; then return 1; fi
		sh -c 'cat <<EOF > /etc/apt/sources.list.d/zabbly-incus-stable.sources
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: $(. /etc/os-release && echo ${VERSION_CODENAME})
Components: main
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/zabbly.asc

EOF'
		apt-get update
		apt-get install -y incus incus-client incus-ui-canonical |& tee -a /opt/vikingos/logs/incus.err
		if [ $? -ne 0 ]; then return 1; fi
		incus admin init --minimal |& tee -a /opt/vikingos/logs/incus.err
		if [ $? -ne 0 ]; then return 1; fi
		incus config set core.https_address "localhost:8443" |& tee -a /opt/vikingos/logs/incus.err
		if [ $? -ne 0 ]; then return 1; fi
		apt install -y debootstrap rsync gpg squashfs-tools git make |& tee -a /opt/vikingos/logs/incus.err
		if [ $? -ne 0 ]; then return 1; fi
		cd /opt/vikingos/virtualization
		git clone https://github.com/lxc/distrobuilder |& tee -a /opt/vikingos/logs/incus.err
		if [ $? -ne 0 ]; then return 1; fi
		cd distrobuilder
		rm -rf /usr/bin/go
		ln -s /usr/local/go/bin/go /usr/bin/go
		make |& tee -a /opt/vikingos/logs/incus.err
		if [ $? -ne 0 ]; then return 1; fi
		cp /root/go/bin/distrobuilder /usr/local/bin		
		rm /opt/vikingos/logs/incus.err
	else
		read -p "Something is wrong with the gpg key for the zabbly repo. Please check and install manually. Press any key to resume..."
	fi
}

install_qemu() {
	echo "qemu" >> /etc/vikingos/vikingos.config
	apt-get install -y qemu-system qemu-user |& tee -a /opt/vikingos/logs/qemu.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/qemu.err
}

install_libvirt() {
	echo "libvirt" >> /etc/vikingos/vikingos.config
	apt-get install -y libvirt-clients libvirt-daemon-system virtinst |& tee -a /opt/vikingos/logs/libvirt.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/libvirt.err
}

install_kubectl() {
	echo "kubectl" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/virtualization
	mkdir kubectl
	cd kubectl
	curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" |& tee -a /opt/vikingos/logs/kubectl.err
	if [ $? -ne 0 ]; then return 1; fi
	install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl |& tee -a /opt/vikingos/logs/kubectl.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/kubectl.err
}

#coding

install_vscode() {
	echo "vscode" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/coding
	mkdir vscode
	cd vscode
	VSCODE_LINK=`curl -L https://code.visualstudio.com/sha | jq . | grep deb | grep url | grep amd64 | egrep -v insiders | cut -f 4 -d '"'`
	curl -L -O -J $VSCODE_LINK |& tee -a /opt/vikingos/logs/vscode.err
	if [ $? -ne 0 ]; then return 1; fi
	PATH=$PATH:/usr/sbin:/sbin dpkg -i * |& tee -a /opt/vikingos/logs/vscode.err
	if [ $? -ne 0 ]; then return 1; fi

	rm /opt/vikingos/logs/vscode.err
}

install_nasm() {
	echo "nasm" >> /etc/vikingos/vikingos.config
	apt-get install -y nasm |& tee -a /opt/vikingos/logs/nasm.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/nasm.err
}

install_musl() {
	echo "musl" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/coding
	git clone https://git.musl-libc.org/git/musl |& tee -a /opt/vikingos/logs/musl.err
	if [ $? -ne 0 ]; then return 1; fi
	cd musl
	./configure |& tee -a /opt/vikingos/logs/musl.err
	if [ $? -ne 0 ]; then return 1; fi
	make|& tee -a /opt/vikingos/logs/musl.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/musl.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/musl.err
}

install_perl() {
	echo "perl" >> /etc/vikingos/vikingos.config
	apt-get install -y perl |& tee -a /opt/vikingos/logs/perl.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/perl.err
}

install_ruby() {
	echo "ruby" >> /etc/vikingos/vikingos.config
	apt-get install -y ruby |& tee -a /opt/vikingos/logs/ruby.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/ruby.err
}

install_rust() {
	echo "rust" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/coding
	mkdir rust
	cd rust
	RUSTUP_HOME=/opt/vikingos/coding/rust
	export RUSTUP_HOME
	CARGO_HOME=/opt/vikingos/coding/rust
	export CARGO_HOME
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path |& tee -a /opt/vikingos/logs/rust.err
	if [ $? -ne 0 ]; then return 1; fi
	ls /opt/vikingos/coding/rust/bin | xargs -I {} bash -c 'echo "RUSTUP_HOME=/opt/vikingos/coding/rust exec /opt/vikingos/coding/rust/bin/{} \"\$@\" " > /usr/local/bin/{} && chmod 555 /usr/local/bin/{}'
	rm /opt/vikingos/logs/rust.err
}

install_clang() {
	echo "clang" >> /etc/vikingos/vikingos.config
	apt-get install -y clang |& tee -a /opt/vikingos/logs/clang.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/clang.err
}

install_mingw() {
	echo "mingw-w64" >> /etc/vikingos/vikingos.config
	apt-get install -y mingw-w64 |& tee -a /opt/vikingos/logs/mingw-w64.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/mingw-w64.err
}

install_nim() {
	echo "nim" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/coding
	curl https://nim-lang.org/install_unix.html | grep x64 | egrep -v sha | cut -f 2 -d '"' | xargs -I {} curl -L -O -J https://nim-lang.org/{} |& tee -a /opt/vikingos/logs/nim.err
	if [ $? -ne 0 ]; then return 1; fi
	tar xf nim*
	rm -rf *.tar.xz
	cd nim*
	./install.sh /usr/local/bin |& tee -a /opt/vikingos/logs/nim.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/nim.err
}

#notes

install_ghostwriter() {
	echo "ghostwriter" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/notes
	git clone https://github.com/GhostManager/Ghostwriter.git |& tee -a /opt/vikingos/logs/ghostwriter.err
	if [ $? -ne 0 ]; then return 1; fi
	cd Ghostwriter
	/sbin/service postgresql stop
	./ghostwriter-cli-linux install |& tee -a /opt/vikingos/logs/ghostwriter.err
	if [ $? -ne 0 ]; then return 1; fi
	ln -s /opt/vikingos/notes/Ghostwriter/ghostwriter-cli-linux /usr/local/bin/ghostwriter
	rm /opt/vikingos/logs/ghostwriter.err
}

install_cherrytree() {
	echo "cherrytree" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/notes
	mkdir cherrytree
	cd cherrytree
	curl -s https://api.github.com/repos/giuspen/cherrytree/releases/latest | grep browser_download_url | grep "AppImage" | cut -d '"' -f 4 | xargs -L1 curl -L -O -J |& tee -a /opt/vikingos/logs/cherrytree.err
	if [ $? -ne 0 ]; then return 1; fi
	chmod +x Cherry*
	if [[ $OS == *"ubuntu"* ]]; then
		apt-get install -y libfuse2 |& tee -a /opt/vikingos/logs/cherrytree.err
		if [ $? -ne 0 ]; then return 1; fi
	fi
	ls | xargs -I {} ln -s /opt/vikingos/notes/cherrytree/{} /usr/local/bin/cherrytree
	rm /opt/vikingos/logs/cherrytree.err
}

install_mousetrap() {
set -e

# Install pynvim for Python 3 support in Neovim
pip3 install --user --upgrade pynvim

# Define directories
VIM_DIR="$HOME/.vim"
BUNDLE_DIR="$VIM_DIR/bundle"
VUNDLE_DIR="$BUNDLE_DIR/Vundle.vim"
NVIM_CONFIG_DIR="$HOME/.config/nvim"
INIT_VIM="$NVIM_CONFIG_DIR/init.vim"

# Create necessary directories
mkdir -p "$BUNDLE_DIR"
mkdir -p "$NVIM_CONFIG_DIR"

# Install Vundle if not already installed
if [ ! -d "$VUNDLE_DIR" ]; then
  git clone https://github.com/VundleVim/Vundle.vim.git "$VUNDLE_DIR"
fi

# Create init.vim with plugin configurations
cat > "$INIT_VIM" <<EOL
set nocompatible              " be iMproved, required
filetype off                  " required

" set the runtime path to include Vundle and initialize
set rtp+=~/.vim/bundle/Vundle.vim
call vundle#begin()

" let Vundle manage Vundle, required
Plugin 'VundleVim/Vundle.vim'

" Mousetrap plugin
Plugin 'CleverNamesTaken/Mousetrap'

" UltiSnips for snippets
Plugin 'SirVer/ultisnips'

" vim-markdown for Markdown editing
Plugin 'preservim/vim-markdown'

call vundle#end()            " required
filetype plugin indent on    " required

" UltiSnips configuration
let g:UltiSnipsExpandTrigger="<tab>"
let g:UltiSnipsJumpForwardTrigger="<c-j>"
let g:UltiSnipsJumpBackwardTrigger="<c-k>"

" vim-markdown configuration
let g:vim_markdown_folding_disabled = 1
let g:vim_markdown_conceal = 0
let g:vim_markdown_frontmatter = 1
EOL

# Install plugins using Neovim
nvim +PluginInstall +qall

echo "Neovim setup complete with Vundle, Mousetrap, UltiSnips, and vim-markdown."

}

install_sysreptor() {
	echo "sysreptor" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/notes
	mkdir sysreptor
	cd sysreptor

	# Run official installer script
	bash <(curl -s https://docs.sysreptor.com/install.sh) |& tee -a /opt/vikingos/logs/sysreptor.err
	if [ $? -ne 0 ]; then return 1; fi

	# Optional: Create symlink if SysReptor binary exists in a known location
	if [[ -f /opt/sysreptor/sysreptor ]]; then
		ln -s /opt/sysreptor/sysreptor /usr/local/bin/sysreptor
	fi

	rm /opt/vikingos/logs/sysreptor.err
}

install_obsidian() {
	echo "obsidian" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/notes
	mkdir obsidian
	cd obsidian
	curl -L https://obsidian.md/download | grep -i "AppImage" | head -1 | cut -f 2 -d '"' | xargs -I {} curl -L -o obsidian {} |& tee -a /opt/vikingos/logs/obsidian.err
	if [ $? -ne 0 ]; then return 1; fi
	chmod +x obsidian
	ln -s /opt/vikingos/notes/obsidian/obsidian /usr/local/bin/obsidian
	rm /opt/vikingos/logs/obsidian.err
}

install_latex() {
	echo "latex" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/
	curl -L -o install-tl-unx.tar.gz https://mirror.ctan.org/systems/texlive/tlnet/install-tl-unx.tar.gz |& tee -a /opt/vikingos/logs/latex.err
	zcat < install-tl-unx.tar.gz | tar xf - |& tee -a /opt/vikingos/logs/latex.err
	rm -f install-tl-unx.tar.gz
	cd install-tl-*
	perl ./install-tl --no-interaction |& tee -a /opt/vikingos/logs/latex.err
	latex_dir=`ls /usr/local/texlive/20*`
	export PATH=$latex_dir/bin/x86_64-linux:$PATH
	rm /opt/vikingos/logs/latex.err

}

install_drawio() {
	echo "drawio" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/notes
	mkdir drawio
	cd drawio
	curl -s https://api.github.com/repos/jgraph/drawio-desktop/releases/latest | grep browser_download_url | grep "amd64" | grep "deb" | cut -f 4 -d '"' | xargs -L1 curl -L -O -J |& tee -a /opt/vikingos/logs/drawio.err
	if [ $? -ne 0 ]; then return 1; fi
	apt -y install ./drawio* |& tee -a /opt/vikingos/logs/drawio.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/drawio.err
}

#net

install_macchanger() {
	echo "macchanger" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/net
	git clone https://github.com/alobbs/macchanger |& tee -a /opt/vikingos/logs/macchanger.err
	if [ $? -ne 0 ]; then return 1; fi
	cd macchanger
	./autogen.sh |& tee -a /opt/vikingos/logs/macchanger.err
	if [ $? -ne 0 ]; then return 1; fi
	./configure |& tee -a /opt/vikingos/logs/macchanger.err
	if [ $? -ne 0 ]; then return 1; fi
	make |& tee -a /opt/vikingos/logs/macchanger.err
	if [ $? -ne 0 ]; then return 1; fi
	make install |& tee -a /opt/vikingos/logs/macchanger.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/macchanger.err
}

install_hp_lights_out() {
    echo "hp_lights_out" >> /etc/vikingos/vikingos.config
    LOG_FILE="/opt/vikingos/logs/hp_lights_out.err"
    TARGET_DIR="/opt/vikingos/windows/windows-uploads/"

    # Create the target directory
    mkdir -p "$TARGET_DIR" |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    cd "$TARGET_DIR" |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    # Download the HP Lights-Out Management package
    curl -fL -o "SP50793.zip" "https://downloads.hpe.com/pub/softlib2/software1/pubsw-windows/p117886007/v64767/SP50793.zip" |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    # Extract the ZIP file
    unzip -o "SP50793.zip" -d "$TARGET_DIR" |& tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then return 1; fi

    # Clean up the log file upon successful completion
    rm "$LOG_FILE"
}


install_jdgui() {
	echo "jd-gui" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/coding
	mkdir jd-gui
	cd jd-gui
	curl -s https://api.github.com/repos/java-decompiler/jd-gui/releases/latest | grep browser_download_url | egrep -v "min" | grep "\.jar" | cut -d '"' -f 4 | xargs -L1 curl -L -O -J |& tee -a /opt/vikingos/logs/jdgui.err
	if [ $? -ne 0 ]; then return 1; fi
	ls | xargs -I {} echo 'java -jar /opt/vikingos/coding/jd-gui/{}' > /usr/local/bin/jd-gui && chmod 555 /usr/local/bin/jd-gui
	rm /opt/vikingos/logs/jdgui.err
}

install_nfsserver() {
	echo "nfs-server" >> /etc/vikingos/vikingos.config
	if [[ $OS == *"ubuntu"* ]]; then
		apt-get install -y nfs-kernel-server |& tee -a /opt/vikingos/logs/nfsserver.err
		if [ $? -ne 0 ]; then return 1; fi
	else
		apt-get install -y nfs-server |& tee -a /opt/vikingos/logs/nfsserver.err
		if [ $? -ne 0 ]; then return 1; fi
	fi
	rm /opt/vikingos/logs/nfsserver.err
}

#opensource research

install_harvester() {
	echo "harvester" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/opensource-research
	git clone https://github.com/laramies/theHarvester |& tee -a /opt/vikingos/logs/harvester.err
	if [ $? -ne 0 ]; then return 1; fi
	cd theHarvester
	python3 -m venv /usr/share/.harvester
	/usr/share/.harvester/bin/pip3 install -r requirements.txt |& tee -a /opt/vikingos/logs/harvester.err
	if [ $? -ne 0 ]; then return 1; fi
	echo '/usr/share/.harvester/bin/python3 /opt/vikingos/opensource-research/theHarvester/theHarvester.py' > /usr/local/bin/harvester && chmod 555 /usr/local/bin/harvester
	rm /opt/vikingos/logs/harvester.err
}

#encryption/password managers

install_keepassxc() {
	echo "keepassxc" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/encryption_password_managers
	mkdir keepassxc
	cd keepassxc
	curl -L https://keepassxc.org/download/#linux | grep -i "Download Appimage" | cut -f 2 -d '"' | xargs -I {} curl -L -o keepassxc {} |& tee -a /opt/vikingos/logs/keepassxc.err
	if [ $? -ne 0 ]; then return 1; fi
	chmod +x keepassxc
	ln -s /opt/vikingos/encryption_password_managers/keepassxc/keepassxc /usr/local/bin/keepassxc
	rm /opt/vikingos/logs/keepassxc.err
}

install_veracrypt() {
	echo "veracrypt" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/encryption_password_managers
	mkdir veracrypt
	cd veracrypt
	if [[ $OS == *"ubuntu"* ]]; then
		curl -L https://veracrypt.fr/en/Downloads.html | grep href | grep -i `echo $OS | cut -d '=' -f 2` | grep -i `echo $VERSION_ID | cut -d '"' -f 2 | cut -f 1 -d '.'` | head -n 1 | cut -f 2 -d '"' | sed -e "s/&#43;/+/g" | xargs -I {} curl -L -O -J {} |& tee -a /opt/vikingos/logs/veracrypt.err
		if [ $? -ne 0 ]; then return 1; fi
	else
		curl -L https://veracrypt.fr/en/Downloads.html | grep href | grep -i `echo $OS | cut -d '=' -f 2` | grep -i `echo $VERSION_ID | cut -d '"' -f 2` | head -n 1 | cut -f 2 -d '"' | sed -e "s/&#43;/+/g" | xargs -I {} curl -L -O -J {} |& tee -a /opt/vikingos/logs/veracrypt.err
		if [ $? -ne 0 ]; then return 1; fi
	fi
	apt -y install ./*.deb |& tee -a /opt/vikingos/logs/veracrypt.err
	if [ $? -ne 0 ]; then return 1; fi
	rm *.deb
	rm /opt/vikingos/logs/veracrypt.err
}

install_bitwarden() {
	echo "bitwarden" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/encryption_password_managers
	mkdir bitwarden
	cd bitwarden
	curl -L -o bitwarden https://vault.bitwarden.com/download/?app=desktop\&platform=linux |& tee -a /opt/vikingos/logs/bitwardent.err
	if [ $? -ne 0 ]; then return 1; fi
	chmod +x bitwarden
	ln -s /opt/vikingos/encryption_password_managers/bitwarden/bitwarden /usr/local/bin/bitwarden
	rm /opt/vikingos/logs/bitwardent.err
}

install_tor() {
	echo "tor" >> /etc/vikingos/vikingos.config
	apt-get install -y tor |& tee -a /opt/vikingos/logs/tor.err
	if [ $? -ne 0 ]; then return 1; fi
	rm /opt/vikingos/logs/tor.err
}

install_vscode_extensions() {
	echo "vscode-extensions" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/coding
	mkdir -p code_extensions
	cd code_extensions

	EXTENSIONS=(
	    "github.vscode-pull-request-github"
	    "gitlab.gitlab-workflow"
	    "ms-python.python"
	    "ms-python.vscode-pylance"
	    "ms-azuretools.vscode-docker"
	    "ms-kubernetes-tools.vscode-kubernetes-tools"
	    "hashicorp.terraform"
	    "redhat.vscode-yaml"
        "ms-vscode-remote.remote-ssh"
	    "redhat.ansible"
        "ms-vscode-remote.remote-ssh"
        "ms-vscode-remote.remote-containers"
        "platformio.platformio-ide"
	    "ms-azuretools.vscode-bicep"
	    "ms-vscode.vscode-node-azure-pack"
	    "ms-vscode-remote.remote-ssh"
	    "ms-vscode-remote.remote-containers"
	    "ms-azure-devops.azure-pipelines"
        "ms-azuretools.vscode-docker"
        "ms-vscode.cpptools"
        "ms-vscode.powershell"
        "ms-vscode.cpptools-extension-pack"
	    "mongodb.mongodb-vscode"
	    "vscjava.vscode-java-pack"
	    "sonarsource.sonarlint-vscode"
	    "ms-vscode.powershell"
	    "atlassian.atlascode"
	    "ms-vscode.cpptools"
	    "ms-vscode.cpptools-extension-pack"
	    "Oracle.oracle-java"
	    "vscodevim.vim"
        "AmazonWebServices.aws-toolkit-vscode"
	)

	for extension in "${EXTENSIONS[@]}"; do
	    code --install-extension "$extension" --no-sandbox |& tee -a /opt/vikingos/logs/vscode_extensions.err
	    if [ $? -ne 0 ]; then return 1; fi
	done

	rm /opt/vikingos/logs/vscode_extensions.err
}

install_zsh() {
	echo "zsh" >> /etc/vikingos/vikingos.config
	apt-get install -y zsh |& tee -a /opt/vikingos/logs/zsh.err
	if [ $? -ne 0 ]; then return 1; fi
    sudo snap install zellij --classic
    if [ $? -ne 0 ]; then return 1; fi
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended |& tee -a /opt/vikingos/logs/zsh.err
	rm /opt/vikingos/logs/zsh.err
}

install_glab() {
	echo "glab" >> /etc/vikingos/vikingos.config
	cd /opt/vikingos/coding
	mkdir glab
	cd glab

	# Download latest .deb package
	wget https://gitlab.com/api/v4/projects/25320657/packages/generic/glab/latest/glab_amd64.deb |& tee -a /opt/vikingos/logs/glab.err
	if [ $? -ne 0 ]; then return 1; fi

	apt install -y ./glab_amd64.deb |& tee -a /opt/vikingos/logs/glab.err
	if [ $? -ne 0 ]; then return 1; fi

	rm /opt/vikingos/logs/glab.err
}


choices=''
if [ $# -eq 1 ]
  then
  choices=`cat $1`
else
	cmd=(dialog --separate-output --checklist "VikingOS\nTake what you need, leave which you don't:" 22 76 16)
	options=(nmap "" on
		masscan "" on
		nbtscan "" on
		netexec "" on
		medusa "" on
		hydra "" on
		ncrack "" on
		metasploit "" on
		responder "" on
        keystoreexplorer "" on
		flamingo "" on
		sqlmap "" on
		mitm6 "" on
		bettercap "" on
		ettercap "" on
		burpsuite "" on
		zap "" on
		nikto "" on
		wpscan "" on
		feroxbuster "" on
		gobuster "" on
		cewl "" on
		cadaver "" on
        firefoxtools "" on
		web-check "" on
		onesixtyone "" on
		snmp "" on
		dnsrecon "" on
		dnsenum "" on
		sleuthkit "" on
		volatility "" on
		binwalk "" on
		ghidra "" on
		radare2 "" on
		gdbpeda "" on
		jadx "" on
		seclists "" on
        hacktricks "" on
		payloadallthethings "" on
		rockyou "" on
        kwprocessor "" on
		crackstation-wordlists "" on
		cyberchef "" on
		crunch "" on
		john-the-ripper "" on
		hashcat "" on
		hashcat-rules "" on
		impacket "" on
		bloodhound "" on
		nidhogg "" on
		openldap "" on
		mimikatz "" on
		kekeo "" on
		lazagne "" on
		sharpcollection "" on
		powersploit "" on
		evil-winrm "" on
		enum4linux "" on
		pingcastle "" on
		nanodump "" on
		kerbrute "" on
		krbrelayx "" on
		certipy "" on
		incognito "" on
		sysinternals "" on
		godpotato "" on
		juicypotato "" on
		printspoofer "" on
		roguepotato "" on
		powershell "" on
        winscp "" on
        7zip "" on
		pspy "" on
		sshsnake "" on
		reptile "" on
		busybox "" on
		awsbucketdump "" on
		aws-consoler "" on
		pacu "" on
		enumerate-iam "" on
		awscli "" on
        aws_boto3 "" on
		azurecli "" on
		googlecli "" on
		trufflehog "" on
		social-engineer-toolkit "" on
        evilginx2 "" on
		donut "" on
        FilelessPELoader "" on
		scarecrow "" on
		ebowla "" on
        uploadserver "" on
		chisel "" on
		ligolo-ng "" on
		sliver "" on
		mythic "" off
		merlin "" off
		villain "" off
		havoc "" off
		poshc2 "" off
		peass-ng "" on
		okteta "" on
		bless "" on
		brave-browser "" on
		chromium-browser "" on
		incus "" on
		qemu "" on
		libvirt "" on
		kubectl "" on
		vscode "" on
		nasm "" on
		musl "" on
		perl "" on
		ruby "" on
		rust "" on 
		clang "" on
		mingw-w64 "" on
		nim "" on
        vscode_extensions "" off
		ghostwriter "" off
		cherrytree "" on
        mousetrap "" on
        sysreptor "" on
		obsidian "" on
		latex "" off
		drawio "" on
		macchanger "" on
        hp_lights_out "" on
		jd-gui "" on
		theHarvester "" on
		keepassxc "" on
		veracrypt "" on
		bitwarden "" on
		tor "" off
        zsh "" on
		nfs-server "" off)
	choices=$("${cmd[@]}" "${options[@]}" 2>&1 >/dev/tty)
	clear
fi

apt-get install -y smbclient
apt-get install -y recordmydesktop
apt-get install -y screengrab
apt-get install -y shutter
apt-get install -y curl
apt-get install -y git
apt-get install -y gcc
apt-get install -y bzip2
apt-get install -y make
apt-get install -y cmake
apt-get install -y build-essential
apt-get install -y libssl-dev
apt-get install -y libssh-dev 
apt-get install -y automake
apt-get install -y gdb
apt-get install -y nodejs 
apt-get install -y node
apt-get install -y npm
apt-get install -y postgresql-client
apt-get install -y sqlite3 sqlite3-tools
apt-get install -y sqlitebrowser
apt-get install -y python3-pip
apt-get install -y wireshark
apt-get install -y openjdk-17-jre openjdk-17-jdk
apt-get install -y ruby-rubygems ruby-dev
apt-get install -y ssh
apt-get install -y vim
apt-get install -y texinfo
apt-get install -y python3-pip python3-venv python3-virtualenv
apt-get install -y sshuttle
apt-get install -y gdb
apt-get install -y nfs-common
apt-get install -y openvpn
apt-get install -y wireguard
apt-get install -y proxychains
apt-get install -y iptables-persistent
apt-get install -y krb5-config krb5-user
apt-get install -y freerdp2-x11
apt-get install -y libffi-dev
apt-get install -y screen
apt-get install -y tmux
apt-get install -y terminator
apt-get install -y net-tools
apt-get install -y xfburn
apt-get install -y ipmitool
apt-get install -y open-vm-tools
apt-get install -y libreoffice
apt-get install -y gimp
apt-get install -y vlc
apt-get install -y klogg
apt-get install -y softhsm2
apt-get install -y opensc
apt-get install -y filezilla
apt-get install -y samba
apt-get install -y telnet
apt-get install -y minicom
apt-get install -y yubikey-manager
apt-get install -y yubikey-luks
apt-get install -y yubikey-piv-tool
apt-get install -y yubikey-personalization
apt-get install -y yubikey-personalization-gui
apt-get install -y yubikey-manager-qt
apt-get install -y yubioath-desktop
apt-get install -y gnupg2
apt-get install -y pcscd
apt-get install -y scdaemon
apt-get install -y pcscd
apt-get install -y pcsc-tools
apt-get install -y scdaemon 
apt-get install -y gnupg2
apt-get install -y kleopatra
apt-get install -y scdaemon 
apt-get install -y p7zip-full
apt-get install -y net-tools
apt-get install -y neovim
pip3 install --user --upgrade pynvim
apt-get install -y sed
apt-get install -y uuid-runtime
apt-get install -y coreutils
apt-get install -y socat
apt-get install -y minicom 
apt-get install -y fzf
apt-get install -y bat
apt-get install -y ripgrep
sudo snap install dbeaver-ce




# Install Jira CLI tools
echo "Installing Jira CLI tools..."
npm install -g jira-cli

# Install Confluence CLI tools
echo "Installing Confluence CLI tools..."
npm install -g confluence-cli

# Install Bitbucket CLI tools
echo "Installing Bitbucket CLI tools..."
npm install -g bitbucket-cli

echo "Installing AWS SDK npm"
npm install -g aws-sdk


echo "Atlassian CLI tools installation complete."
echo "Development environment setup complete."







if [[ $OS == *"ubuntu"* ]]; then
	apt-get install -y 7zip
fi

if [[ $OS == *"ubuntu"* ]]; then
	apt-get install -y ca-certificates curl
	install -m 0755 -d /etc/apt/keyrings
	curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
	chmod a+r /etc/apt/keyrings/docker.asc
	echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
	apt-get update
	apt-get -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
else
	apt-get install -y ca-certificates curl
	install -m 0755 -d /etc/apt/keyrings
	curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
	chmod a+r /etc/apt/keyrings/docker.asc
	echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" |  tee /etc/apt/sources.list.d/docker.list > /dev/null
	apt-get update
	apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

python3 -m venv /usr/share/.pvenv
mkdir /etc/vikingos
mkdir /opt/vikingos
mkdir /opt/vikingos/logs
mkdir /opt/vikingos/scanning
mkdir /opt/vikingos/bruteforce
mkdir /opt/vikingos/exploit
mkdir /opt/vikingos/sql
mkdir /opt/vikingos/relay
mkdir /opt/vikingos/web
mkdir /opt/vikingos/snmp
mkdir /opt/vikingos/dns
mkdir /opt/vikingos/forensics
mkdir /opt/vikingos/resources
ln -s /opt/vikingos/resources /usr/share/vikingos-resources
mkdir /opt/vikingos/resources/wordlists
mkdir /opt/vikingos/password-cracking
mkdir /opt/vikingos/windows
mkdir /opt/vikingos/windows-uploads
ln -s /opt/vikingos/windows-uploads /usr/share/vikingos-resources/
mkdir /opt/vikingos/linux-uploads
ln -s /opt/vikingos/linux-uploads /usr/share/vikingos-resources/
mkdir /opt/vikingos/cloud
mkdir /opt/vikingos/github
mkdir /opt/vikingos/phishing
mkdir /opt/vikingos/evasion
mkdir /opt/vikingos/c2
mkdir /opt/vikingos/privesc
ln -s /opt/vikingos/privesc /usr/share/vikingos-resources
mkdir /opt/vikingos/coding
mkdir /opt/vikingos/notes
mkdir /opt/vikingos/net
mkdir /opt/vikingos/virtualization
mkdir /opt/vikingos/opensource-research
mkdir /opt/vikingos/pivoting
mkdir /opt/vikingos/encryption_password_managers

cd /opt/vikingos/coding
mkdir go
cd go
curl -L https://go.dev/dl | grep linux-amd64 | head -1 | cut -f 4 -d '"' | xargs -I {} curl -L -O -J https://go.dev/{}
rm -rf /usr/local/go && tar -C /usr/local -xzf go*
echo "export PATH=/usr/local/go/bin:\$PATH:/usr/sbin:/sbin" >> /etc/profile
echo "export PATH=/usr/local/go/bin:\$PATH:/usr/sbin:/sbin" >> /etc/bash.bashrc
source /etc/profile
rm -rf /usr/bin/go
ln -s /usr/local/go/bin/go /usr/bin/go

for choice in $choices
do
	case $choice in
		nmap)
			install_nmap
			;;
		masscan)
			install_masscan
			;;
		nbtscan)
			install_nbtscan
			;;
		netexec)
			install_netexec
			;;
		medusa)
			install_medusa
			;;
		hydra)
			install_hydra
			;;
		ncrack)
			install_ncrack
			;;
		metasploit)
			install_metasploit
			;;
		responder)
			install_responder
			;;
        keystoreexplorer)
            install_keystoreexplorer
            ;;
		flamingo)
			install_flamingo
			;;
		sqlmap)
			install_sqlmap
			;;
		mitm6)
			install_mitm6
			;;
		bettercap)
			install_bettercap
			;;
		ettercap)
			install_ettercap
			;;
		burpsuite)
			install_burpsuite
			;;
		zap)
			install_zap
			;;
		nikto)
			install_nikto
			;;
		wpscan)
			install_wpscan
			;;
		feroxbuster)
			install_feroxbuster
			;;
		gobuster)
			install_gobuster
			;;
		cewl)
			install_cewl
			;;
		cadaver)
			install_cadaver
			;;
        firefoxtools)
            install_firefoxtools
            ;;
		web-check)
			install_webcheck
			;;
		onesixtyone)
			install_onesixtyone
			;;
		snmp)
			install_snmp
			;;
		dnsrecon)
			install_dnsrecon
			;;
		dnsenum)
			install_dnsenum
			;;
		sleuthkit)
			install_sleuthkit
			;;
		volatility)
			install_volatility
			;;
		binwalk)
			install_binwalk
			;;
		ghidra)
			install_ghidra
			;;
		radare2)
			install_radare2
			;;
		gdbpeda)
			install_gdbpeda
			;;
		jadx)
			install_jadx
			;;
		seclists)
			install_seclists
            ;;
        hacktricks)
            install_hacktricks
			;;
		payloadallthethings)
			install_payloadallthethings
			;;
		rockyou)
			install_rockyou
			;;
        kwprocessor)
            install_kwprocessor
            ;;
		crackstation-wordlists)
			install_crackstationwordlists
			;;
		cyberchef)
			install_cyberchef
			;;
		crunch)
			install_crunch
			;;
		john-the-ripper)
			install_johntheripper
			;;
		hashcat)
			install_hashcat
			;;
		hashcat-rules)
			install_hashcatrules
			;;
		impacket)
			install_impacket
			;;
		bloodhound)
			install_bloodhound
			;;
		nidhogg)
			install_nidhogg
			;;
		openldap)
			install_openldap
			;;
		mimikatz)
			install_mimikatz
			;;
		kekeo)
			install_kekeo
			;;
		lazagne)
			install_lazagne
			;;
		sharpcollection)
			install_sharpcollection
			;;
		powersploit)
			install_powersploit
			;;
		evil-winrm)
			install_evilwinrm
			;;
		enum4linux)
			install_enum4linux
			;;
		pingcastle)
			install_pingcastle
			;;
		nanodump)
			install_nanodump
			;;
		kerbrute)
			install_kerbrute
			;;
		krbrelayx)
			install_krbrelayx
			;;
		certipy)
			install_certipy
			;;
		incognito)
			install_incognito
			;;
		sysinternals)
			install_sysinternals
			;;
		godpotato)
			install_godpotato
			;;
		juicypotato)
			install_juicypotato
			;;
		printspoofer)
			install_printspoofer
			;;
		roguepotato)
			install_roguepotato
			;;
		powershell)
			install_powershell
			;;
        winscp)
            install_winscp
            ;;
        7zip)
            install_7zip
            ;;
		pspy)
			install_pspy
			;;
		sshsnake)
			install_sshsnake
			;;
		reptile)
			install_reptile
			;;
		busybox)
			install_busybox
			;;
		awsbucketdump)
			install_awsbucketdump
			;;
		aws-consoler)
			install_awsconsoler
			;;
		pacu)
			install_pacu
			;;
		enumerate-iam)
			install_enumerateiam
			;;
		awscli)
			install_awscli
			;;
        aws_boto3)
            install_boto3
            ;;
		azurecli)
			install_azurecli
			;;
		googlecli)
			install_googlecli
			;;
		trufflehog)
			install_trufflehog
			;;
		social-engineer-toolkit)
			install_set
			;;
        evilginx2)
            install_evilginx2
            ;;
		donut)
			install_donut
			;;
        FilelessPELoader)
            install_FilelessPELoader
            ;;
		scarecrow)
			install_scarecrow
			;;
		ebowla)
			install_ebowla
			;;
        uploadserver)
            install_uploadserver
            ;;
		chisel)
			install_chisel
			;;
		ligolo-ng)
			install_ligolong
			;;
		sliver)
			install_sliver
			;;
		mythic)
			install_mythic
			;;
		merlin)
			install_merlin
			;;
		villain)
			install_villain
			;;
		havoc)
			install_havoc
			;;
		poshc2)
			install_poshc2
			;;
		peass-ng)
			install_peassng
			;;
		okteta)
			install_okteta
			;;
		bless)
			install_bless
			;;
		brave-browser)
			install_brave
			;;
		chromium-browser)
			install_chromium
			;;
		incus)
			install_incus
			;;
		qemu)
			install_qemu
			;;
		libvirt)
			install_libvirt
			;;
		kubectl)
			install_kubectl
			;;
		vscode)
			install_vscode
			;; 
		nasm)
			install_nasm
			;;
		musl)
			install_musl
			;;
		perl)
			install_perl
			;;
		ruby)
			install_ruby
			;;
		rust)
			install_rust
			;;
		clang)
			install_clang
			;;
		mingw-w64)
			install_mingw
			;;
        vscode_extensions_NOT_OPSEC_SAFE)
            install_vscode_extensions
            ;;
		nim)
			install_nim
			;;
		ghostwriter)
			install_ghostwriter
			;;
		cherrytree)
			install_cherrytree
            ;;
        mousetrap)
            install_mousetrap
            ;;
        sysreptor)
            install_sysreptor
			;;
		obsidian)
			install_obsidian
			;;
		latex)
			install_latex
			;;
		drawio)
			install_drawio
			;;
		macchanger)
			install_macchanger
			;;
        hp_lights_out)
            install_hp_lights_out
            ;;
		jd-gui)
			install_jdgui
			;;
		theHarvester)
			install_harvester
			;;
		keepassxc)
			install_keepassxc
			;;
		veracrypt)
			install_veracrypt
			;;
		bitwarden)
			install_bitwarden
			;;
		tor)
			install_tor
			;;
        zsh)
            install_zsh
            ;;
        glab) 
            install_glab
            ;;
		nfs-server)
			install_nfsserver
			;;
	esac
done

echo -ne "Thank you for using vikingos! Some tips:\n\n"
echo -ne "\tFor future builds, you can use /etc/vikingos/vikingos.config to build this same config. Just do ./vikingos.sh vikingos.config!\n\n"
echo -ne "\tFor sliver, make sure you start the service/server then run "armory install all" on the sliver-client and sliver-server to get all the extensions"
echo -ne "\tIf you installed Mythic, using a root shell run the following command to initalize Mythic: cd /opt/vikingos/c2/Mythic && mythic-cli\n\n\t"
echo -ne "\tIf you installed BloodHound, please run the BloodHound command to install all the docker containers and change the password for BloodHound(see https://github.com/SpecterOps/BloodHound for more details)\n\n"
echno -ne "\tIf you install firefoxtools, you need to go to /opt/vikingos/web/firefoxtools and install the extensions manually"
echo -ne "\tResources for the os are located at /usr/share/vikingos-resources\n\n"
echo -ne "\tDev extensions for VS Code install script will need to be run as a normal user in the coding folder"
echo -ne "\tFor cyberchef, ubuntu installs firefox and chromium via snapd which chroots those apps. Because of this,  they cannot read the file. Use brave to open cyberchef instead or reinstall firefox/chromium without using snapd\n\n"
if [ -z "$(ls -A /opt/vikingos/logs)" ]; then
	echo "All Packages installed!"
else
	echo -ne "The following packages failed to install:\n"
	ls -A /opt/vikingos/logs | cut -f 1 -d "." | xargs -I _ echo -ne "\t_\n"
	echo "Please see /opt/vikingos/logs to see log details!"
fi

exit


