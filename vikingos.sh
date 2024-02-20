#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

OS=`cat /etc/*release | grep "^ID="`

if [[ $OS == *"debian"* ]]; then
	echo "Debian"
elif [[ $OS == *"ubuntu"* ]]; then
	echo "Ubuntu"
else
	echo "OS is not Debian or Ubuntu! Exiting!"
	exit
fi

if [[ -z "$VIKINGOS_LOG" ]]; then
	if [[ $OS == *"ubuntu"* ]]; then
		script vikingos.log /bin/bash -c "VIKINGOS_LOG=1 $0 $*"
	else
		script vikingos.log -c "VIKINGOS_LOG=1 $0 $*"
	fi
	echo "Logfile: vikingos.log"
	exit
fi

apt-get update

export DEBIAN_FRONTEND=noninteractive

apt-get install -y dialog

IMPACKET_INSTALLED=0



#scanning

install_nmap() {
	cd /opt/vikingos/scanning
	git clone https://github.com/nmap/nmap.git
	cd nmap
	./configure --without-zenmap
	make 
	make install
}

install_masscan() {
	cd /opt/vikingos/scanning
	git clone https://github.com/robertdavidgraham/masscan.git
	cd masscan
	make
	make install 
}

install_nbtscan() {
	cd /opt/vikingos/scanning
	git clone https://github.com/resurrecting-open-source-projects/nbtscan
	cd nbtscan
	./autogen.sh
	./configure
	make
	make install
}


#bruteforce

install_crackmapexec() {
	cd /opt/vikingos/bruteforce
	git clone https://github.com/byt3bl33d3r/CrackMapExec.git
	cd CrackMapExec
	apt-get install -y pipx
	PIPX_BIN_PATH=/usr/local/bin PIPX_HOME=/usr/local/bin pipx install .
	ln -s /usr/local/bin/venvs/crackmapexec/bin/cme /usr/local/bin/cme
	ln -s /usr/local/bin/venvs/crackmapexec/bin/crackmapexec /usr/local/bin/crackmapexec
}

install_medusa() {
	cd /opt/vikingos/bruteforce
	git clone https://github.com/jmk-foofus/medusa.git
	cd medusa
	./configure
	make 
	make install
}

install_hydra() {
	cd /opt/vikingos/bruteforce
	git clone https://github.com/vanhauser-thc/thc-hydra.git
	cd thc-hydra
	./configure
	make
	make install
	cd hydra-gtk
	apt-get install -y libgtk2.0-dev
	./configure
	make
	make install
}

install_ncrack() {
	cd /opt/vikingos/bruteforce
	git clone https://github.com/nmap/ncrack
	cd ncrack 
	./configure
	make
	make install
}

#exploit

install_metasploit() {
	cd /opt/vikingos/exploit
	mkdir metasploit
	cd metasploit
	curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
}

install_responder() {
	cd /opt/vikingos/exploit
	git clone https://github.com/lgandx/Responder	
	cd Responder
	/usr/share/.pvenv/bin/pip3 install -r requirements.txt
	echo '/usr/share/.pvenv/bin/python3 /opt/vikingos/exploit/Responder/Responder.py "$@"' > /usr/local/bin/responder && chmod 555 /usr/local/bin/responder
}

install_flamingo() {
	cd /opt/vikingos/exploit
	git clone https://github.com/atredispartners/flamingo
	cd flamingo
	go build -o flamingo
	ln -s /opt/vikingos/exploit/flamingo/flamingo /usr/local/bin/flamingo
}

#sql

install_sqlmap() {
	cd /opt/vikingos/sql
	git clone https://github.com/sqlmapproject/sqlmap
	cd sqlmap
	echo 'python3 /opt/vikingos/sql/sqlmap/sqlmap.py "$@"' > /usr/local/bin/sqlmap && chmod 555 /usr/local/bin/sqlmap
}

#relay

install_mitm6() {
	cd /opt/vikingos/relay
	git clone https://github.com/dirkjanm/mitm6
	apt-get install -y python3-scapy python3-netifaces python3-twisted
	echo 'python3 /opt/vikingos/relay/mitm6/mitm6/mitm6.py "$@"' > /usr/local/bin/mitm6 && chmod 555 /usr/local/bin/mitm6
}

#web

install_burpsuite() {
	cd /opt/vikingos/web
	mkdir burpsuite
	cd burpsuite
	BURPAPPEND=`curl -L https://portswigger.net/burp/releases/community/latest | grep "Burp Suite Community Edition - Linux<" | grep -Eo "/[a-zA-Z0-9?=/&;.*-]*" | head -1 | sed -e "s/amp;//g"`
	curl -L -o install_burpsuite.sh https://portswigger.net$BURPAPPEND
	chmod 544 install_burpsuite.sh
	./install_burpsuite.sh
}

install_zap() {
	cd /opt/vikingos/web
	mkdir zap
	cd zap
	ZAPAPPEND=`curl -L https://zaproxy.org/download | grep "unix.sh" | grep -Eo "https://[a-zA-Z0-9*/&=?;_.]*"`
	curl -L -o zap.sh $ZAPAPPEND
	chmod 544 zap.sh
	./zap.sh
}

install_nikto() {
	cd /opt/vikingos/web
	git clone https://github.com/sullo/nikto
	echo 'perl /opt/vikingos/web/nikto/program/nikto.pl "$@"' > /usr/local/bin/nikto && chmod 555 /usr/local/bin/nikto
}

install_wpscan() {
	cd /opt/vikingos/web
	git clone https://github.com/wpscanteam/wpscan
	cd wpscan
	gem install wpscan
}

install_feroxbuster() {
	cd /opt/vikingos/web
	mkdir feroxbuster && cd feroxbuster
	curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
	ln -s /opt/vikingos/web/feroxbuster/feroxbuster /usr/local/bin/feroxbuster
}

install_gobuster() {
	cd /opt/vikingos/web
	git clone https://github.com/OJ/gobuster
	cd gobuster 
	go get && go build 
	ln -s /opt/vikingos/web/gobuster/gobuster /usr/local/bin/gobuster
}

install_cewl() {
	cd /opt/vikingos/web
	git clone https://github.com/digininja/CeWL
	cd CeWL
	gem install bundler
	bundle install
	echo 'ruby /opt/vikingos/web/CeWL/cewl.rb "$@"' > /usr/local/bin/cewl && chmod 555 /usr/local/bin/cewl
}

install_cadaver() {
	cd /opt/vikingos/web
	git clone https://github.com/notroj/cadaver
	cd cadaver
	./autogen.sh
	apt-get install -y libneon27-dev
	./configure
	make && make install
}

#snmp

install_onesixtyone() {
	cd /opt/vikingos/snmp
	git clone https://github.com/trailofbits/onesixtyone
	cd onesixtyone
	make && make install
}

install_snmp() {
	apt-get install -y snmp
}

#dns

install_dnsrecon() {
	cd /opt/vikingos/dns
	git clone https://github.com/darkoperator/dnsrecon
	cd dnsrecon
	/usr/share/.pvenv/bin/pip3 install -r requirements.txt
	echo '/usr/share/.pvenv/bin/python3 /opt/vikingos/dns/dnsrecon/dnsrecon.py "$@"' > /usr/local/bin/dnsrecon && chmod 555 /usr/local/bin/dnsrecon
}

install_dnsenum() {
	cd /opt/vikingos/dns
	git clone https://github.com/SparrowOchon/dnsenum2
	cd dnsenum2
	apt-get install -y cpanminus
	make && make install
}

#forensics

install_sleuthkit() {
	cd /opt/vikingos/forensics
	git clone https://github.com/sleuthkit/sleuthkit
	cd sleuthkit
	./bootstrap
	./configure
	make && make install
}

install_volatility() {
	cd /opt/vikingos/forensics
	git clone https://github.com/volatilityfoundation/volatility3
	cd volatility3
	/usr/share/.pvenv/bin/pip3 install -r requirements.txt
	/usr/share/.pvenv/bin/python3 setup.py build
	/usr/share/.pvenv/bin/python3 setup.py install
	echo '/usr/share/.pvenv/bin/python3 /usr/share/.pvenv/bin/vol "$@"' > /usr/local/bin/volatility && chmod 555 /usr/local/bin/volatility
}

install_binwalk() {
	cd /opt/vikingos/forensics
	git clone https://github.com/ReFirmLabs/binwalk
	cd binwalk
	python3 setup.py install
}

install_ghidra() {
	cd /opt/vikingos/forensics
	ghidra_link=`curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | grep browser_download_url | cut -d '"' -f 4`
	curl -L -O -J $ghidra_link
	unzip ghidra*
	rm *.zip
	ghidra_dir=`find /opt/vikingos/forensics -name *ghidra*`
	ln -s $ghidra_dir/ghidraRun /usr/local/bin/ghidra
}

install_radare2() {
	cd /opt/vikingos/forensics
	mkdir radare2
	cd radare2
	radare2_link=`curl -s https://api.github.com/repos/radareorg/radare2/releases/latest | grep browser_download_url | egrep -v "dev" | grep "amd64" | cut -d '"' -f 4`
	curl -L -O -J $radare2_link
	dpkg -i *
}

install_gdbpeda() {
	cd /opt/vikingos/forensics
	git clone https://github.com/longld/peda
	echo "source /opt/vikingos/forensics/peda/peda.py" >> /etc/gdb/gdbinit
}

#resources

install_seclists() {
	cd /opt/vikingos/resources
	git clone https://github.com/danielmiessler/SecLists
}

install_payloadallthethings() {
	cd /opt/vikingos/resources
	git clone https://github.com/swisskyrepo/PayloadsAllTheThings
}

install_rockyou() {
	cd /opt/vikingos/resources/wordlists
	curl -L -O -J https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
}


install_crackstationwordlists() {
	cd /opt/vikingos/resources/wordlists
	curl -L -O -J https://crackstation.net/files/crackstation.txt.gz
	echo "Running gunzip on crackstation...."
	gunzip crackstation.txt.gz
	curl -L -O -J https://crackstation.net/files/crackstation-human-only.txt.gz
	gunzip crackstation-human-only.txt.gz
}

install_cyberchef() {
	cd /opt/vikingos/resources
	curl -s https://api.github.com/repos/gchq/CyberChef/releases/latest | grep browser_download_url | grep "CyberChef" | cut -f 4 -d '"' | xargs -L1 curl -L -O -J
	unzip -d cyberchef CyberChef*.zip
	rm -f CyberChef*.zip
}

#crunch
install_crunch() {
	apt-get install -y crunch
}

#password cracking

install_johntheripper() {
	cd /opt/vikingos/password-cracking
	git clone https://github.com/openwall/john
	cd john/src
	apt-get install -y libpcap-dev libbz2-dev 
	./configure
	make -s clean && make -sj4 && make install
	echo '/opt/vikingos/password-cracking/john/run/john "$@"' > /usr/local/bin/john && chmod 555 /usr/local/bin/john
	ls /opt/vikingos/password-cracking/john/run | egrep -v "\." | grep "2john" | xargs -I {} ln -s /opt/vikingos/password-cracking/john/run/{} /usr/local/bin/{}
}

install_hashcat() {
	cd /opt/vikingos/password-cracking
	git clone https://github.com/hashcat/hashcat
	cd hashcat
	apt-get install -y opencl-c-headers opencl-headers
	make && make install
}

install_hashcatrules() {
	mkdir /opt/vikingos/resources/hashcat-rules
	cd /opt/vikingos/resources/hashcat-rules
	git clone https://github.com/NotSoSecure/password_cracking_rules
	git clone https://github.com/praetorian-inc/Hob0Rules
	cp -r /opt/vikingos/password-cracking/hashcat/rules/* .
}

#windows

install_impacket() {
	cd /opt/vikingos/windows
	git clone https://github.com/fortra/impacket
	cd impacket
	/usr/share/.pvenv/bin/pip3 install dsinternals
	/usr/share/.pvenv/bin/pip3 install .
	ls /usr/share/.pvenv/bin | grep '.py' | cut -f 1 -d . | xargs -I {} bash -c 'echo "/usr/share/.pvenv/bin/python3 /usr/share/.pvenv/bin/{}.py \"\$@\" " > /usr/local/bin/impacket-{} && chmod 555 /usr/local/bin/impacket-{}' 
	IMPACKET_INSTALLED=1
}

install_bloodhound_sharphound() {
	cd /opt/vikingos/windows
	mkdir BloodHound
	cd BloodHound
	curl -L -O -J https://ghst.ly/getbhce
	echo "cat /opt/vikingos/windows/BloodHound/getbhce | docker compose -f - up" > BloodHound
	chmod +x BloodHound
	ln -s /opt/vikingos/windows/BloodHound/BloodHound /usr/local/bin/BloodHound
	cd /opt/vikingos/windows-uploads
	sharphound_download=`curl -s https://api.github.com/repos/BloodHoundAD/SharpHound/releases/latest | grep browser_download_url | egrep -v debug | cut -d '"' -f 4`
	curl -L -O -J $sharphound_download
	unzip SharpHound* -d sharphound
}


install_openldap() {
	cd /opt/vikingos/windows
	git clone https://github.com/openldap/openldap
	cd openldap
	./configure
	make depend
	make && make install
}

install_mimikatz() {
	cd /opt/vikingos/windows-uploads
	mimikatz_download=`curl -s https://api.github.com/repos/gentilkiwi/mimikatz/releases/latest | grep browser_download_url | grep zip | cut -d '"' -f 4`
	curl -L -O -J $mimikatz_download
	unzip mimikatz* -d mimikatz
}

install_kekeo() {
	cd /opt/vikingos/windows-uploads
	kekeo_download=`curl -s https://api.github.com/repos/gentilkiwi/kekeo/releases/latest | grep browser_download_url | grep zip | cut -d '"' -f 4`
	curl -L -O -J $kekeo_download
	unzip kekeo* -d kekeo
}

install_lazagne() {
	cd /opt/vikingos/windows-uploads
	lazagne_download=`curl -s https://api.github.com/repos/AlessandroZ/LaZagne/releases/latest | grep browser_download_url | cut -d '"' -f 4`
	curl -L -O -J $lazagne_download
}

install_sharpcollection() {
	cd /opt/vikingos/windows-uploads
	git clone https://github.com/Flangvik/SharpCollection
}

install_powersploit() {
	cd /opt/vikingos/windows-uploads
	git clone https://github.com/PowerShellMafia/PowerSploit
}

install_evilwinrm() {
	cd /opt/vikingos/windows
	gem install evil-winrm
}

install_enum4linux() {
	cd /opt/vikingos/windows
	git clone https://github.com/CiscoCXSecurity/enum4linux
	echo 'perl /opt/vikingos/windows/enum4linux/enum4linux.pl "$@"' > /usr/local/bin/enum4linux && chmod 555 /usr/local/bin/enum4linux
}

install_pingcastle() {
	cd /opt/vikingos/windows-uploads
	pingcastle_download=`curl -s https://api.github.com/repos/vletoux/pingcastle/releases/latest | grep browser_download_url | cut -d '"' -f 4`
	curl -L -O -J $pingcastle_download
	unzip PingCastle* -d PingCastle
}

install_nanodump() {
	cd /opt/vikingos/windows-uploads
	git clone https://github.com/fortra/nanodump
	cd nanodump
	apt-get install -y mingw-w64
	make -f Makefile.mingw
}

install_kerbrute() {
	cd /opt/vikingos/windows
	git clone https://github.com/ropnop/kerbrute
	cd kerbrute
	make linux
	ln -s /opt/vikingos/windows/kerbrute/dist/kerbrute_linux_amd64 /usr/local/bin/kerbrute
}

install_krbrelayx() {
	if [[ $IMPACKET_INSTALLED -eq 0 ]]; then
		install_impacket
	fi
	cd /opt/vikingos/windows
	git clone https://github.com/dirkjanm/krbrelayx 
	cd krbrelayx
	ls * | grep '.py' | egrep -v '^_' | cut -f 1 -d . | xargs -I {} bash -c 'echo "/usr/share/.pvenv/bin/python3  /opt/vikingos/windows/krbrelayx/{}.py \"\$@\" " > /usr/local/bin/{} && chmod 555 /usr/local/bin/{}'
}

install_certipy() {
	if [[ $IMPACKET_INSTALLED -eq 0 ]]; then
		install_impacket
	fi
	cd /opt/vikingos/windows
	git clone https://github.com/ly4k/Certipy
	cd Certipy
	/usr/share/.pvenv/bin/pip3 install .
	echo '/usr/share/.pvenv/bin/python3 /usr/share/.pvenv/bin/certipy "$@"'> /usr/local/bin/certipy && chmod 555 /usr/local/bin/certipy
}

#linux

install_pspy() {
	cd /opt/vikingos/linux-uploads
	mkdir pspy
	cd pspy
	curl -s https://api.github.com/repos/DominicBreuker/pspy/releases/latest | grep browser_download_url | cut -d '"' -f 4 | xargs -L1 curl -L -O -J
}

#cloud

install_awsbucketdump() {
	cd /opt/vikingos/cloud
	git clone https://github.com/jordanpotti/AWSBucketDump
	cd AWSBucketDump
	python3 -m venv /usr/share/.awsbucketdump
	/usr/share/.awsbucketdump/bin/pip3 install -r requirements.txt
	echo '/usr/share/.awsbucketdump/bin/python3 /opt/vikingos/cloud/AWSBucketDump/AWSBucketDump.py "$@"' > /usr/local/bin/awsbucketdump && chmod 555 /usr/local/bin/awsbucketdump
}

install_azurehound() {
	cd /opt/vikingos/cloud
	azurehound_linux_download=`curl -s https://api.github.com/repos/BloodHoundAD/AzureHound/releases/latest | grep browser_download_url | egrep -v "sha256" | grep "linux-amd64" | cut -d '"' -f 4`
	curl -L -O -J $azurehound_linux_download
	unzip azurehound-linux-amd64.zip -d azurehound
	rm -f azurehound-linux-amd64.zip
	ln -s /opt/vikingos/cloud/azurehound/azurehound /usr/local/bin/azurehound
	cd /opt/vikingos/windows-uploads
	azurehound_windows_download=`curl -s https://api.github.com/repos/BloodHoundAD/AzureHound/releases/latest | grep browser_download_url | egrep -v "sha256" | grep "windows-amd64" | cut -d '"' -f 4`
	curl -L -O -J $azurehound_windows_download
	unzip azurehound-windows-amd64.zip -d azurehound
	rm -f azurehound-windows-amd64.zip
}

install_awscli() {
	cd /opt/vikingos/cloud
	curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
	unzip awscliv2.zip
	./aws/install
}

install_googlecli() {
	cd /opt/vikingos/cloud
	apt-get install apt-transport-https ca-certificates gnupg curl
	curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
	echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
	apt-get update && apt-get install google-cloud-cli
	gcloud init
}

install_azurecli() {
	cd /opt/vikingos/cloud
	curl -sL https://aka.ms/InstallAzureCLIDeb | bash
	apt-get install ca-certificates curl apt-transport-https lsb-release gnupg
	mkdir -p /etc/apt/keyrings
	curl -sLS https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | tee /etc/apt/keyrings/microsoft.gpg > /dev/null
	chmod go+r /etc/apt/keyrings/microsoft.gpg
	AZ_DIST=$(lsb_release -cs)
	echo "deb [arch=`dpkg --print-architecture` signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ $AZ_DIST main" | tee /etc/apt/sources.list.d/azure-cli.list
	apt-get update
	apt-get install azure-cli

}

#github

install_trufflehog() {
	cd /opt/vikingos/github
	mkdir trufflehog
	cd trufflehog
	curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | grep browser_download_url | grep "linux_amd64" | cut -d '"' -f 4 | xargs -L1 curl -L -O -J
	gunzip truffle*
	tar xf truffle*
	chown root:root trufflehog
	ln -s /opt/vikingos/github/trufflehog/trufflehog /usr/local/bin/trufflehog
}

#phishing

install_set() {
	cd /opt/vikingos/phishing
	git clone https://github.com/trustedsec/social-engineer-toolkit
	cd social-engineer-toolkit
	/usr/share/.pvenv/bin/pip3 install -r requirements.txt
	/usr/share/.pvenv/bin/python3 setup.py
	echo "cd /usr/share/setoolkit && /usr/share/.pvenv/bin/python3 /usr/share/setoolkit/setoolkit" > /usr/local/bin/setoolkit && chmod 555 /usr/local/bin/setoolkit
}

#evasion

install_donut() {
	cd /opt/vikingos/evasion
	git clone http://github.com/thewover/donut
	cd donut
	make 
	ln -s /opt/vikingos/evasion/donut/donut /usr/local/bin/donut
}

install_scarecrow() {
	cd /opt/vikingos/evasion
	git clone https://github.com/optiv/ScareCrow
	cd ScareCrow
	apt-get install -y osslsigncode openssl mingw-w64
	go build ScareCrow.go
	ln -s /opt/vikingos/evasion/ScareCrow/ScareCrow /usr/local/bin/ScareCrow
}

#c2

install_sliver() {
	cd /opt/vikingos/c2
	curl https://sliver.sh/install | bash
}

install_mythic() {
	cd /opt/vikingos/c2
	git clone https://github.com/its-a-feature/Mythic
	cd Mythic
	make
	ln -s /opt/vikingos/c2/Mythic/mythic-cli /usr/local/bin/mythic-cli
}

install_merlin() {
	cd /opt/vikingos/c2
	mkdir merlin
	cd merlin
	wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinServer-Linux-x64.7z
	if [[ $OS == *"ubuntu"* ]]; then
		7zz x -p"merlin" merlinServer-Linux-x64.7z
	else
		7z x -p"merlin" merlinServer-Linux-x64.7z
	fi
	ln -s /opt/vikingos/c2/merlin/merlinServer-Linux-x64 /usr/local/bin/merlinServer
	ln /opt/vikingos/c2/merlin/data/bin/merlinCLI-Linux-x64 /usr/local/bin/merlinCLI
}

install_villain() {
	cd /opt/vikingos/c2
	git clone https://github.com/t3l3machus/Villain
	cd Villain
	python3 -m venv /usr/share/.villain
	/usr/share/.villain/bin/pip3 install -r requirements.txt
	echo '/usr/share/.villain/bin/python3 /opt/vikingos/c2/Villain/Villain.py' > /usr/local/bin/villain && chmod 555 /usr/local/bin/villain 
}

install_havoc() {
	cd /opt/vikingos/c2
	git clone https://github.com/HavocFramework/Havoc.git
	cd Havoc
	apt install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev qtbase5-dev libqt5websockets5-dev python3-dev libboost-all-dev mingw-w64 nasm
	cd teamserver
	go mod download golang.org/x/sys
	go mod download github.com/ugorji/go
	cd ..
	make ts-build
	make client-build
	echo 'cd /opt/vikingos/c2/Havoc && ./havoc "$@"' > /usr/local/bin/havoc && chmod 555 /usr/local/bin/havoc
}

install_poshc2() {
	cd /opt/vikingos/c2
	curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | bash
}

#privesc

install_peassng() {
	cd /opt/vikingos/privesc
	mkdir linpeas
	cd linpeas
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_fat.sh
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_darwin_amd64
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_darwin_arm64
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_linux_386
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_linux_amd64
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_linux_arm
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_linux_arm64
	cd ..
	mkdir winpeas
	cd winpeas
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64_ofs.exe
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx86.exe
	curl -L -O -J https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx86_ofs.exe
	ln -s /opt/vikingos/privesc/linpeas /usr/share/vikingos-resources/linux-uploads/
	ln -s /opt/vikingos/privesc/winpeas /usr/share/vikingos-resources/windows-uploads/
}

#hexeditor
install_okteta() {
	apt-get install -y okteta
}

install_bless() {
	apt-get install -y bless
}

#browsers
install_brave() {
	apt install curl
	curl -fsSLo /usr/share/keyrings/brave-browser-archive-keyring.gpg https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg
	echo "deb [signed-by=/usr/share/keyrings/brave-browser-archive-keyring.gpg] https://brave-browser-apt-release.s3.brave.com/ stable main"|sudo tee /etc/apt/sources.list.d/brave-browser-release.list
	apt update
	apt install -y brave-browser
}

install_chromium() {
	if [[ $OS == *"ubuntu"* ]]; then
		apt-get install -y chromium-browser
	else
		apt-get install -y chromium
	fi
}

#virtualization

install_incus() {
	if [[ `curl -fsSL https://pkgs.zabbly.com/key.asc | gpg --show-keys --fingerprint | grep "4EFC 5906 96CB 15B8 7C73  A3AD 82CC 8797 C838 DCFD"` ]]
	then
		mkdir -p /etc/apt/keyrings/
		curl -fsSL https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc
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
		apt-get install -y incus
	else
		read -p "Something is wrong with the gpg key for the zabbly repo. Please check and install manually. Press any key to resume..."
	fi
}

install_qemu() {
	apt-get install -y qemu-system qemu-user
}

install_libvirt() {
	apt-get install -y libvirt-clients libvirt-daemon-system virtinst
}

#coding

install_vscode() {
	cd /opt/vikingos/coding
	mkdir vscode
	cd vscode
	VSCODE_LINK=`curl -L https://code.visualstudio.com/sha | jq . | grep deb | grep url | grep amd64 | egrep -v insiders | cut -f 4 -d '"'`
	curl -L -O -J $VSCODE_LINK
	PATH=$PATH:/usr/sbin:/sbin dpkg -i *
}

install_nasm() {
	apt-get install -y nasm
}

install_musl() {
	cd /opt/vikingos/coding
	git clone https://git.musl-libc.org/git/musl
	cd musl
	./configure
	make && make install
}

install_perl() {
	apt-get install -y perl
}

install_ruby() {
	apt-get install -y ruby
}

install_python3() {
	apt-get install -y python3
}

install_rust() {
	cd /opt/vikingos/coding
	mkdir rust
	cd rust
	RUSTUP_HOME=/opt/vikingos/coding/rust
	export RUSTUP_HOME
	CARGO_HOME=/opt/vikingos/coding/rust
	export CARGO_HOME
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
	ls /opt/vikingos/coding/rust/bin | xargs -I {} bash -c 'echo "RUSTUP_HOME=/opt/vikingos/coding/rust exec /opt/vikingos/coding/rust/bin/{} \"\$@\" " > /usr/local/bin/{} && chmod 555 /usr/local/bin/{}'
}

install_clang() {
	apt-get install -y clang
}

install_mingw() {
	apt-get install -y mingw-w64
}

install_nim() {
	cd /opt/vikingos/coding
	curl https://nim-lang.org/install_unix.html | grep x64 | egrep -v sha | cut -f 2 -d '"' | xargs -I {} curl -L -O -J https://nim-lang.org/{}
	tar xf nim*
	rm -rf *.tar.xz
	cd nim*
	./install.sh /usr/local/bin
}

#notes

install_ghostwriter() {
	cd /opt/vikingos/notes
	git clone https://github.com/GhostManager/Ghostwriter.git
	cd Ghostwriter
	/sbin/service postgresql stop
	./ghostwriter-cli-linux install
	ln -s /opt/vikingos/notes/Ghostwriter/ghostwriter-cli-linux /usr/local/bin/ghostwriter
}

install_cherrytree() {
	cd /opt/vikingos/notes
	mkdir cherrytree
	cd cherrytree
	curl -s https://api.github.com/repos/giuspen/cherrytree/releases/latest | grep browser_download_url | grep "AppImage" | cut -d '"' -f 4 | xargs -L1 curl -L -O -J
	chmod +x Cherry*
	if [[ $OS == *"ubuntu"* ]]; then
		apt-get install -y libfuse2
	fi
	ls | xargs -I {} ln -s /opt/vikingos/notes/cherrytree/{} /usr/local/bin/cherrytree
}

install_drawio() {
	cd /opt/vikingos/notes
	mkdir drawio
	cd drawio
	curl -s https://api.github.com/repos/jgraph/drawio-desktop/releases/latest | grep browser_download_url | grep "amd64" | grep "deb" | cut -f 4 -d '"' | xargs -L1 curl -L -O -J
	dpkg -i drawio*
}

#net

install_macchanger() {
	cd /opt/vikingos/net
	git clone https://github.com/alobbs/macchanger
	cd macchanger
	./autogen.sh
	./configure
	make && make install
}

install_jdgui() {
	cd /opt/vikingos/coding
	mkdir jd-gui
	cd jd-gui
	curl -s https://api.github.com/repos/java-decompiler/jd-gui/releases/latest | grep browser_download_url | egrep -v "min" | grep "\.jar" | cut -d '"' -f 4 | xargs -L1 curl -L -O -J
	ls | xargs -I {} echo 'java -jar /opt/vikingos/coding/jd-gui/{}' > /usr/local/bin/jd-gui && chmod 555 /usr/local/bin/jd-gui
}

install_nfsserver() {
	if [[ $OS == *"ubuntu"* ]]; then
		apt-get install -y nfs-kernel-server
	else
		apt-get install -y nfs-server
	fi
}

#opensource research

install_harvester() {
	cd /opt/vikingos/opensource-research
	git clone https://github.com/laramies/theHarvester 
	cd theHarvester
	python3 -m venv /usr/share/.harvester
	/usr/share/.harvester/bin/pip3 install -r requirements.txt
	echo '/usr/share/.harvester/bin/python3 /opt/vikingos/opensource-research/theHarvester/theHarvester.py' > /usr/local/bin/harvester && chmod 555 /usr/local/bin/harvester
}


cmd=(dialog --separate-output --checklist "VikingOS\nTake what you need, leave which you don't:" 22 76 16)
options=(nmap "" on
	masscan "" on
	nbtscan "" on
	crackmapexec "" on
	medusa "" on
	hydra "" on
	ncrack "" on
	metasploit "" on
	responder "" on
	flamingo "" on
	sqlmap "" on
	mitm6 "" on
	burpsuite "" on
	zap "" on
	nikto "" on
	wpscan "" on
	feroxbuster "" on
	gobuster "" on
	cewl "" on
	cadaver "" on
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
	seclists "" on
	payloadallthethings "" on
	rockyou "" on
	crackstation-wordlists "" on
	cyberchef "" on
	crunch "" on
	john-the-ripper "" on
	hashcat "" on
	hashcat-rules "" on
	impacket "" on
	bloodhound-sharphound "" on
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
	pspy "" on
	awsbucketdump "" on
	azurehound "" on
	awscli "" on
	azurecli "" on
	googlecli "" on
	trufflehog "" on
	social-engineer-toolkit "" on
	donut "" on
	scarecrow "" on
	sliver "" on
	mythic "" on
	merlin "" on
	villain "" on
	havoc "" on
	poshc2 "" on
	peass-ng "" on
	okteta "" on
	bless "" on
	brave-browser "" on
	chromium-browser "" on
	incus "" on
	qemu "" on
	libvirt "" on
	vscode "" on
	nasm "" on
	musl "" on
	perl "" on
	ruby "" on
	rust "" on 
	clang "" on
	mingw-w64 "" on
	nim "" on
	ghostwriter "" on
	cherrytree "" on
	drawio "" on
	maccahnger "" on
	jd-gui "" on
	theHarvester "" on
	nfs-server "" off)
choices=$("${cmd[@]}" "${options[@]}" 2>&1 >/dev/tty)
clear

apt-get install -y smbclient
apt-get install -y recordmydesktop
apt-get install -y screengrab
apt-get install -y shutter
apt-get install -y curl
apt-get install -y git
apt-get install -y gcc
apt-get install -y make
apt-get install -y cmake
apt-get install -y build-essential
apt-get install -y libssl-dev
apt-get install -y libssh-dev 
apt-get install -y automake
apt-get install -y postgresql-client
apt-get install -y sqlite3 sqlite3-tools
apt-get install -y python3-pip
apt-get install -y wireshark
apt-get install -y openjdk-17-jre openjdk-17-jdk
apt-get install -y ruby-rubygems ruby-dev
apt-get install -y tor
apt-get install -y ssh
apt-get install -y vim
apt-get install -y texinfo
apt-get install -y python3-pip python3-venv
apt-get install -y sshuttle
apt-get install -y gdb
apt-get install -y nfs-common


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
mkdir /opt/vikingos
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

cd /opt/vikingos/coding
mkdir go
cd go
curl -L https://go.dev/dl | grep linux-amd64 | head -1 | cut -f 4 -d '"' | xargs -I {} curl -L -O -J https://go.dev/{}
rm -rf /usr/local/go && tar -C /usr/local -xzf go*
echo "export PATH=\$PATH:/usr/local/go/bin" >> /etc/profile
echo "export PATH=\$PATH:/usr/local/go/bin" >> /etc/bash.bashrc
source /etc/profile

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
		crackmapexec)
			install_crackmapexec
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
		flamingo)
			install_flamingo
			;;
		sqlmap)
			install_sqlmap
			;;
		mitm6)
			install_mitm6
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
		seclists)
			install_seclists
			;;
		payloadallthethings)
			install_payloadallthethings
			;;
		rockyou)
			install_rockyou
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
		bloodhound-sharphound)
			install_bloodhound_sharphound
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
		pspy)
			install_pspy
			;;
		awsbucketdump)
			install_awsbucketdump
			;;
		azurehound)
			install_azurehound
			;;
		awscli)
			install_awscli
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
		donut)
			install_donut
			;;
		scarecrow)
			install_scarecrow
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
		nim)
			install_nim
			;;
		ghostwriter)
			install_ghostwriter
			;;
		cherrytree)
			install_cherrytree
			;;
		drawio)
			install_drawio
			;;
		macchanger)
			install_macchanger
			;;
		jd-gui)
			install_jdgui
			;;
		theHarvester)
			install_harvester
			;;
		nfs-server)
			install_nfsserver
			;;
	esac
done

echo -ne "Thank you for using vikingos! Some tips:\n\n\tIf you installed Mythic, using a root shell run the following command to initalize Mythic: cd /opt/vikingos/c2/Mythic && mythic-cli\n\n\tIf you installed BloodHound, please run the BloodHound command to install all the docker containers and change the password for BloodHound(see https://github.com/SpecterOps/BloodHound for more details)\n\n\tResources for the os are located at /usr/share/vikingos-resources\n\n\t For cyberchef, ubuntu installs firefox and chromium via snapd which chroots those apps. Because of this, they cannot read the file. Use brave to open cyberchef instead or reinstall firefox/chromium without using snapd\n\n"

exit


