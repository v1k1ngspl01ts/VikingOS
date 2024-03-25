# VikingOS
![_5d4be6af-f44a-4de5-8449-3fcfbf95d752](https://github.com/v1k1ngspl01ts/VikingOS/assets/160347797/30fce136-48fd-4974-b203-5776d992b110)

The VikingOS shell script takes a Debian or Ubuntu os and turns it into a penetration testing distro. It has currently been tested on Debian 12 and Ubuntu 22.04. It currently installs the following tools:

Scanning:
   - nmap
   - masscan
   - nbtscan
    
Bruteforce:
   - crackmapexec
   - netexec
   - medusa
   - hydra
   - ncrack

Exploit:
   - metasploit
   - responder
   - flamingo

SQL:
   - sqlmap

Relay:
   - mitm6
    
Web:
   - burpsuite
   - zap
   - nikto
   - wpscan
   - feroxbuster
   - gobuster
   - cewl
   - cadaver
   - web-check

SNMP:
   - onesixtyone
   - snmp(snmpwalk, ect)

DNS:
   - dnsrecon
   - dnsenum

Forensics:
   - sleuthkit
   - volatility
   - binwalk
   - ghidra
   - radare2
   - gdbpeda

Resources:
   - seclists
   - payloadallthethings
   - rockyou
   - crackstation-wordlists
   - cyberchef
    
Password cracking:
   - crunch
   - johntheripper
   - hashcat
   - hashcatrules

Windows:
   - impacket
   - bloodhound/sharphound
   - nidhogg (need a windows machine with VS to build)
   - openldap
   - mimikatz
   - kekeo
   - lazagne
   - sharpcollection
   - powersploit
   - evil-winrm
   - enum4linux
   - pingcastle
   - nanodump
   - kerbrute
   - krbrelayx
   - certipy
   - incognito
   - sysinternals
    
Linux:
   - pspy
   - sshsnake
   - reptile
   - busybox

Cloud:
   - awsbucketdump
   - aws_consoler
   - azurehound
   - awscli
   - googlecli
   - azurecli

Github:
   - trufflehog

Phising:
   - social-engineer-toolkit

Evasion:
   - donut
   - scarecrow

Pivoting:
   - chisel
   - ligolo-ng

C2:
   - sliver
   - mythic
   - merlin
   - villian
   - havoc
   - poshc2

Privesc:
   - peass-ng
    
Hex Editor:
   - okteta
   - bless

Browsers:
   - brave
   - chromium

Virtualization:
   - incus
   - qemu
   - libvirt
   - kubectl

Coding:
   - vscode
   - nasm
   - musl
   - perl
   - ruby
   - python3
   - rust
   - clang
   - mingw
   - nim
   - go
   - jd-gui

Notes:
   - ghostwriter
   - cherrytree
   - obsidian
   - drawio

Net:
   - machanger

Server:
   - nfsserver

Opensource Research:
   - theharvester

Encryption/Password Managers:
   - keepassxc
   - veracrypt
   - bitwarden

From apt repos:
   - smbclient
   - recordmydesktop
   - screengrab
   - shutter
   - postgresql-client
   - sqlite3
   - wireshark
   - tor
   - vim
   - sshuttle
   - gdb
   - 7zip
   - latex

Docker:
   - docker


Docker, ruby, go and all the tools from the apt repos are automatically installed. The rest of the tools can be either select or not select for install when the script is run. 

# Requirements
Debian 12 (or newer)\ 
Ubuntu 22.04 (or newer)\
~55 GB of free space on drive after OS install
