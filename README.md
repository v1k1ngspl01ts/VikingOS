# VikingOS
![_e6a334b7-19c0-4140-8dc3-e47f140ba2c8](https://github.com/v1k1ngspl01ts/VikingOS/assets/160347797/f1ecd534-b998-4f8e-9b2c-f09da8f0ca96)

The VikingOS shell script takes a Debian or Ubuntu os and turns it into a penetration testing distro. It has currently been tested on Debian 12 and Ubuntu 22.04. It currently installs the following tools:

Scanning:
    nmap
    masscan
    nbtscan
    
Bruteforce:
    crackmapexec
    medusa
    hydra
    ncrack

Exploit:
    metasploit
    responder
    flamingo

SQL:
    sqlmap

Relay:
    mitm6
    
Web:
    burpsuite
    zap
    nikto
    wpscan
    feroxbuster
    gobuster
    cewl
    cadaver

SNMP:
    onesixtyone
    snmp* (snmpwalk, ect *)

DNS:
    dnsrecon
    dnsenum

Forensics:
    sleuthkit
    volatility
    binwalk
    ghidra
    radare2
    gdbpeda

Resources:
    seclists
    payloadallthethings
    rockyou
    crackstation-wordlists
    
Password cracking:
    crunch
    johntheripper
    hashcat
    hashcatrules

Windows:
    impacket
    bloodhound/sharphound
    openldap
    mimikatz
    kekeo
    lazagne
    sharpcollection
    powersploit
    evil-winrm
    enum4linux
    pingcastle
    nanodump
    kerbrute
    krbrelayx
    certipy
    
Linux:
    pspy

Cloud:
    awsbucketdump
    azurehound
    awscli
    googlecli
    azurecli

Github:
    trufflehog

Phising:
    social-engineer-toolkit

Evasion:
    donut
    scarecrow

C2:
    sliver
    mythic
    merlin
    villian
    havoc
    poshc2

Privesc:
    peass-ng
    
Hex Editor:
    okteta
    bless

Browsers:
    brave
    chromium

Virtualization:
    incus
    qemu
    libvirt

Coding:
    vscode
    nasm
    musl
    perl
    ruby
    python3
    rust
    clang
    mingw
    nim
    go
    jd-gui

Notes:
    ghostwriter
    cherrytree
    
Server:
    nfsserver

Opensource Research:
    theharvester

From apt repos:
    smbclient
    recordmydesktop
    screengrab
    shutter
    postgresql-client
    sqlite3
    wireshark
    tor
    vim
    sshuttle gdb
    7zip

Docker:
    docker


Docker, ruby, go and all the tools from the apt repos are automatically installed. The rest of the tools can be either select or not select for install when the script is run. 
