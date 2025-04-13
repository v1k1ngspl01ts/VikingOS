# VikingOS
![_5d4be6af-f44a-4de5-8449-3fcfbf95d752](https://github.com/v1k1ngspl01ts/VikingOS/assets/160347797/30fce136-48fd-4974-b203-5776d992b110)

The VikingOS shell script takes a Debian or Ubuntu os and turns it into a penetration testing distro. It has currently been tested on Debian 12 and Ubuntu 22.04. It currently installs the following tools:

Scanning:
   - nmap
   - masscan
   - nbtscan
   - zenmap for windows upload
    
Bruteforce:
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
   - ettercap
   - bettercap
    
Web:
   - burpsuite
   - zap
   - nikto
   - wpscan
   - feroxbuster
   - gobuster
   - cewl
   - cadaver
   - webcheck

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
   - jadx

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
   - bloodhound
   - nidhogg (need to compile on windows)
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
   - godpotato
   - juicypotato
   - printspoofer
   - roguepotato
    
Linux:
   - pspy
   - sshsnake
   - reptile (needs compile)
   - busybox
   - zsh:
     - zellij
     - ohmyzsh

Cloud:
   - awsbucketdump
   - aws-consoler
   - pacu
   - enumerate-iam
   - azurehound
   - awscli
   - AWS SDK
     - npm
     - python boto3
   - googlecli
   - azurecli

Github:
   - trufflehog

Phising:
   - social-engineer-toolkit
   - evilngix2
     - phishlets:
       - n0nUD4Y/Evilginx2-Phishlets
       - ArchonLabs/evilginx2-phishlets

Evasion:
   - donut
   - scarecrow
   - ebowla
   - FilelessPELoader

Pivot:
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
     - vsvode extensions:
	    - github.vscode-pull-request-github
	    - gitlab.gitlab-workflow
	    - ms-python.python
	    - ms-python.vscode-pylance
	    - ms-azuretools.vscode-docker
	    - ms-kubernetes-tools.vscode-kubernetes-tools
	    - hashicorp.terraform
	    - redhat.vscode-yaml
       - ms-vscode-remote.remote-ssh
	    - redhat.ansible
       - ms-vscode-remote.remote-containers
       - platformio.platformio-ide
	    - ms-azuretools.vscode-bicep
	    - ms-vscode.vscode-node-azure-pack
	    - ms-vscode-remote.remote-containers
	    - ms-azure-devops.azure-pipelines
       - ms-azuretools.vscode-docker
       - ms-vscode.cpptools
       - ms-vscode.powershell
       - ms-vscode.cpptools-extension-pack
	    - mongodb.mongodb-vscode
	    - vscjava.vscode-java-pack
	    - sonarsource.sonarlint-vscode
	    - ms-vscode.powershell
	    - atlassian.atlascode
	    - ms-vscode.cpptools
	    - ms-vscode.cpptools-extension-pack
	    - Oracle.oracle-java
	    - vscodevim.vim
       - AmazonWebServices.aws-toolkit-vscode
       - bierner.markdown-mermaid
       - DavidAnson.vscode-markdownlint
       - bierner.markdown-preview-github-styles
       - bierner.markdown-checkbox
       - ms-toolsai.datawrangler
       - ms-toolsai.jupyter
       - astral-sh.ruff
       - njpwerner.autodocstring
       - streetsidesoftware.code-spell-checker
       - humao.rest-client
       - redhat.java
       - esbenp.prettier-vscode
       - christian-kohler.npm-intellisense
       - vscjava.vscode-java-debug
       - ms-vscode.remote-explorer
       - ms-vscode-remote.remote-ssh-edit
       - golang.Go
       - ms-vscode.cmake-tools
       - ms-mssql.mssql
       - vscodevim.vim
   - neovim
     - plugins:
       - vundle
       - mousetrap
       - ultisnips
       - vim-markdown
   - nasm
   - musl
   - perl
   - ruby
   - rust
   - clang
   - mingw
   - nim
   - go
   - jd-gui
   - glab(gitlab cli)
   - confluence cli
   - bitbucket cli
   - jira cli

Notes:
   - ghostwriter
   - cherrytree
   - drawio
   - obsidian
   - sysreptor

Net:
   - macchanger
    
Server:
   - nfsserver
   - HP ilo utility(windows upload)

Opensource Research:
   - theharvester

Encryption/Password Managers:
   - veracrypt
   - keepass
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
   - updates to Viking apt repos
   - screen
   - tmux
   - terminator
   - net-tools
   - xfburn
   - ipmitool
   - open-vm-tools
   - libreoffice
   - gimp
   - vlc
   - klogg
   - softhsm2
   - opensc
   - filezilla
   - samba
   - telnet
   - minicom
   - yubikey-manager
   - yubikey-luks
   - yubikey-piv-tool
   - yubikey-personalization
   - yubikey-personalization-gui
   - yubikey-manager-qt
   - yubioath-desktop
   - gnupg2
   - scdaemon
   - pcscd
   - pcsc-tools
   - scdaemon 
   - gnupg2
   - kleopatra
   - scdaemon 
   - p7zip-full
   - net-tools
   - neovim
   - pynvim
   - uuid-runtime
   - coreutils
   - socat
   - minicom 
   - fzf
   - bat
   - ripgrep
   - dbeaver-ce


Docker:
   - docker


Docker, ruby, go and all the tools from the apt repos are automatically installed. The rest of the tools can be either select or not select for install when the script is run. 

# Requirements
Debian 12 (or newer)\ 
Ubuntu 22.04 (or newer)\
~80 GB of free space on drive after OS install
