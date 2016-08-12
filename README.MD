usage: cicspwn.py [-h] [-a APPLID] [-i] [-t] [-f] [-p PATTERN] [-U USERID]
                  [-P PASSWORD] [--get-file FILENAME]
                  [--enable-trans ENA_TRANS] [-q] [-u] [-g SURROGAT_USER] [-s]
                  [-l LHOST] [-j JCL]
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
  -s, --submit          Submit JCL to CICS server, default is a reverse shell
                        in REXX
  -l LHOST, --lhost LHOST
                        Remote server to call back to for reverse shell
                        (host:port)
  -j JCL, --jcl JCL     Custom JCL file to provide
