#!/usr/bin/env python

from py3270 import Emulator,CommandError,FieldTruncateError,TerminatedError,WaitError,KeyboardStateError,FieldTruncateError,x3270App,s3270App
import platform
from time import sleep

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
		if ''.join(response.data).strip()=="":
		    sleep(0.3)
		    return self.screen_get()
		return response.data

	# Send text without triggering field protection
	def safe_send(self, text):
		for i in xrange(0,len(text)):
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

	def find_field_start_on_row(self,row):
		# This is as usual a horrible hack
		# rows start at 1 (not 0)
		# from what I can tell - if you get a SF(c0=c*) it means a start of field.
		# This is then what we are looking for
		
		for _ in xrange(0,2):
			response = self.exec_command('ReadBuffer(Ascii)')
			if ''.join(response.data).strip()=="":
				sleep(0.3)
			else:
				break
		else:
			if ''.join(response.data).strip()=="":
				raise Exception("Unable to retrieve buffer data")
		for counter, char in enumerate(response.data[row-1].split()):
			if char.startswith("SF(c0=c"):
				return counter+2 # +1 to convert the 0 based index to 1 based
								 # +1 to move to actual field
								 



	# Search the screen for text when we don't know exactly where it is, checking for read errors
	def find_response(self, response):
		ret = self.find_response_xy(response)
		if ret is False:
			return False
		if type(ret)==tuple:
			return True

	# Search the screen for text when we don't know exactly where it is, checking for read errors
	def find_response_xy(self, response):
		for rows in xrange(1,int(self.status.row_number)+1):
			for cols in xrange(1,int(self.status.col_number)+1-len(response)):
				try:
					if self.string_found(rows, cols, response):
						return (cols,rows)
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
		#x3270_executable = 'Windows_Binaries/wc3270.exe'
		x3270App.executable = 'wc3270.exe'
else:
	logger('Your Platform:', platform.system(), 'is not supported at this time.',kind='err')
	sys.exit(1)
