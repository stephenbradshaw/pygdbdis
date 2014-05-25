'''
pygdbdis - Python GDB Disassembly Extensions

Copyright (c) 2014, Stephen Bradshaw
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the organization nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Visit my blog: http://www.thegreycorner.com
'''

from __future__ import with_statement
import gdb
import binascii
import struct
import os
import re
import sys
from fcntl import ioctl
from termios import TIOCGWINSZ
from textwrap import TextWrapper
from inspect import getmembers, isclass
from array import *

global stackFifo
global registerFifo
global disassemblyFifo


program_version="1.20"

# these settings are used when the program initialises, so they havent been added to the user configurable setting list
# change them here if you wish
AUTO_SET_TERMINAL_WIDTH = True # extension will try and set terminal width automatically at init, used to size fifodisplay output



registers64 = [ '$rax', '$rcx', '$rdx', '$rbx', '$rsp', '$rbp', '$rsi', '$rdi', '$rip', '$r8', '$r9', '$r10', '$r11', '$r12', '$r13', '$r14' ]
registers32 = [ '$eax', '$ecx', '$edx', '$ebx', '$esp', '$ebp', '$esi', '$edi', '$eip' ]


# The default program settings are stored in this dictionary
program_default_settings = {
	'fifodir' : [ '/tmp/', 'Directory to store the fifo files for the fifodisplay command' ],
	'stack_fifoname' : [ 'stack', 'Filename of the fifodisplay stack fifo file' ],
	'registers_fifoname' : [ 'registers', 'Filename of the fifodisplay registers fifo file' ],
	'disassembly_fifoname' : [ 'disassembly', 'Filename of the fifodisplay disassembly fifo file' ],
	'min_string_length' : [ 3, 'The number of characters in a row before a value can be considered a string' ],
	'hexdump_column_size' : [ 8 , 'The number of bytes shown per line in hexdump view' ],
	'stack_terminal_width' : [ 80, 'Stack terminal width'],
	'registers_terminal_width' : [ 80, 'Registers terminal width'],
	'disassembly_terminal_width' : [ 80, 'Disassembly terminal width'],
	'stack_terminal_height' : [ 20, 'Stack terminal height'],
	'registers_terminal_height' : [ 20, 'Registers terminal height'], # currently not used
	'disassembly_terminal_height' : [ 20, 'Disassembly terminal height'],
	'main_termal_width' : [ 80, 'Main terminal width' ],
	'remove_fifos_on_exit' : [ False, 'Automatically remove fifodisplay fifos when program exits/restarts' ],
	'set_break_on_entry' : [ True, 'Automatically set a breakpoint on entry when a new objfile is loaded' ]

}


class ExtensionProgramSettings(object):
	"""Class for managing extension settings which are user configurable during runtime"""
	def __init__(self):
		self.settings = {}

	def createValue(self, valueName, valueSetting, valueDescription):
		"""Creates a new setting value"""
		self.settings[valueName] = [ valueSetting, valueDescription ]

	def setValue(self, valueName, valueSetting):
		"""Sets a setting value. Entry must have already been created with createValue."""
		self.settings[valueName][0] = valueSetting

	def setDescription(self, valueName, valueDescription):
		"""Sets a setting description. Entry must have already been created with createValue."""
		self.settings[valueName][1] = valueDescription

	def getValue(self, valueName):
		"""Gets a setting value"""
		return self.settings[valueName][0]

	def getDescription(self, valueName):
		"""Gets the description for a value"""
		return self.settings[valueName][1]		

	def listMatchingSettings(self, value):
		"""Generator providing details of settings whose name contains the given value"""
		for key in sorted(self.settings.iterkeys()):
			if key.find(value) > -1:
				yield [ key, self.settings[key][0], self.settings[key][1] ]

	def printSettings(self, value=None):
		"""Returns settings in printable format"""
		out = []
		if value:
			for item in self.listMatchingSettings(value):
				out.append(str(item[0]) + ' : ' + str(item[1]) + '\nDesc: ' + str(item[2]))
		else:
			for key in sorted(self.settings.iterkeys()):
				out.append(str(key) + ' : ' + str(self.settings[key][0]) + '\nDesc: ' + str(self.settings[key][1]))
		return out

	def listAllSettingNames(self):
		"""Returns a list of all setting names"""
		return sorted(self.settings.iterkeys())



def derefLongFromAddr (addr) :
	"""Get the value pointed by addr"""
	val = gdb.Value(addr).cast(gdb.lookup_type('long').pointer()).dereference()
	return long(val) & faddress_and



def machRegionsParser (regions):
	"""Parses info from mach regions command"""
	mslines=regions.split('\n')
	retarray=[]
	for s in mslines:
		if ( (s.find("0x") > -1) and (s.find("---/") == -1) ):
			addresses=s.split(' ')
			addressparts=addresses[0].split('-')
			startaddress=int(addressparts[0], 16)
			endaddress=int(addressparts[1],16)
			size=endaddress-startaddress
			retarray.append([startaddress, endaddress, size])
	return retarray


def procInfoParser (regions):
	"""Parses info from info proc mappings command"""
	mslines=regions.split('\n')
	retarray=[]
	for s in mslines:
		if (s.find("0x") > -1):
			addresses=s.split()
			startaddress=int(addresses[0], 16)
			endaddress=int(addresses[1],16)
			size=endaddress-startaddress
			retarray.append([startaddress, endaddress, size])
	return retarray


def unicoder(string):
	"""Converts to double byte string"""
	return "\x00".join(string) + "\x00"
	


def makeFifo(filename):
	"""Makes a fifo for use in output redirection"""
	try:
		os.mkfifo(filename)
		print filename
	except OSError, e:
		pass
	
	fifo = open(filename, 'w')
	return fifo
	

def FifoRemover(event):
	RemoveFifo()
	
	
def RemoveFifo():	
	print "Removing fifos"
	try:
		stackFifo.close()
		registerFifo.close()
		disassemblyFifo.close()
	except:
		pass
	try:
		os.remove(ExtensionSettings.getValue('fifodir') + ExtensionSettings.getValue('stack_fifoname'))
		os.remove(ExtensionSettings.getValue('fifodir') + ExtensionSettings.getValue('registers_fifoname'))
		os.remove(ExtensionSettings.getValue('fifodir') + ExtensionSettings.getValue('disassembly_fifoname'))
	except: 
		pass


def argumentsParser(args):
	"""Simple command line arguments parser"""
	arguments = []
	if args.find('"') > -1:
		t_arguments = args.split('"')
		for a in t_arguments:
			if a == '' or a == ' ':
				pass
			elif a[-1] == ' ':
				arguments.append(a[:-1])
			else:
				arguments.append(a)
	elif args.find("'") > -1:
		t_arguments = args.split("'")
		for a in t_arguments:
			if a == '' or a == ' ':
				pass
			elif a[-1] == ' ':
				arguments.append(a[:-1])
			else:
				arguments.append(a)
	elif args == ' ':
		pass
	else:
		arguments = args.split(' ')
	return arguments


# from https://gist.github.com/jtriley/1108174
def ioctlGWINSZ(fd):
	"""Helper function to get terminal size"""
	try:
		cr = struct.unpack('hh', ioctl(fd, TIOCGWINSZ, '1234'))
		return cr
	except:
		pass


def getTerminalSize():
	"""Gets terminal size"""
	# from https://gist.github.com/jtriley/1108174
	cr = ioctlGWINSZ(0) or ioctlGWINSZ(1) or ioctlGWINSZ(2)
	if not cr:
		try:
			fd = os.open(os.ctermid(), os.O_RDONLY)
			cr = ioctlGWINSZ(fd)
			os.close(fd)
		except:
			pass
	if not cr:
		try:
			cr = (os.environ['LINES'], os.environ['COLUMNS'])
		except:
			return None
	return [ int(cr[1]), int(cr[0]) ]




def ReadMemHex( address, size ):
	pointer=address.cast(gdb.lookup_type('char').pointer())
	output=""
	for a in range(0,size):
		val1= chr(pointer.dereference().cast(gdb.lookup_type('int')) & 0xff)
		output+=binascii.hexlify(val1)
		pointer+=1
	return output


def ReadMemRaw( address, size ):
	pointer=address.cast(gdb.lookup_type('char').pointer())
	output=[]
	for a in range(0,size):
		val1= chr(pointer.dereference().cast(gdb.lookup_type('int')) & 0xff)
		output.append(val1)
		pointer+=1
	return output




def setBreakAtEntry():
	"""Sets a breakpoint at the programs entry point if a breakpoint does not already exist at that location."""
	file_info=gdb.execute("info file", False, True)
	mslines=file_info.split('\n')
	for s in mslines:
		if s.find("Entry point") > -1:
			address = '*'+s.split(': ')[-1]
			try:
				if address not in [ bp.location for bp in gdb.breakpoints() ]: 
					print 'Setting entry point breakpoint at ' + str(address)
					gdb.Breakpoint(address, gdb.BP_BREAKPOINT)
			except TypeError: # no breakpoints set
				print 'Setting entry point breakpoint at ' + str(address)
				gdb.Breakpoint(address, gdb.BP_BREAKPOINT)
				
					

def ReadMemHexDump( address, lines, leadaddr, columnwidth=8 ):
	pointer=address.cast(gdb.lookup_type('char').pointer())
	sp=pointer
	asciiwidth=columnwidth
	hexwidth=asciiwidth*3
	
	output=""
	for a in range(0,lines):
		
		hexline=""
		asciiline=""
		for b in range(0,asciiwidth):
			v1 = pointer.dereference().cast(gdb.lookup_type('int')) & 0xff
			v2 = binascii.hexlify(chr(v1))
			if ( (v1 > 127) | (v1 == 0x0a) | (v1 == 0x0d) | (v1 == 0x0c) | (v1 == 0x0b) | (v1 == 0) | (v1 == 9) | (v1 == 8) ):
				v1='.'
			else:
				v1=chr(v1)
			hexline+= ' ' + v2
			asciiline+=v1
			pointer+=1
		
		if (leadaddr):
			output+=("0x" + faddress_printf) %(long(sp)) +": "
			sp+=asciiwidth
		output+=hexline+"    "+asciiline+'\n'
		address+=asciiwidth
	return output



def ReadMemAString( address):
	pointer=address.cast(gdb.lookup_type('char').pointer())
	output=""
	while True:
		val1=pointer.dereference().cast(gdb.lookup_type('int')) & 0xff
		pointer+=1
		if ((val1 > 0) & (val1 < 128)):
			output+=chr(val1)
		else:
			break
	return output
		

def ReadMemUString( address):
	pointer=address.cast(gdb.lookup_type('char').pointer())
	output=""
	while True:
		val1=pointer.dereference().cast(gdb.lookup_type('int')) & 0xff
		pointer+=1
		val2=pointer.dereference().cast(gdb.lookup_type('int')) & 0xff
		pointer+=1
		if ((int(val1) > 0) & (int(val1) < 128) & (int(val2) == 0)):
			output+=chr(val1)
		else:
			break
		
	return output
	


def HexToByteArray( hexstring ):
	return array('c', [chr(int((hexstring[i:i+2]),16)) for i in range(0, len(hexstring), 2)])




def NewObjfileHandler(event):
	"""Event handler that runs on new objfile loaded"""
	CheckFileArch()


def CheckFileArch():
	"""Checks file architecture"""
	errorstring = "Could not properly determine program architecture to setup environment."
	global faddress_printf
	global faddress_and
	global stacksize
	global registers


	if bool(ExtensionSettings.getValue('set_break_on_entry')):
		setBreakAtEntry()
	try:
		target_info=gdb.execute("info target", False, True)
		mslines=target_info.split('\n')
		targeti=False
		for s in mslines:
			if s.find("file type") > -1:
				aparts=s.split()
				arch = aparts[3]
				if (aparts[3].find("64") > -1):
					bsize = '64'
					registers=registers64
					faddress_printf="%016x"
					stacksize=8
					faddress_and=0xffffffffffffffff
				else:
					bsize = '32'
					registers=registers32
					faddress_printf="%08x"
					stacksize=4
					faddress_and=0xffffffff
				
				targeti=True
				break
		if (not targeti):
			print errorstring
	except:
		print errorstring
	print 'pygdbdis configured for objfile ' + gdb.objfiles()[0].filename + '.'
	print 'objfile has ' + bsize + ' bit architecture ' + arch



def initExtension():
	"""Extension initialisation function"""
	global ExtensionSettings
	global er
	global osplatform
	
	osplatform = sys.platform

	er = gdb.events
	er.new_objfile.connect(NewObjfileHandler) # installs event handler to check file arch on new objfile
		
	# configure program settings 
	ExtensionSettings = ExtensionProgramSettings()
	for key in program_default_settings.iterkeys():
		ExtensionSettings.createValue(key, program_default_settings[key][0], program_default_settings[key][1])


	[twidth, _] = getTerminalSize()
	
	if AUTO_SET_TERMINAL_WIDTH:
		# making assumption here that terminals are all same width, however user can change manually if desired
		for settings in ExtensionSettings.listMatchingSettings('_terminal_width'):
			ExtensionSettings.createValue(settings[0], int(twidth), settings[2])
	else: # set main terminal width
		ExtensionSettings.createValue('main_termal_width', int(twidth), ExtensionSettings.getDescription('main_termal_width'))

	if len(gdb.objfiles()) > 0:
		CheckFileArch()

	print "pygdbdis " + program_version + " loaded"


initExtension()




def FifoStopHandler(event):
	stackFifo = makeFifo(ExtensionSettings.getValue('fifodir') + ExtensionSettings.getValue('stack_fifoname'))
	registerFifo = makeFifo(ExtensionSettings.getValue('fifodir') + ExtensionSettings.getValue('registers_fifoname'))
	disassemblyFifo = makeFifo(ExtensionSettings.getValue('fifodir') + ExtensionSettings.getValue('disassembly_fifoname'))
	StackPrinter(int(ExtensionSettings.getValue('stack_terminal_height')), fifoname=stackFifo, width=int(ExtensionSettings.getValue('stack_terminal_width')))
	RegisterPrinter(fifoname=registerFifo, width=int(ExtensionSettings.getValue('registers_terminal_width')))
	DisassemblyPrinter(int(ExtensionSettings.getValue('disassembly_terminal_height')), fifoname=disassemblyFifo, width=int(ExtensionSettings.getValue('disassembly_terminal_width')))
	stackFifo.flush()
	registerFifo.flush()
	disassemblyFifo.flush()



def FancyReader( address, hexdump ):
	"""Shows data at given address (as gdb.Value).  Hexdump set to true for hex and ascii"""
	try:
		data = ReadMemAString(address)
		prefix="ASCII: "
	except Exception:
		data=""
		prefix=""
	
	if len(data) < int(ExtensionSettings.getValue('min_string_length')):
		try:
			data = ReadMemUString(address)
			prefix="U: "
		except Exception:
			data=""
			prefix=""
	
	if len(data) < int(ExtensionSettings.getValue('min_string_length')):
		try:
			if hexdump:
				data = ReadMemHexDump(address, 1, False, columnwidth=int(ExtensionSettings.getValue('hexdump_column_size')))
				data=data.replace('\n', '')
			else:
				data = ReadMemHex(address, 16)
			prefix="Hex: "
		except Exception:
			data=""
			prefix=""
	
	return prefix+data




def DisassemblyPrinter( instructions, fifoname='', width=int(ExtensionSettings.getValue('main_termal_width')), wrap=False):
	if (fifoname):
		output=fifoname
	else:
		output=sys.stdout
	print >>output, "=" * 16
	data = gdb.execute("x/" + str(instructions) + "i $pc", False, True)
	if wrap:
		print >>output, data
	else:
		wrapper = TextWrapper() # use TextWrapper to properly deal with tab lengths in output
		wrapper.width = width
		wrapper.drop_whitespace = False
		for line in data.split('\n'):
			out = wrapper.wrap(line)
			if len(out) > 0:
				print >>output, wrapper.wrap(line)[0]
	


def RegisterPrinter(fifoname='', width=int(ExtensionSettings.getValue('main_termal_width')), wrap=False):
	if (fifoname):
		output=fifoname
	else:
		output=sys.stdout
	print >> output, '=' * 16
	for a in registers:
		address_str = gdb.parse_and_eval(a)
		data = FancyReader(address_str, False).split('\n')[0] # no newlines
		oval = ("% 4s - 0x" + faddress_printf + " : %s") %(a, long(address_str.cast(gdb.lookup_type('char').pointer())) & faddress_and, data)
		if wrap:
			print >> output, oval
		else:
			print >> output, oval[:width-2]
	


def StackPrinter( arg, fifoname='', width=int(ExtensionSettings.getValue('main_termal_width')), wrap=False ):
	cstack=gdb.parse_and_eval("$sp")
	count=10
	if (fifoname):
		output=fifoname
	else: 
		output=sys.stdout
		
	if (arg):
		count=int(arg)
	
	print >>output, "=" *16
	for a in range(0,count):
		content = long(cstack.cast(gdb.lookup_type('long').pointer()).dereference()) & faddress_and
		address=gdb.Value(content)
		stackdata = FancyReader(address, True).split('\n')[0] # no newlines
		oval = ("%s: " + faddress_printf + "    %s") %(cstack, content, stackdata)
		if wrap:
			print >>output, oval
		else:
			print >>output, oval[:width-2]
		cstack+=stacksize
	







class SetBreakpointAtEntry(gdb.Command):
	"""Sets a breakpoint at the programs entry point if a breakpoint does not already exist at that location."""

	def __init__ (self):
		gdb.Command.__init__(self, "setbreakpointatentry", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		setBreakAtEntry()

SetBreakpointAtEntry()





class PrintExtensionSettings(gdb.Command):
	"""Prints a list of settings the user can configure at runtime using the changeextensionsetting command. Provide an argument to find matching settings."""

	def __init__ (self):
		gdb.Command.__init__(self, "printextensionsettings", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		val = None
		if len(arg) > 0:
			val = arg
		for line in ExtensionSettings.printSettings(value=val):
			print '-' * 20
			print line
		

PrintExtensionSettings()



class SavePrefixCommand (gdb.Command):
	"Prefix command for saving things."

	def __init__ (self):
		super (SavePrefixCommand, self).__init__ ("save", gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, True)

SavePrefixCommand()


class SaveBreakpointsCommand (gdb.Command):
	"""Save breakpoints to a file.  These breakpoints can then be read back into a new session using the built in gdb 'source' command."""

	def __init__ (self):
		super (SaveBreakpointsCommand, self).__init__ ("save breakpoints", gdb.COMMAND_SUPPORT, gdb.COMPLETE_FILENAME)

	def invoke (self, arg, from_tty):
		if (not arg):
			print "Please provide a filename in which to save breakpoints"
		else:
			with open (arg, 'w') as f:
				bpcount=1
				for bp in gdb.breakpoints():
					print >> f, "break", bp.location,
					if bp.thread is not None:
						print >> f, " thread", bp.thread,
					if bp.condition is not None:
						print >> f, " if", bp.get_condition,
						print >> f
					if not bp.enabled:
						print >> f, "disable " + str(bpcount)
				
					bpcount+=1
					commands = bp.commands
					if commands is not None:
						print >> f, "commands"
						print >> f, commands,
						print >> f, "end"
						print >> f

SaveBreakpointsCommand()



class ReadHexMemory(gdb.Command):
	"""Prints in hex format a given number of bytes from a given address in memory."""
	
	def __init__ (self):
		gdb.Command.__init__(self, "readhexmemory", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		arguments = arg.split(' ')
		if (len(arguments) < 2):
			print "Please provide an address and a size"
		else:
			output=ReadMemHex(gdb.parse_and_eval(str(arguments[0])), int(arguments[1]))
			print output
		
ReadHexMemory()


class ReadHexDumpMemory(gdb.Command):
	"""Prints out a given number of lines (user confgurable) of a hex dump of memory starting at a given address. Each line contains the hex value for each byte as well as its ASCII representation, in a similar fashion as you would see in a Hex editor."""
	
	def __init__ (self):
		gdb.Command.__init__(self, "readhexdumpmemory", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		arguments = arg.split(' ')
		if (len(arguments) < 2):
			print "Please provide an address and a number of lines"
		else:
			output=ReadMemHexDump(gdb.parse_and_eval(str(arguments[0])), int(arguments[1]), True, columnwidth=int(ExtensionSettings.getValue('hexdump_column_size')))
			print output
		
ReadHexDumpMemory()


class ReadString(gdb.Command):
	"""Prints out any string located at a given address in memory.  Works with ASCII and basic Unicode strings."""
	
	def __init__ (self):
		gdb.Command.__init__(self, "readstring", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		if (not arg):
			print "Please provide a memory address to check for a string"
		else:
			char_pointer_type = gdb.lookup_type('char').pointer()
			address_str = gdb.parse_and_eval(arg)
			astring = ReadMemAString(address_str)
			ustring = ReadMemUString(address_str)
			if (len(astring) > 1):
				print "ASCII: " + astring
			if (len(ustring) > 1):
				print "Unicode: " + ustring


ReadString()


class SearchString(gdb.Command):
	"""Searches allocated program memory for a given string, and prints out all discovered instances along with their associated memory addresses.  Works for ASCII and simple Unicode strings.  Only linux and Masc OSX supported.  Warnings may appear when certain sections of memory cannot be searched - these are nothing to worry about."""
	
	def __init__ (self):
		gdb.Command.__init__(self, "searchstring", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		if gdb.selected_thread() == None:
			print 'Please ensure the program is running before searching memory.'
			return

		if not(arg):
			print "Please provide a string to search for"
		else:
			inferior=gdb.selected_inferior()
			supported=True
			if (osplatform == "linux2"):
				mainsec=gdb.execute("info proc mappings", False, True)
				memregions=procInfoParser(mainsec)
			elif (osplatform == "darwin"): #OSX
				mainsec=gdb.execute("info mach-regions", False, True)
				memregions=machRegionsParser(mainsec)
			else:
				supported=False
				print "OS not supported"
			
			if (supported):
				search=str(arg)
				searchu=unicode(search)
				out=[]
				for region in memregions:
					found=True
					while found:
						found=False
						try:
							result = inferior.search_memory(region[0], region[2], search)
							if (isinstance(result, long) & (result < faddress_and) & (result > 0x1)):
								out.append(("0x" + faddress_printf + ": ASCII: %s") % (result, ReadMemAString(gdb.Value(result))))
								found=True
								region[0]=result+1
						except:
							pass

					found=True
					while found:
						found=False
						try:
							result = inferior.search_memory(region[0], region[2], searchu)
							if (isinstance(result, long) & (result < faddress_and) & (result > 0x1)):
								out.append(("0x" + faddress_printf + ": Unicode: %s") % (result, ReadMemUString(gdb.Value(result))))
								found=True
								region[0]=result+1
						except:
							pass

				for line in out:
					print line


SearchString()


class SearchBinary(gdb.Command):
	"""searches allocated program memory for binary data, provided in hex format, e.g. 414243ae. Only linux and Mac OSX supported. Warnings may appear when certain sections of memory cannot be searched - these are nothing to worry about."""
	
	def __init__ (self):
		gdb.Command.__init__(self, "searchbinary", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		if gdb.selected_thread() == None:
			print 'Please ensure the program is running before searching memory.'
			return
		if not(arg):
			print "Please provide a binary value to search for in hex format e.g. 414243ae"
		else:
			supported=True
			inferior=gdb.selected_inferior()
			if (osplatform == "linux2"):
				mainsec=gdb.execute("info proc mappings", False, True)
				memregions=procInfoParser(mainsec)
			elif (osplatform == "darwin"): #OSX
				mainsec=gdb.execute("info mach-regions", False, True)
				memregions=machRegionsParser(mainsec)
			else:
				supported=False
				print "OS not supported"
			
			if (supported):
				search=HexToByteArray(arg)
				out=[]
				for region in memregions:
					found = True
					while found:		
						found = False
						try:
							result = inferior.search_memory(region[0], region[2], search)
							if (isinstance(result, long) & (result < faddress_and) & (result > 0x1)):
								found=True
								out.append(("0x" + faddress_printf + ": %s") % (result, ReadMemHex(gdb.Value(result), len(arg)/2)))
								region[0]=result+1
						except:
							pass
				for line in out:
					print line




SearchBinary()


class PrintStack(gdb.Command):
	"""Prints out a given number of lines of the stack view, including the address, the value stored in memory at that address and, if the stack entry could be interpreted as a pointer, any data (string if possible, hex if not) stored at that address.  If the number of lines is ommitted, a value of 10 is assumed."""
	
	def __init__ (self):
		gdb.Command.__init__(self, "printstack", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		if arg:
			try:
				int(arg)
			except:
				print 'Please provide a valid number as parameter one'
		StackPrinter(arg, wrap=True)

PrintStack()



class PrintRegisters(gdb.Command):
	"""Prints out the registers, along with contextual information of the data located at the memory address stored by each register."""
	
	def __init__ (self):
		gdb.Command.__init__(self, "printregisters", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		RegisterPrinter(wrap=True)
		

PrintRegisters()


class PrintDisassembly(gdb.Command):
	"""Prints out the disassembly for the code located at the instruction pointer register. By default 20 instructions are printed, specify a different number as paramater one to print a different number."""
	
	def __init__ (self):
		gdb.Command.__init__(self, "printdisassembly", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		if arg:
			try:
				instructions=int(arg)
			except Exception:
				pass
		else:
			instructions=20
		DisassemblyPrinter(instructions, wrap=True)

PrintDisassembly()


class PrintExtensionHelp(gdb.Command):
	"""Print out a list of commands included with the extension and descriptions of their usage."""
	
	def __init__ (self):
		gdb.Command.__init__(self, "printextensionhelp", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		# here we get the docstrings and function init paramaters for the gdb.Command classes in this script
		out = {}
		for _, obj in getmembers(sys.modules[__name__], isclass):
			if obj.__module__ == '__main__'  and hasattr(obj, 'invoke'):
				out[obj.__init__.im_func.func_code.co_consts[1]] = obj.__doc__
		for key in sorted(out.iterkeys()):
			print key + " - " + out[key] + '\n'
		
		

PrintExtensionHelp()


class FifoDisplay(gdb.Command):
	"""Registers a number of handlers to automatically run the printstack, printregisters and printdisassembly commands each time the program pauses, and to send the output to fifo pipes created in the tmp directory named stack, registers and disassembly (by default, this is user configurable using the changeextensionsetting command).  Combined with a multiple paned terminal window, can give you useful contextual information while debugging. Use the Stop parameter to disable the handlers."""

	def __init__ (self):
		gdb.Command.__init__(self, "fifodisplay", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		if (arg != "Stop" and arg != "stop" ):
			print "Adding handler.  Use 'fifodisplay stop' to remove."
			er.stop.connect(FifoStopHandler)

			if bool(ExtensionSettings.getValue('remove_fifos_on_exit')):
				print "-----------------------------"
				print 'Adding exit handler for fifos to trigger on program exit/restart.'
				print 'Set remove_fifos_on_exit to False to disable this handler.'
				print "-----------------------------"
				er.exited.connect(FifoRemover)

			sf_val = ExtensionSettings.getValue('fifodir') + ExtensionSettings.getValue('stack_fifoname')
			rf_val = ExtensionSettings.getValue('fifodir') + ExtensionSettings.getValue('registers_fifoname')
			df_val = ExtensionSettings.getValue('fifodir') + ExtensionSettings.getValue('disassembly_fifoname')
			
			
			print "Program execution will now pause while you create fifo listeners\n(e.g. use 'tail -f <filename>')"
			print "-----------------------------"
			print "Create a fifo listener for file " + sf_val + " to display the stack"
			stackFifo = makeFifo(sf_val)
			print "-----------------------------"
			print "Create a fifo listener for " + rf_val + " to display register values"
			registerFifo = makeFifo(rf_val)
			print "-----------------------------"
			print "Create a fifo listener for " + df_val + " to display disassembly information"
			disassemblyFifo = makeFifo(df_val)
			print "-----------------------------"
			print "Done!"
		else:
			try:
				er.stop.disconnect(FifoStopHandler)
				print 'Removed stop handler'
				er.exited.disconnect(FifoRemover)
				print 'Removed exit handler'
			except: 
				pass
			RemoveFifo()


FifoDisplay()




class ChangeExtensionSetting(gdb.Command):
	"""Configures extension configuration settings. Provide an extension configuration option name as parameter one, and the value as parameter two.  List valid settings using printextensionsettings. Values used as file and directory names are not sanity checked so its your responsibility to provide correct values."""

	def __init__ (self):
		gdb.Command.__init__(self, "changeextensionsetting", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		errorstring = 'Please provide a setting and value to configure.  Use printextensionsettings to see valid settings.'
		if len(arg) == 0:
			print errorstring
			return
		arguments = argumentsParser(arg)
		if len(arguments) < 2:
		 	print errorstring
		 	return
		if arguments[0] not in ExtensionSettings.listAllSettingNames():
			print 'Invalid setting name.  Use printextensionsettings to see valid settings.'
			return
		else:
		 	currentVal = ExtensionSettings.getValue(arguments[0])
		 	if type(currentVal) == int:
		 		try:
		 			ExtensionSettings.setValue(arguments[0], int(arguments[1]))
		 		except ValueError:
		 			print 'Value could not be converted to integer. Provide a valid integer.'
		 	elif type(currentVal) == bool:
		 		if arguments[1] == 'True' or arguments[1] == 'true':
		 			bval = True
		 		elif arguments[1] == 'False' or arguments[1] == 'false':
		 			bval = False
		 		else:
		 			print 'Value could not be converted to boolean. Use True/False.'
		 			return
		 		ExtensionSettings.setValue(arguments[0], bval)

		 		if arguments[0] == 'remove_fifos_on_exit' and not bval:
		 			try:
		 				er.exited.disconnect(FifoRemover)
		 				print 'Removed fifodisplay exit/restart handler.'
		 				print 'Fifo files will no longer be automatically closed and deleted on program exit.'
		 			except:
		 				pass
		 	else:
		 		if currentVal[-1] == '/' and arguments[1][-1] !='/':
		 			print 'Please provide trailing slashes on directory names.'
		 		else:
		 			ExtensionSettings.setValue(arguments[0], arguments[1])


ChangeExtensionSetting()


class NextOver(gdb.Command):
	"""Does an assembly level step operation that will skip over 'call' function calls and wont break on new threads."""

	def __init__ (self):
		gdb.Command.__init__(self, "no", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		ci=gdb.execute("x/2i $pc", False, True)
		count=0
		for a in ci.split('\n'):
			if (count==0):
				[_, command] = a.split('>:')
				command = command.replace('\t','')
			elif ('<' in a):
				bits = a.split('<')
				address = bits[0].replace(' ', '')
				
			count+=1
		
		command = re.sub('\s+',' ',command)
		if (command.startswith('call')):
			cbits=command.split(' ')
			gdb.Breakpoint('*'+address, gdb.BP_BREAKPOINT, 0, True) # silent breakpoint
			out = gdb.execute("c", False, True).replace('\n', '')
			[one, two] = out.split(', ')
			print two
			gdb.breakpoints()[-1].delete() # delete last added breakpoint
		else:
			out = gdb.execute("si", False, True).replace('\n', '')
			print out
		
		

		

NextOver()


