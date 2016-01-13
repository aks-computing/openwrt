#!/usr/bin/env python
# encoding: utf-8
#
""" CSV-IP alarm reporting
"""

# System modules
from threading import Condition, Thread, Event
import socket
import signal
import sys
import logging
import logging.handlers
import time
import re
import os
import datetime

# Constants
MAX_RECEIVE_DATA_SIZE = 200
NEW_EVENT_PRIORITY = 10
FAILED_EVENT_PRIORITY = 3
TIME_TO_WAIT_BEFORE_RETRY_CONENCT = 2
TIME_TO_WAIT_BEFORE_RETRY_SEND = 2
LOG_FILE_MAX_BYTES = 51200
LOG_FILE_BACKUP_COUNT = 3
MAX_OUTPUT_STRING_SIZE = 80
CONFIG_FILE_NAME = "/etc/config/csvipalarm"
LOGGER_FILE_NAME = "/var/log/csvipalarm.log"
MANDATORY_PARM_LIST = ["primIP", "primPort"]

# Default LuCI constants
DEFAULT_POLL_INT = 120
DEFAULT_CONNECT_RETRY = 3
DEFAULT_SOCKET_TIMEOUT = 10
DEFAULT_SEND_RETRY = 3
DEFAULT_POLL_FAIL_THRESHOLD = 3
DEFAULT_POLL_MSG = "POLL"
DEFAULT_REBOOT_MSG = "REBOOT"

#TODO handle SIGUSR1 for changing logging level and start, stop, restart, reload config

class SendMsgException(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

class EventQueue:
	def __init__(self):
		self.queue = []
		self.cv = Condition()
		
	def qsize(self):
		with self.cv:
			return len(self.queue)
		
	def peek(self, index):
		with self.cv:
			return self.queue[index]
		
	def enqueue(self,item):
		with self.cv:
			self.queue.append(item)
		
	def dequeue(self,index):
		with self.cv:
			self.queue.remove(self.queue[index])

	def getQueue(self):
		with self.cv:
			return self.queue

class EventSenderThread(Thread):

	def __init__(self, pconcentrator,sconcentrator):
		super(EventSenderThread,self).__init__()
		self.primConcentrator = pconcentrator
		self.secConcentrator = sconcentrator
		self._stop = False

	def stop(self):
		logger.info('stopping %s' %self.name)
		self._stop = True

	def start_again(self):
		logger.info('starting again %s' %self.name)
		self._stop = False
		
	def run(self):
		logger.info('starting %s' %self.name)
		waitforpoll = True
		while self._stop == False:
			while True:
				if waitforpoll:
					logger.info('waiting for  poll %s' %self.name)
					time.sleep(pollInt)
					waitforpoll = False
				with eventCV:
					while not event_queue.qsize() > 0:
						eventCV.wait()
					data = event_queue.peek(0)	
					logger.info('peeking event "%s"' % data)
					if self.primConcentrator != None and self.primConcentrator.isAvailable():
						logger.info('trying to send event thru primConcentrator "%s"' % data)
						if self.primConcentrator.event(data):
							logger.info('dequeue event "%s"' % data)
							event_queue.dequeue(0)
						else:
							logger.info('looks like primConcentrator is not available, updating its status')
							self.primConcentrator.setAvailable(False)
					elif self.secConcentrator != None and self.secConcentrator.isAvailable():
						logger.info('trying to send event thru secConcentrator"%s"' % data)
						if self.secConcentrator.event(data):
							logger.info('dequeue event "%s"' % data)
							event_queue.dequeue(0)
						else:
							logger.info('looks like secConcentrator is not available, updating its status')
							self.secConcentrator.setAvailable(False)
					else:
						logger.info('no concentrator is available')
						waitforpoll = True

class ConcentratorClient:
	def __init__(self, which, IP, port):
		self.IP = IP
		self.port = port
		self.sock = None
		self.available = False
		self.pollFailCount = 0
		self.safe_to_close = True
		self.which = which
		self.socketCV = Condition()
		self.msgCV = Condition()
		self.pollFailEventEnqueued = False
		self.pollingTimer = timer("%sPollTimer" %self.which,pollInt,self.poll)
		self.disconnectTimer = None

	def make_csv(self,data):
		return '%s,%s,%s,%s' %(username,password,accnum, data if data == pollMsg else (("{:<%d}" % MAX_OUTPUT_STRING_SIZE).format(data)))
		
	def isAvailable(self):
		return self.available

	def setAvailable(self, available):
		self.available = available
		
	def isConnected(self):
		return True if self.sock != None else False

	def connect(self):
		logger.info('sock "%s"' %self.sock)
		with self.socketCV:
			if self.sock == None:
				server_address = (self.IP, self.port)
				self.sock = None
				for failure in xrange(connectRetry):		
					logger.info('Connecting to IP %s port %s - attempt %d' % (server_address[0], server_address[1], failure+1))
					try:
						self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						self.sock.settimeout(sendTimeout)
					except socket.error as msg:
						logger.error('socket err %s' % msg)
						self.sock = None
						continue
					try:
						time.sleep(TIME_TO_WAIT_BEFORE_RETRY_CONENCT)
						self.sock.connect(server_address)
						break
					except socket.error as msg:
						logger.error('connect err %s' % msg)
						self.sock.close()
						self.sock = None
						continue
					
				if self.sock is None:
					logger.error('Failed to open socket to server after %d attempts' % connectRetry)
				else:
					logger.info('Connected Client IP %s port %d' % self.sock.getsockname())
					if self.disconnectTimer != None:
						self.disconnectTimer()
					self.disconnectTimer = timer("%sDisconnectTimer"%self.which,sendTimeout, self.disconnect)
			else:
				logger.info('new connect request received - socket already opened - restart disconnect timer')
				if self.disconnectTimer != None:
					self.disconnectTimer()
				self.disconnectTimer = timer("%sDisconnectTimer"%self.which,sendTimeout, self.disconnect)

	def disconnect(self):
		logger.info('IDLE socket timer expired, closing socket %s' %self.which)
		with self.socketCV:
				self.sock.close()
				self.sock = None
				if self.disconnectTimer != None:
					self.disconnectTimer()
			
	def poll(self):
		with self.msgCV, eventCV:
			for failure in xrange(sendRetry):
				logger.info('attempt %d to send poll "%s" to %s' % (failure+1,pollMsg,self.which))
				try:
					self.connect()
					if self.sock != None:
						if self.send_msg(pollMsg) == 0:
							self.pollFailCount = 0
							self.available = True
							self.pollFailEventEnqueued = False
							return
				except (AttributeError, SendMsgException,) as e:
					logger.error('caught exception %s' %e)
					if self.disconnectTimer != None:
						self.disconnectTimer()
			else:
				self.pollFailCount += 1
				logger.error('polling failed %d time(s)' % self.pollFailCount)
				if eventPollFail == 1 and self.pollFailCount >= pollFailThreshold and self.pollFailEventEnqueued == False:
					logger.info('enqueue poll fail event "%s"' % pollMsg)
					self.available = False				
					event_queue.enqueue("POLL FAIL %s" %self.which)
					self.pollFailEventEnqueued = True
					eventCV.notify()


	def send_msg(self, message):
		try:
			message = self.make_csv(message)
			logger.info('sending "%s"' % message)
			self.sock.sendall(message)
				
			# check for echoed response
			data = self.sock.recv(MAX_RECEIVE_DATA_SIZE)
			logger.info('received "%s"' % data)
			
			if data != message:
				raise SendMsgException('sent message "%s" is not echoed correctly, received response is "%s"' % (message, data))
			else:
				logger.info('message successfully sent')
				return 0
		except SendMsgException as e:
			raise SendMsgException(e)
		except:
			#timer has timed-out
			raise SendMsgException('no echo response received in %d seconds' % sendTimeout)		

	def event(self,message):
		rc = False
		with self.msgCV:
			try:
				for failure in xrange(sendRetry):
					logger.info('attempt %d to send message "%s"' % (failure+1,message))
					try:
						self.connect()
						if self.sock != None:
							if self.send_msg(message) == 0:
								rc = True
								break
					except (AttributeError, SendMsgException,) as e:
						logger.error('caught exception %s' %e)
						if self.disconnectTimer != None:
							self.disconnectTimer()
			finally:
				return rc

def sigUSR1_handler(signum, stack):
	logger.info('SIGUSR1 received')
	with eventCV:
		msg = " Date: %s" %datetime.datetime.now()
		msg += "\n Queue Size: %d" % event_queue.qsize()
		msg += "\n Queued Events: %s" %event_queue.getQueue()
		msg += "\n PrimConcentrator Status: %sAvailable" % ("" if primConcentrator != None and primConcentrator.isAvailable() else "Not ")
		msg += "\n  SecConcentrator Status: %sAvailable" % ("" if secConcentrator != None and secConcentrator.isAvailable() else "Not ")
		msg += "\n"
		with open('/etc/csvipalarm_status', 'w') as f:
			f.write(msg)
			
def logger_init(source="default"):
	# create logger
	global logger
	logger = logging.getLogger('CSV-IP-ALARM')
	logger.setLevel(logging.INFO)
	formatter= logging.Formatter('%(asctime)s:%(name)s[%(process)d]:%(levelname)s:%(funcName)s():%(lineno)s - %(message)s')
	if source == "console":
		ch = logging.StreamHandler()
	elif source == "syslog":
		# DO NOT ENABLE DEBUG LOGGING IN SYSLOG MODE.. script goes into infinite loop
		formatter= logging.Formatter('%(name)s[%(process)d]:%(levelname)s:%(funcName)s():%(lineno)s - %(message)s')
		ch = logging.handlers.SysLogHandler(address = '/dev/log')
	else:
		ch = logging.handlers.RotatingFileHandler(filename=LOGGER_FILE_NAME, maxBytes=LOG_FILE_MAX_BYTES, backupCount=LOG_FILE_BACKUP_COUNT)
	ch.setFormatter(formatter)
	logger.addHandler(ch)

def filter_log(data):

	#check if LAN status reporting is enabled
	if eventLanStatus == 1:
		regexp = re.search('kernel: \[[ ]*[0-9]+.[0-9]+\] ralink_soc_eth 10100000.ethernet eth0: port (?P<portnum>[0-3]) link (?P<state>(?:up|down))',data)
		if regexp:
					return ('LAN Port %s %s' % (regexp.group('portnum'),regexp.group('state')))
	
		#check if WAN status reporting is enabled
	if eventWanStatus == 1:
		regexp = re.search('mwan3track: Interface wan \(eth0\.2\) is (?P<state>(?:offline|online))',data)
		if regexp:
	    		return ('WAN %s' % ('down' if regexp.group('state') == 'offline' else 'up'))
					
	#check if 3G/4G status reporting is enabled
	if event3gStatus == 1:
		regexp = re.search('mwan3track: Interface (4g_)?wan6 \(\d*\w*-?\w*\) is (?P<state>(?:offline|online))',data)
		if regexp:
					return ('3G or 4G %s' % ('down' if regexp.group('state') == 'offline' else 'up'))

	#check if Login success reporting is enabled
	if eventLoginSuccess == 1:
		regexp = re.search('(?P<source>(?:dropbear|LUCI))\[?[0-9]*\]?: Password auth succeeded for \'(?P<user>[\w]*)\' from (?P<one>[0-9]+).(?P<two>[0-9]+).(?P<three>[0-9]+).(?P<four>[0-9]+):(?P<port>[0-9]+)',data)
		if regexp:
			return ('%s login success from %03d.%03d.%03d.%03d:%05d for %s' %(('WEB' if regexp.group('source') == 'LUCI' else 'SSH'),int(regexp.group('one')), int(regexp.group('two')), int(regexp.group('three')), int(regexp.group('four')),int(regexp.group('port')),(regexp.group('user'))))

	#check if Login max fail reporting is enabled
	if eventLoginMaxFail == 1:
		regexp = re.search('(?P<source>(?:dropbear|LUCI))\[?[0-9]*\]?: Exit before auth[\w ,\',\(\)]*: Max auth tries reached - user \'(?P<user>[\w ]*)\' from (?P<one>[0-9]+).(?P<two>[0-9]+).(?P<three>[0-9]+).(?P<four>[0-9]+):(?P<port>[0-9]+)',data)
		if regexp:
			return ('%s login max fail from %03d.%03d.%03d.%03d:%05d for %s' %(('WEB' if regexp.group('source') == 'LUCI' else 'SSH'),int(regexp.group('one')), int(regexp.group('two')), int(regexp.group('three')), int(regexp.group('four')),int(regexp.group('port')),('root' if regexp.group('user') == 'root' else 'nonexistent')))

	#check if Login failure reporting is enabled
	if eventLoginFail == 1:
		regexp = re.search('(?P<source>(?:dropbear|LUCI))\[?[0-9]*\]?: Bad password attempt for \'(?P<user>[\w]*)\' from (?P<one>[0-9]+).(?P<two>[0-9]+).(?P<three>[0-9]+).(?P<four>[0-9]+):(?P<port>[0-9]+)', data)
		if regexp:
			return ('%s login failed from %03d.%03d.%03d.%03d:%05d for %s' %(('WEB' if regexp.group('source') == 'LUCI' else 'SSH'),int(regexp.group('one')), int(regexp.group('two')), int(regexp.group('three')), int(regexp.group('four')),int(regexp.group('port')),('root' if regexp.group('user') == 'root' else 'nonexistent')))

		regexp = re.search('(?P<source>(?:dropbear|LUCI))\[?[0-9]*\]?: Login attempt for (?P<user>nonexistent) user from (?P<one>[0-9]+).(?P<two>[0-9]+).(?P<three>[0-9]+).(?P<four>[0-9]+):(?P<port>[0-9]+)', data)
		if regexp:
			return '%s login failed from %03d.%03d.%03d.%03d:%05d for %s' %(('WEB' if regexp.group('source') == 'LUCI' else 'SSH'),int(regexp.group('one')), int(regexp.group('two')), int(regexp.group('three')), int(regexp.group('four')),int(regexp.group('port')),(regexp.group('user')))


	return None

def log_filter_receiver(server_ip):

	logger.info('starting log_filter_receiver')

	# Enqueue Reboot event
	with eventCV:
		logger.info('enqueue Reboot event')
		event_queue.enqueue(rebootMsg)
		eventCV.notify()

	log_filter_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	log_filter_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	# Bind the socket to the address given
	server_address = (server_ip, 10000)
	logger.info('starting up on %s port %s' % server_address)
	log_filter_sock.bind(server_address)
	log_filter_sock.listen(1)

	while True:
		logger.info('waiting for a connection')
		connection, client_address = log_filter_sock.accept()
		try:
			logger.info('client connected: %s %d' % client_address)
			while True:
				data = connection.recv(MAX_RECEIVE_DATA_SIZE)
				logger.debug('received "%s"' % data)
				if data:
					msg = filter_log(data)
					if msg:
						with eventCV:
							logger.info('enqueue event "%s"' % msg)
							event_queue.enqueue(msg)
							eventCV.notify()
				else:
					break
		finally:
			connection.close()

def timer(name, interval, func, *args):
	logger.info("%s timer started" % name)
	stopped = Event()
	def loop():
		while not stopped.wait(interval): # the first call is in `interval` secs
			logger.info("%s timer expired- calling %s" % (name,func))
			func(*args)
	Thread(target=loop,name=name).start()    
	return stopped.set					

def read_file(filename):
	config_file_contents = ""
	try:
		file=open(filename, 'r')
		config_file_contents = file.read()
	except IOError as e:
		logger.error('%s' %e)
	finally:
		file.close()
		return config_file_contents.split("option")

def load_config():

	global primIP 
	global primPort
	global secIP
	global secPort
	global username 
	global password 
	global accnum 
	global pollMsg
	global pollInt 
	global pollFailThreshold
	global connectRetry 
	global sendRetry 
	global sendTimeout 
	global eventLanStatus 
	global eventWanStatus
	global event3gStatus 
	global eventLoginSuccess 
	global eventLoginFail 
	global eventLoginMaxFail 
	global eventPollFail 
	global rebootMsg 
	
	primIP = config['primIP']
	primPort = int(config['primPort'])
	secIP = config['secIP'] if 'secIP' in config else None
	secPort = int(config['secPort']) if 'secPort' in config and config['secPort'] != '' else None
	username = config['username'] if 'username' in config else ""
	password = config['password'] if 'password' in config else ""
	accnum = config['accnum'] if 'accnum' in config else ""
	rebootMsg = config['rebootMsg'] if 'rebootMsg' in config else DEFAULT_REBOOT_MSG
	pollMsg = config['pollMsg'] if 'pollMsg' in config else DEFAULT_POLL_MSG
	pollInt = int(config['pollInt']) if 'pollInt' in config and config['pollInt'] != '' else DEFAULT_POLL_INT
	pollFailThreshold = int(config['pollFailThreshold']) if 'pollFailThreshold' in config and config['pollFailThreshold'] != '' else DEFAULT_POLL_FAIL_THRESHOLD
	connectRetry = int(config['connectRetry']) if 'connectRetry' in config and config['connectRetry'] != '' else DEFAULT_CONNECT_RETRY
	sendRetry = int(config['sendRetry']) if 'sendRetry' in config and config['sendRetry'] != '' else DEFAULT_SEND_RETRY
	sendTimeout = int(config['sendTimeout']) if 'sendTimeout' in config and config['sendTimeout'] != '' else DEFAULT_SOCKET_TIMEOUT
	eventLanStatus = int(config['eventLanStatus']) if 'eventLanStatus' in config else 0
	eventWanStatus = int(config['eventWanStatus']) if 'eventWanStatus' in config else 0
	event3gStatus = int(config['event3gStatus']) if 'event3gStatus' in config else 0
	eventLoginSuccess = int(config['eventLoginSuccess']) if 'eventLoginSuccess' in config else 0
	eventLoginFail = int(config['eventLoginFail']) if 'eventLoginFail' in config else 0
	eventLoginMaxFail = int(config['eventLoginMaxFail']) if 'eventLoginMaxFail' in config else 0
	eventPollFail = int(config['eventPollFail']) if 'eventPollFail' in config else 0
	logger.info(config)
			
def parse_config():
	global config
	splitter = None
	if len(sys.argv) == 3 and str(sys.argv[1]) == "config":
		# first command-line-arg is config then next arg is file name
		config_file_name = str(sys.argv[2])
		logger.info('reading config from file %s' %config_file_name)
		read_from = read_file(config_file_name)
	elif len(sys.argv) >= 3 and str(sys.argv[1]) == "args":
		# first command-line-arg is args then next arg are parameters
		logger.info('reading config from command-line-args')
		read_from = sys.argv[2:]
		splitter = "="
	else:
		# read from UCI config file
		logger.info('reading config from file %s' % CONFIG_FILE_NAME)
		read_from = read_file(CONFIG_FILE_NAME)

	if read_from != "":
		for x in read_from:
			y = x.split(splitter)
			if len(y) >= 2:
				config [y[0]] = y[1][1:len(y[1])-1] if y[1][0] == "\'" and y[1][0] == "\'" else y[1]		

		for y in MANDATORY_PARM_LIST:
			if y not in config or config[y] is "":
				logger.error('mandatory parameters missing')
				break
		else:
			load_config()
			return True
			
	return False
									
try:
	# Set up global variables
	event_queue = EventQueue() 
	receiver = None
	sender = None
	primConcentrator = None
	secConcentrator = None
	config = dict()
	eventCV = Condition()
	
	# set up logging
	logger_init(source="default")
	logger.info('My PID is: %d' %os.getpid())

	# set up USR1 handler	
	signal.signal(signal.SIGUSR1, sigUSR1_handler)

	if parse_config():
		logger.info('starting the service')
		receiver = Thread(target=log_filter_receiver, args=('localhost',), name="LogReceiver")
		receiver.start()
		primConcentrator = ConcentratorClient("primary",primIP,primPort)
		if secIP != None and secPort != None:
			secConcentrator = ConcentratorClient("secondary",secIP,secPort)
		sender = EventSenderThread(primConcentrator,secConcentrator)
		sender.setName("EventSenderThread")
		sender.start()
		
		# this loop is required for handling USR1 signal to report the status
		while True:
			pass
		logger.info('main thread exiting')
	else:
		logger.error('mandatory parameters missing')
except Exception as e:
		logger.info('service is stopped %s' %e)


