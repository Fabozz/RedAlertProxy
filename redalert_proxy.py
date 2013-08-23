import sys
import time
import socket
import select
import argparse
import struct
import math
import serial


parser = argparse.ArgumentParser("ArtemisProxy : proxy between Artemis clients and server, forwards certain events to Arduino")

parser.add_argument("--serverip", type=str, help="Artemis server IP", default='10.0.1.4')
parser.add_argument("--listenip", type=str, help="ip to listen for clients on", default='127.0.0.1')
parser.add_argument("--serial", type=str, help="serial port of Arduino", default='')

args = parser.parse_args()




serverip = args.serverip

ktCount = 0
selectionPacketSent = False

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind((args.listenip, 2010))
serversocket.listen(1)
print "Waiting for connection from client..."
serverSock = None

while True:
	(toClientSock, addr) = serversocket.accept()
	print "got connection from ", addr
	break


#packet header string

splitStr = "\xef\xbe\xad\xde"

print "conecting to artemis server at", serverip
toServerSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)



toServerSock.connect((serverip, 2010))

print "..connected"

ser = None
if len(args.serial):
	print args.serial
	ser = serial.Serial(
		port=args.serial,
		baudrate=9600,
		parity=serial.PARITY_NONE,
		stopbits=serial.STOPBITS_ONE,
		bytesize=serial.EIGHTBITS
	)
if ser:
	print ser.isOpen()
#if len(sys.argv) < 2:
#	usb = None
#else:
#	usb = sys.argv[1]

deadbeef =  "".join([chr(0xef),chr(0xbe), chr(0xad), chr(0xde)])
shipId = 0


def serialSend(msg):
	print 'SERIAL==>' + msg
	if ser:
		ser.write(msg)
		response = ''
		while ser.inWaiting() > 0:
			response += ser.read(1)
		print response

serialSend(" ") 
		

#===============================
def shorthex(message):
	bytes = ""
	for c in message:
		code = ord(c)
		bytes += "%0.2X" % code
	return bytes

def hexdump(message, maxBytes):
	bytes = ""
	chars = ""
	count = 0
	for c in message:
		count += 1
		code = ord(c)
		bytes += "%0.2X" % code
		if count % 4 == 0:
			bytes += " "
		if code >= 32:
			chars += c
		else:
			chars += '.'
		if count == maxBytes:
			break
	while count < maxBytes:
		bytes += "  "
		count += 1
		if count % 4 == 0:
			bytes += " "
	return bytes + "   " + chars

MSG_whatever =	"".join([chr(0xF9),chr(0x3D), chr(0x80), chr(0x80)])
MSG_nothing =	"".join([chr(0x00),chr(0x00), chr(0x00), chr(0x00)])
MSG_update =	"".join([chr(0x01),chr(0xEB), chr(0x03), chr(0x00)])
MSG_comm =		"".join([chr(0x5F),chr(0xC3), chr(0x72), chr(0xD6)])
def parseMessage(message):
	msgType = message[0:4]
	if msgType == MSG_whatever:
		message = message[4:]
		msgType = message[0:4]
	
	if msgType == MSG_nothing:
		return
		
	if msgType == MSG_comm:
		#print ' Comm message'
		return
	
	if msgType[0] == MSG_update[0]:
		ship = ord(msgType[0])
		parseUpdate(message[4:], ship)
		return
	
	#print '=' + hexdump(message, 32)

fieldTypes = {35: ("main screen", 'b', False), 33: ("red alert", 'b', False), 21: ("some movement thing?", 'f', False), 15 : ("energy", 'f', False), 21: ("coordY", 'f', False), 19: ("coordX", 'f', False), 16: ("shield", 'h'), 14: ("warp rate", 'b', False), 10:("rotation rate", 'f', False), 9: ("impulse rate", 'f', False),  23: ("unknown2", 'f'), 25: ("speed", 'f', False), 24: ("rotation", 'f', False), 28: ("frontshield",'f'), 30: ("rearshield", 'f'), 8: ("weaponlock", "i"), 13:("autobeams",'b')}
numLens = { 'f' : 4, 'h' : 2, 'i' : 4, 'b' : 1}
def bitIndex(value):
	result = 0
	while value > 0:
		result += 1
		value = value / 2
	return result


lastFrontShield = 0
lastRearShield = 0

def parseUpdate(message, ship):
	if ship != 1:
		return
	
	if len(message) < 12:
		pass #print '?' + hexdump(message, 32)
	
	fields = []
	values = []
	
	fieldBits = struct.unpack('iii', message[0:12])
	for fieldID in range(96):
		index = int(fieldID / 32)
		test = fieldBits[index]
		bit = 1 << (fieldID - (index * 32))
		if test & bit == bit:
			fields.append(fieldID)
	
	result = " "
	first = True
	index = 12
	
	for fieldID in fields:
		if fieldID in fieldTypes:
			recognized = fieldTypes[fieldID]
		else:
			recognized = None
		
		if recognized:
			name = recognized[0]
			valueSize = numLens[recognized[1]]
			#value = shorthex(message[index:index+valueSize])
			value = struct.unpack(recognized[1], message[index:index+valueSize])[0]
			index += valueSize
			values.append(str(value))
			
			if fieldID == 28:
				if value < lastFrontShield:
					print "FRONT DAMAGE {0}".format(lastFrontShield - value)
					# todo serialSend
				lastFrontShield = value				
			if fieldID == 30:
				if value < lastRearShield:
					print "REAR DAMAGE {0}".format(lastRearShield - value)
					# todo serialSend
				lastRearShield = value				
			
			if fieldID == 16:
				if value > 0:
					print "SHIELDS UP"
					serialSend('S')
				else:
					print "SHIELDS DOWN"
					serialSend('s')
			
			if fieldID == 33:
				if value > 0:
					print "RED ALERT"
					serialSend('R')
				else:
					print "STAND DOWN"
					serialSend('r')
		else:
			name = str(fieldID)
			value = shorthex(message[index:])
		
		if first:
			first = False
		else:
			result += ', '
		result += name + "=" + str(value)
		
	if index < (len(message) - 4):
		result += ' plus ' + shorthex(message[index:-4])
		
	#print result

def processMessage(message):
	if len(message) < 4:
		pass #print '!' + shorthex(message)
	elif message[0:4] == deadbeef:
		pass #print '\\' + hexdump(message, 32)
	else:
		header = struct.unpack('i', message[0:4])
		if header[0] != len(message) - 4:
			pass #print '*' + hexdump(message, 32)
		else:
			parseMessage(message[4:])

def processEnvelopes(packet):
	index = 0
	
#	try:
	while index < (len(packet) - 16):
		if packet[index:index+4] != deadbeef:
			pass #print '~malformed ' + hexdump(packet, 64)
			break
		
		header = struct.unpack('iii', packet[index+4:index+16])
		nextIndex = index + header[0]
		processMessage(packet[index+16:nextIndex])
		index = nextIndex
	if index < len(packet):
		leftovers = len(packet) - index
		pass #print "-LEFTOVERS: %d of %d" % (leftovers, len(packet))
#	except Exception as ex:
#		print str(ex)
#		print '>' + hexdump(packet[index:], 128)
#====================================




print "setting up.."

inputs = [toServerSock, toClientSock]
outputs = []
#data from artemis server to client
buff = ""
#data from artemis client to server
fromClientBuff = ""

#list of packets extracted from stream to client
packets = []
workingPacket = ""
print "..done! Here we go.."

while(True):

	(read, write, fucked) = select.select(inputs, [], [])
	for r in read:
		if r is toServerSock:

			#read the data from the server
			buff = toServerSock.recv(256)
		elif r is toClientSock:
			#read the data from the client
			fromClientBuff = toClientSock.recv(256)
	#scan the buffer for the start string and length
	
	if len(buff) > 0:
		processEnvelopes(buff)

	#now we've processed it we can forward data in its respective directions
	if len(buff) > 0:
		toClientSock.send(buff)
		buff = ""

	if len(fromClientBuff) > 0:
		toServerSock.send(fromClientBuff)
		fromClientBuff = ""







