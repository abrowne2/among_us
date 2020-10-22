#author" adam browne (degen)

# 1. get PID
# ps ax | grep "Among" to get the PID....

# 2. get UDP port 
# lsof -p PID
# (try first or second ports for seeing..)

# 3. look for the source port

from scapy.all import *
import struct
import binascii


# packet length constants
VENTING_OR_NEW_HAT = 16
O2_SABOTAGE = 26
MOVEMENT = 22
HANDSHAKE = (3, 4)

def sniff_packets(iface=None):
    sniff(filter="port 22023", prn=process_packet, store=False)

def process_packet(packet):
	if packet.haslayer(UDP):
		udp_layer = packet.getlayer(UDP)
		handleSituations(packet)

#reads all chat, including dead players
def lookForChatMessages(pay):
	if pay.len > 0:
		payload = str(pay)
		last_byte_delimeter = payload.rfind("\\")
		last_byte_delimeter -= 1
		if payload[last_byte_delimeter:][0] == 'r':
			initial = payload[last_byte_delimeter+1:]
			if initial[1] == 'n': # the splicing is due to the byte prefixes
				print("msg: ", initial[1:-1])
			else:
				print("msg: ", initial[4:-1])
			return True
	return False

def lookForPossibleMovement(pay):
	pass

def handleVentOrHat(pay):
	print("event: VENTING / new hat [possible]")	

def handleSabotageO2(pay):
	print("event: O2 / Reactor SABOTAGE [possible]")

def handleSituations(pay):
	isChatMsg = lookForChatMessages(pay)
	if not isChatMsg:
		if len(pay.load) == VENTING_OR_NEW_HAT:
			handleVentOrHat(pay.load)			
		elif len(pay.load) == MOVEMENT:
			lookForPossibleMovement(pay)
		elif len(pay.load) == O2_SABOTAGE:
			handleSabotageO2(pay)
		elif len(pay.load) in HANDSHAKE: # handshakes
			pass

if __name__ == "__main__":
    print("Among Us Analyzer")
    sniff_packets()