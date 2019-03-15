import socket, time, sys, pprint
import intellivue

pp = pprint.PrettyPrinter(indent=1)

def die(sock):
	sock.close()
	print('closing socket, goodbye')
	sys.exit()

assoc_request = intellivue.build_assoc_request()
mds_result = intellivue.build_mds_create_event_result()
poll_request = intellivue.build_poll_request()
get_request = intellivue.build_get_prio_list_request()

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_address = ('192.168.1.111', 24105)

def handle_message(data):
	print('received {!r}'.format(data))
	header = data[:2].hex()
	if header == '0ece':
		print('received association accept')
	elif header == 'e100':
		message = intellivue.parse_protocol_command(data)
		print(message)
		if message['ro_type'] == 'ROIV_APDU':
			print('sending mds_result')
			sock.sendto(mds_result, server_address)
			time.sleep(.5)
			print('sending poll_request')
			sock.sendto(poll_request, server_address)
			# print('sending get_request')
			# sock.sendto(get_request, server_address)
		if message['ro_type'] == 'RORS_APDU':
			print('op result')
	elif header == '192e':	
		print('received association abort')
		die(sock)
	else:
		print("I don't know what to do")

def send_assoc():
	print('sending Assoc Request')
	sent = sock.sendto(assoc_request, server_address)

if __name__ == "__main__":
	send_assoc()
	while True:
	    # Receive response
	    print('waiting to receive')
	    data, server = sock.recvfrom(4096)
	    handle_message(data)
