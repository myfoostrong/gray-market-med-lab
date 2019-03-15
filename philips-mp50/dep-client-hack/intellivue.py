def build_assoc_request():
	AssocReqSessionHeader = [0x0D, 0xEC]
	AssocReqSessionData = [0x05, 0x08, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02, 0x80, 0x00, 0x14, 0x02, 0x00, 0x02]
	AssocReqPresentationHeader = [0xC1, 0xDC, 0x31, 0x80, 0xA0, 0x80, 0x80, 0x01, 0x01, 0x00, 0x00, 0xA2, 0x80, 0xA0, 0x03, 0x00, 0x00, 0x01, 0xA4, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0x06, 0x04, 0x52, 0x01, 0x00, 0x01, 0x30, 0x80, 0x06, 0x02, 0x51, 0x01, 0x00, 0x00, 0x00, 0x00, 0x30, 0x80, 0x02, 0x01, 0x02, 0x06, 0x0C, 0x2A, 0x86, 0x48, 0xCE, 0x14, 0x02, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x30, 0x80, 0x06, 0x0C, 0x2A, 0x86, 0x48, 0xCE, 0x14, 0x02, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0xA0, 0x80, 0x60, 0x80, 0xA1, 0x80, 0x06, 0x0C, 0x2A, 0x86, 0x48, 0xCE, 0x14, 0x02, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0xBE, 0x80, 0x28, 0x80, 0x06, 0x0C, 0x2A, 0x86, 0x48, 0xCE, 0x14, 0x02, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x01, 0x02, 0x81]
	AssocReqUserData = [
		0x48, 						# ASNLength
		0x80, 0x00, 0x00, 0x00,		# Protocol Version MDDL_VERSION1
		0x40, 0x00, 0x00, 0x00,		# NomenclaturVersion NOMEN_VERSION
		0x00, 0x00, 0x00, 0x00, 	# FunctionalUnits
		0x80, 0x00, 0x00, 0x00, 	# SystemType SYST_CLIENT
		# 0x00, 0x80, 0x00, 0x00, 	# SystemType SYST_SERVER
		0x20, 0x00, 0x00, 0x00, 	# StartupMode COLD_START
		# 0x40, 0x00, 0x00, 0x00, 	# StartupMode WARM_START
		# 0x80, 0x00, 0x00, 0x00, 	# StartupMode HOT_START
		0x00, 0x00, 0x00, 0x00,		# Option List Count 0 Length 0
		0x00, 0x01, 0x00, 0x2c,		# Supported Profiles Count 1 Length 44
		0x00, 0x01, 0x00, 0x28, 	# AVAType OIDType NOM_POLL_PROFILE_SUPPORT, Length 40
		0x80, 0x00, 0x00, 0x00,		# PollProfileRevision POLL_PROFILE_REV_0
		0x00, 0x00, 0x09, 0xc4, 	# RelativeTime min_poll_period
		0x00, 0x00, 0x09, 0xc4, 	# max_mtu_rx
		0x00, 0x00, 0x03, 0xe8, 	# max_mtu_tx
		0xff, 0xff, 0xff, 0xff, 	# max_bw_tx
		0x60, 0x00, 0x00, 0x00, 	# PollProfileOptions
		0x00, 0x01, 0x00, 0x0c, 	# Optional Packages, Count 1, Length 12
		0xf0, 0x01, 0x00, 0x08, 	# AVAType, OIDType NOM_ATTR_POLL_PROFILE_EXT, Length 8
		0x20, 0x00, 0x00, 0x00, 	# PollProfileExtOptions  POLL_EXT_PERIOD_NU_AVG_60SEC
		0x00, 0x00, 0x00, 0x00]		# Count 0, Length 0
	AssocReqPresentationTrailer = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

	return bytes(AssocReqSessionHeader + AssocReqSessionData + AssocReqPresentationHeader + AssocReqUserData + AssocReqPresentationTrailer)

def build_poll_request():
	session_id = [0xE1, 0x00]
	p_context_id = [0x00, 0x02]
	ro_type = [0x00, 0x01]		#ROIV_APDU
	length = [0x00, 0x1c]
	invoke_id = [0x00, 0x01]
	command_type = [0x00, 0x07] 	#CMD_CONFIRMED_ACTION
	roi_length = [0x00, 0x16]
	m_obj_class = [0x00, 0x21]		#NOM_MOC_VMS_MDS
	context_id = [0x00, 0x00]
	handle = [0x00, 0x00]
	scope = [0x00, 0x00, 0x00, 0x00]
	action_type = [0x0c, 0x16]		#NOM_ACT_POLL_MDIB_DATA
	action_length = [0x00, 0x08]
	poll_number = [0x00, 0x01]
	partition = [0x00, 0x01]		#NOM_PART_OBJ
	# code = [0x00, 0x06]		#NOM_MOC_VMO_METRIC_NU
	# code = [0x00, 0x36]			#NOM_MOC_VMO_AL_MON
	code = [0x00, 0x2A]		#NOM_MOC_PT_DEMOG
	polled_attr_grp = [0x00, 0x00]		#all attribute groups
	return bytes(session_id + p_context_id + ro_type + length + invoke_id + command_type + roi_length + m_obj_class + context_id + handle + scope + action_type + action_length + poll_number + partition + code + polled_attr_grp)

def build_mds_create_event_result():
	mds_sppdu = [0xe1, 0x00, 0x00, 0x02]
	mds_roapdus = [0x00, 0x02, 0x00, 0x14]
	mds_rorsapdu = [0x00, 0x01, 0x00, 0x01, 0x00, 0x0e]
	mds_event_report = [0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x47, 0x00, 0x0d, 0x06, 0x00, 0x00]
	return bytes(mds_sppdu + mds_roapdus + mds_rorsapdu + mds_event_report)

def build_get_prio_list_request():
	session_id = [0xE1, 0x00]
	p_context_id = [0x00, 0x02]
	ro_type = [0x00, 0x01]		#ROIV_APDU
	length = [0x00, 0x18]
	invoke_id = [0x00, 0x00]
	command_type = [0x00, 0x03] 	#CMD_CONFIRMED_ACTION
	roi_length = [0x00, 0x12]
	m_obj_class = [0x00, 0x21]		#NOM_MOC_VMS_MDS
	context_id = [0x00, 0x00]
	handle = [0x00, 0x00]
	scope = [0x00, 0x00, 0x00, 0x00]
	count = [0x00, 0x02]
	attr_length = [0x00, 0x04]
	oid_type = [0xf2, 0x39]			#NOM_ATTR_POLL_RTSA_PRIO_LIST
	oid_type2 = [0xf2, 0x28]			#NOM_ATTR_POLL_RTSA_PRIO_LIST
	return bytes(session_id + p_context_id + ro_type + length + invoke_id + command_type + roi_length + m_obj_class + context_id + handle + scope + count + attr_length + oid_type + oid_type2)

def build_set_prio_list_request():
	session_id = [0xE1, 0x00]
	p_context_id = [0x00, 0x02]
	ro_type = [0x00, 0x01]		#ROIV_APDU
	length = [0x00, 0x00]
	invoke_id = [0x00, 0x00]
	command_type = [0x00, 0x05] 	#CMD_CONFIRMED_SET
	roi_length = [0x00, 0x00]
	m_obj_class = [0x00, 0x21]		#NOM_MOC_VMS_MDS
	context_id = [0x00, 0x00]
	handle = [0x00, 0x00]
	scope = [0x00, 0x00, 0x00, 0x00]
	count = [0x00, 0x01]
	attr_length = [0x00, 0x00]
	modify_operator = [0x00, 0x00]
	oid_type = [0x09, 0x5d]			#NOM_ATTR_PT_NAME_GIVEN
	oid_length = [0x00,0x00]
	return bytes(session_id + p_context_id + ro_type + length + invoke_id + command_type + roi_length + m_obj_class + context_id + handle + scope + count + attr_length + modify_operator + oid_type + oid_length)


def big_int(data):
	return int.from_bytes(data, byteorder='big')






def parseIndicationEvent(data):
	nomen = data[:4].hex()
	print("Nomenclature: ", nomen)
	ro_type = data[4:6].hex()
	print("RO Type: ", ro_type)
	length = int.from_bytes(data[6:8], byteorder='big')
	print("Total Message Length: ", length)

	invoke_id = data[8:10].hex()
	print("invoke_id: ", invoke_id)
	command_type = data[10:12].hex()
	print("command_type: ", command_type)
	length2 = int.from_bytes(data[12:14], byteorder='big')
	print("Rest of message length: ", length2)

	m_obj_class = data[14:16].hex()
	print("m_obj_class: ", m_obj_class)
	context_id = data[16:18].hex()
	print("context_id: ", context_id)
	handle = data[18:20].hex()
	print("handle: ", handle)
	event_time = int.from_bytes(data[20:24], byteorder='big')
	print("event_time: ", event_time)
	event_type = data[24:26].hex()
	print("event_type: ", event_type)
	length3 = int.from_bytes(data[26:28], byteorder='big')
	print("Rest of message length: ", length3)
	parse_attribute_list(data[28:])

def parse_protocol_command(data):
	message = dict()
	message['session_id'] = data[:2].hex()		#u_16, always 0xE100
	message['p_context_id'] = int.from_bytes(data[2:4], byteorder='big')	#u_16
	ro_type = data[4:6].hex()	#u_16
	dispatch = {
		'0001' : parse_op_invoke,
		'0002' : parse_op_result,
		'0003' : parse_op_error,
		'0005' : parse_op_linked_result
	}
	message['length'] = int.from_bytes(data[6:8], byteorder='big')
	return dispatch[ro_type](message,data[8:])

def parse_op_invoke(message,data):
	message['ro_type'] = "ROIV_APDU"
	invoke = dict()
	invoke['invoke_id'] = data[:2].hex()
	command_type = parse_command_type(data[2:4])
	invoke['command_type'] = command_type
	invoke['length'] = big_int(data[4:6])
	if invoke['command_type'] == 'CMD_CONFIRMED_EVENT_REPORT':
		invoke['event_report'] = parse_event_report(data[6:])
	else:
		invoke['data'] = data[6:]
	message['invoke'] = invoke
	return message

def parse_op_result(message,data):
	message['ro_type'] = "RORS_APDU"
	invoke_id = data[:2].hex()
	command_type = parse_command_type(data[2:4])
	length = big_int(data[4:6])
	rors_apdu = {'invoke_id': invoke_id, 'command_type': command_type, 'length':length}
	message['rors_apdu'] = rors_apdu
	if command_type == 'CMD_CONFIRMED_ACTION':
		message['action_result'] = parse_action_result(data[6:])
	elif command_type == 'CMD_GET':

		message['get_result'] = parse_get_result(data[6:])
	else:
		message['data'] = data[16:]
	return message

def parse_action_result(data):
	m_obj_class = parse_managed_obj(data[:6])
	action_type = define_action(data[6:8])
	length = big_int(data[8:10])
	action_result = {'m_obj_class': m_obj_class, 'action_type': action_type, 'length':length}
	print('shit')
	if action_type == 'NOM_ACT_POLL_MDIB_DATA':
		action_result['poll_mdib_data_reply'] = parse_poll_data(data[10:])
	else:
		action_result['data'] = data[10:]
	return action_result

def parse_get_result(data):
	managed_object = parse_managed_obj(data[:6])
	attributes = parse_attribute_list(data[6:])
	return {'managed_object': managed_object, 'attributes': attributes}

def parse_poll_data(data):
	poll_number = big_int(data[:2])
	rel_time_stamp = parse_rel_time(data[2:6])
	abs_time_stamp = parse_abs_time(data[6:14])
	polled_obj_type = parse_system_type(data[14:18])
	polled_attr_grp = parse_oid_type(data[18:20])
	return {
		'rel_time_stamp': rel_time_stamp,
		'abs_time_stamp': abs_time_stamp,
		'polled_obj_type': polled_obj_type,
		'polled_attr_grp': polled_attr_grp,
		'poll_info_list': parse_poll_info_list( data[20:] )
	}

def parse_op_linked_result(message,data):
	message['ro_type'] = "ROLRS_APDU"
	return message

def parse_op_error(message,data):
	message['ro_type'] = "ROLRS_APDU"
	remote_error = dict()
	remote_error['invoke_id'] = data[:2]	# u_16 
	error_value = int.from_bytes(data[2:4], byteorder='big')	# u_16
	errors = ["NO_SUCH_OBJECT_CLASS",
		"NO_SUCH_OBJECT_INSTANCE",
		"ACCESS_DENIED",
		"INVALID ERROR CODE",
		"INVALID ERROR CODE",
		"INVALID ERROR CODE",
		"INVALID ERROR CODE",
		"GET_LIST_ERROR",
		"SET_LIST_ERROR",
		"NO_SUCH_ACTION",
		"PROCESSING_FAILURE",
		"INVALID ERROR CODE",
		"INVALID ERROR CODE",
		"INVALID ERROR CODE",
		"INVALID ERROR CODE",
		"INVALID_ARGUMENT_VALUE",
		"INVALID_SCOPE",
		"INVALID_OBJECT_INSTANCE"]
	if error_value < len(errors):
		remote_error['error_value'] = errors[error_value]
	else:
		remote_error['error_value'] = "INVALID ERROR CODE"
	remote_error['length'] = data[4:6]		#u_16

	if remote_error['error_value'] == "INVALID_ARGUMENT_VALUE":
		remote_error['action_result'] = parse_action_result(data[6:])
	elif remote_error['error_value'] == 'GET_LIST_ERROR':
		remote_error['info_list'] = parse_get_list_error(data[6:])
	else:
		remote_error['data'] = data[6:]
	message['remote_error'] = remote_error
	return message

def parse_event_report(data):
	event_report = dict()
	event_report['managed_object'] = parse_managed_obj(data[:6])
	event_report['event_time'] = parse_rel_time(data[6:10])
	event_report['event_type'] = parse_oid_type(data[10:12])
	event_report['length'] = int.from_bytes(data[12:14], byteorder='big')
	if event_report['event_type'] == 'NOM_NOTI_MDS_CREAT':
		event_report['mds_create_info'] = parse_mds_create(data[14:])
	else:
		event_report['data'] = data[14:] #parse_attribute_list(data[14:])
	return event_report

def parse_command_type(data):
	types = {
		0: 'CMD_EVENT_REPORT',
		1: 'CMD_CONFIRMED_EVENT_REPORT',
		3: 'CMD_GET',
		4: 'CMD_SET',
		5: 'CMD_CONFIRMED_SET',
		7: 'CMD_CONFIRMED_ACTION'
	}
	return types[big_int(data)]

def parse_poll_info_list(data):
	total_count = big_int(data[:2])
	length = big_int(data[2:4])
	poll_info_list = {'count':total_count, 'length':length, 'polls':[]}
	ptr = 4
	for i in range(total_count):
		context_id = data[ptr:ptr+2].hex()
		ptr += 2
		count = big_int(data[ptr:ptr+2])
		ptr += 2
		length = big_int(data[ptr:ptr+2])
		ptr += 2
		for j in range(count):
			obj_handle = data[ptr:ptr+2]
			ptr += 2
			attributes = parse_attribute_list(data[ptr:])
			poll = {'context_id': context_id, 'poll_info':{ 'count': count, 'length': length, 'poll': {'handle': obj_handle, 'attributes': attributes}}}
			poll_info_list['polls'].append(poll)
		ptr += length
	return poll_info_list


def parse_get_list_error(data):
	managed_object = parse_managed_obj(data[:6])
	count = big_int(data[6:8])
	length = big_int(data[8:10])
	error_list = {'managed_object':managed_object, 'count':count, 'length':length, 'errors':[]}
	ptr = 10
	for i in range(count):
		errors = {2: 'ATTR_ACCESS_DENIED', 5:'ATTR_NO_SUCH_ATTRIBUTE', 6:'ATTR_INVALID_ATTRIBUTE_VALUE', 24:'ATTR_INVALID_OPERATION', 25:'ATTR_INVALID_OPERATOR'}
		error_status = errors[big_int(data[ptr:ptr+2])]
		attribute_id = parse_oid_type(data[ptr+2:ptr+4])
		error_list['errors'].append({'error_status':error_status, 'attribute_id':attribute_id})
		ptr += 4
	return error_list


# def parse_action_result(data):
# 	action_result = dict()
# 	action_result['managed_object'] = parse_managed_obj(data[:6])
# 	action_result['action_type'] = define_action(data[6:8])
# 	action_result['length'] = int.from_bytes(data[8:10], byteorder='big')		#u_16
# 	action_result['data'] = data[10:]
# 	return action_result

def parse_mds_create(data):
	mds = dict()
	mds['managed_object'] = parse_managed_obj(data[:6])
	mds['attribute_list'] = parse_attribute_list(data[6:])
	return mds

def parse_managed_obj(data):
	return {
		'm_obj_class' : data[:2].hex(),
		'm_obj_inst' : {
			'MdsContext' : data[2:4].hex(),
			'handle' : data[4:6].hex()
		}
	}

def define_action(action):
	action_type = int.from_bytes(action, byteorder='big')
	action_labels = {
		3094 : 'NOM_ACT_POLL_MDIB_DATA',
		61755 : 'NOM_ACT_POLL_MDIB_DATA_EXT'
	}
	try:
		return action_labels[action_type]
	except KeyError:
		return action_type


def parsePoll(data,length):
	print(data, length)
	prof_rev = data[2:6].hex()
	min_poll_period = int.from_bytes(data[6:10], byteorder='big')
	max_mtu_rx = int.from_bytes(data[10:14], byteorder='big')
	max_mtu_tx = int.from_bytes(data[14:18], byteorder='big')
	max_bw_tx = int.from_bytes(data[18:22], byteorder='big')
	prof_options = data[22:26].hex()
	optional = data[22:].hex()

	print("Profile Revision: 0x",prof_rev)
	print("Max MTU_RX/TX MAX_BW:", max_mtu_rx, max_mtu_tx, max_bw_tx)
	print("Profile Options: ",prof_options,"\n")

def parse_protocol_support(data):
	prot = dict()
	count = int.from_bytes(data[:2], byteorder='big')
	prot['count'] = count
	length = int.from_bytes(data[2:4], byteorder='big')
	prot['length'] = length
	block = data[4:]
	prot['list'] = []
	while count > 0:
		app_proto = dict()
		app_proto_id = int.from_bytes(block[:2], byteorder='big')
		if app_proto_id == 1:
			app_proto_id = 'AP_ID_ACSE'
		elif app_proto_id == 5:
			app_proto_id = 'AP_ID_DATA_OUT'
		app_proto['appl_proto'] = app_proto_id
		trans_proto_id = int.from_bytes(block[2:4], byteorder='big')
		if trans_proto_id == 1:
			trans_proto_id = 'TP_ID_UDP'
		app_proto['trans_proto'] = trans_proto_id
		app_proto['port'] = int.from_bytes(block[4:6], byteorder='big')
		app_proto['options'] = block[6:8].hex()
		block = block[8:]
		count -= 1
		prot['list'].append(app_proto)
	return prot

	# 0005 0028 000100035dc00000 000200035dc00000 000100015e290000 000500015e290000 0008000182350000
def parse_network_address(data):
	print("Network Address Info")
	mac = data[:6].hex().upper()
	print("Mac Address: ",mac)
	ip = int.from_bytes(data[6:10], byteorder='big')
	ip = ipaddress.IPv4Address(ip).compressed
	print("IP Address: ",ip)
	sub_mask = int.from_bytes(data[10:14], byteorder='big')
	sub_mask = ipaddress.IPv4Address(sub_mask).compressed
	print("Subnet Mask: ",sub_mask,"\n")

def parse_partition(data):
	parts = {
		"1" : "NOM_PART_OBJ",
		"2": "NOM_PART_SCADA",
		"3" : "NOM_PART_EVT",
		"4" : "NOM_PART_DIM",
		"6" : "NOM_PART_PGRP",
		"8" : "NOM_PART_INFRASTRUCT"
	}
	partNum = str(int.from_bytes(data[:2], byteorder='big'))
	part = parts[partNum]

def parse_system_type(data):
	part = parse_partition(data[:2])
	oid_type = parse_oid_type(data[2:4])
	return {'part':part, 'oid_type':oid_type}

def parse_oid_type(data):
	oid_type = int.from_bytes(data, byteorder='big')
	if oid_type == 4429:
		return "NOM_DEV_MON_PHYSIO_MULTI_PARAM_MDS"
	if oid_type == 3334:
		return 'NOM_NOTI_MDS_CREAT'
	else:
		return oid_type

def parse_product_specification(data):
	prod_spec = dict()
	count = int.from_bytes(data[:2], byteorder='big')
	prod_spec['count'] = count
	length = int.from_bytes(data[2:4], byteorder='big')
	prod_spec['length'] = length
	block = data[4:]
	prod_spec['list'] = []
	while count > 0:
		spec = dict()
		# print(block)
		spec_id = str(int.from_bytes(block[:2], byteorder='big'))
		specs = {
			"0" : "UNSPECIFIED",
			"1" : "SERIAL_NUMBER",
			"2" : "PART_NUMBER",
			"3" : "HW_REVISION",
			"4" : "SW_REVISION",
			"5" : "FW_REVISION",
			"6" : "PROTOCOL_REVISION"
		}
		spec_type = specs[spec_id]
		spec['spec_type'] = spec_type
		comp_id = block[2:4].hex()
		comps = {
			b'\x00\x08'.hex() : "ID_COMP_PRODUCT",
			b'\x00\x10'.hex() : "ID_COMP_CONFIG",
			b'\x00\x18'.hex() : "ID_COMP_BOOT",
			b'\x00\x50'.hex() : "ID_COMP_MAIN_BD",
			b'\x00\x58'.hex() : "ID_COMP_APPL_SW"
		}
		try:
			component_id = comps[comp_id]
		except:
			component_id = comp_id
		length = int.from_bytes(block[4:6], byteorder='big')
		spec['component_id'] = component_id
		spec['length'] = length
		spec['label'] = block[6:6+length]
		block = block[6+length:]
		count -= 1
		prod_spec['list'] = spec

def parse_model(data):
	model = dict()
	manf_length = int.from_bytes(data[:2], byteorder='big')
	manf_label = data[2:2+manf_length]
	model['manufacturer'] = {'length':manf_length, 'label': manf_label}
	model['length'] = int.from_bytes(data[2+manf_length:4+manf_length], byteorder='big')
	model['id'] = data[4+manf_length:]
	return model

def parse_localization(data,length):
	locale = dict()
	syslocal_revision = data[:4].hex()
	lang = int.from_bytes(data[4:6], byteorder='big')
	langs = ["LANGUAGE_UNSPEC",
		"ENGLISH",
		"GERMAN",
		"FRENCH",
		"ITALIAN",
		"SPANISH",
		"DUTCH",
		"SWEDISH",
		"FINNISH",
		"NORWEG",
		"DANISH",
		"JAPANESE",
		"REP_OF_CHINA",
		"PEOPLE_REP_CHINA",
		"PORTUGUESE",
		"RUSSIAN",
		"BYELORUSSIAN",
		"UKRAINIAN",
		"CROATIAN",
		"SERBIAN",
		"MACEDONIAN",
		"BULGARIAN",
		"GREEK",
		"POLISH",
		"CZECH",
		"SLOVAK",
		"SLOVENIAN",
		"HUNGARIAN",
		"ROMANIAN",
		"TURKISH",
		"LATVIAN",
		"LITHUANIAN",
		"ESTONIAN",
		"KOREAN"]
	language = langs[lang]
	form = data[6:8]
	if(form == b'\x00\x0b'):
		form = 'STRFMT_UNICODE_NT' 
	locale['syslocal_revision'] = syslocal_revision
	locale['language'] = language
	locale['form'] = form
	return locale

def parse_sys_id(data):
	return {'length': int.from_bytes(data[:2], byteorder='big'), "id": data[2:].hex()}

def parse_assoc_no(data):
	return data.hex()

def parse_nomenclature(data):
	return {'major': data[:2].hex(), "minor": data[2:].hex()}

def parse_mode_op(data):
	op_mode = data[:2].hex()
	ops = {
		'8000' : 'OPMODE_UNSPEC',
		'4000' : 'MONITORING',
		'2000' : 'DEMO',
		'1000' : 'SERVICE',
		'0002' : 'OPMODE_STANDBY',
		'0001' : 'CONFIG'
	}
	return ops[op_mode]

def parse_app_area(data):
	app = data[:2].hex()
	areas = {
		'0004' : 'AREA_CARDIOLOGY_CARE',
		'0003' : 'AREA_NEONATAL_INTENSIVE_CARE',
		'0000' : 'AREA_UNSPEC',
		'0002' : 'AREA_INTENSIVE_CARE',
		'0001' : 'AREA_OPERATING_ROOM'
	}
	return areas[app]

def parse_line_freq(data):
	line = data[:2].hex()
	freqs = {
		'0000' : 'LINE_F_UNSPEC',
		'0002' : 'LINE_F_50HZ',
		'0001' : 'LINE_F_60HZ'
	}
	return freqs[line]

def parse_safety(data):
	return data.hex()

def parse_altitude(data):
	return int.from_bytes(data[:2], byteorder='big', signed=True)

def parse_mds_gen_info(data):
	count = int.from_bytes(data[:2], byteorder='big')
	length = int.from_bytes(data[2:4], byteorder='big')
	info = {'count': count, 'length': length}
	info['system_pulses'] = []
	#Assuming 1 item...
	choice = data[4:6].hex()
	length = int.from_bytes(data[6:8], byteorder='big')
	system_pulse = parse_managed_obj(data[8:14])
	alarm_source = parse_managed_obj(data[14:20])
	pulse = {'choice': choice, 'length': length, 'system_pulse': system_pulse, 'alarm_source': alarm_source}
	info['system_pulses'].append(pulse)
	return info

def parse_mds_status(data):
	x = data[:2].hex()
	opts = {
		'0000' : 'DISCONNECTED',
		'0006' : 'OPERATING',
		'0001' : 'UNASSOCIATED'
	}
	return opts[x]

def parse_string(data):
	length = int.from_bytes(data[:2], byteorder='big')
	return {'length': length, 'label': data[2:]}

def parse_sys_spec(data):
	total_count = int.from_bytes(data[:2], byteorder='big')
	length = int.from_bytes(data[2:4], byteorder='big')
	spec = {'count': total_count, 'length': length}
	spec['obj_support'] = []
	ptr = 4
	for i in range(total_count):
		component_capab_id = data[ptr:ptr+2]
		ptr += 2
		length = int.from_bytes(data[ptr:ptr+2], byteorder='big')
		ptr += 2
		spec_entry = {'component_capab_id': component_capab_id, 'length': length}
		val = data[ptr:ptr+length]
		ptr += length	
		count = int.from_bytes(val[:2], byteorder='big')
		length = int.from_bytes(val[2:4], byteorder='big')
		aptr = 4
		spec_entry['support'] = []
		for j in range(count):
			supp_entry = {'object_type': parse_system_type( val[aptr:aptr+4] ), 'max_inst': val[aptr+4:aptr+8].hex()}
			spec_entry['support'].append(supp_entry)
		spec['obj_support'].append(spec_entry)
	return spec

def parse_abs_time(data):
	return {'century': data[0],
		'year': data[1],
		'month': data[2],
		'day': data[3],
		'hour': data[4],
		'minute': data[5],
		'second': data[6],
		'sec_fractions': data[7]}

def parse_rel_time(data):
	x = int.from_bytes(data[:4], byteorder='big')
	return x

def parse_pat_measure(data):
	value = data[:4].hex()
	m_unit = parse_oid_type(data[4:6])
	return {'value': value, 'm_unit':m_unit}

def parse_attribute_list(data):
	attrs = dict()
	attrs['count'] = int.from_bytes(data[:2], byteorder='big')
	list_length = int.from_bytes(data[2:4], byteorder='big')
	attrs['length'] = list_length
	ptr = 4
	attr_list = []
	while ptr <= list_length:
		attribute = dict()
		attr_id = data[ptr:ptr+2].hex()
		attribute['attribute_id'] = attr_id
		ptr+=2
		length = int.from_bytes(data[ptr:ptr+2], byteorder='big')
		attribute['length'] = length
		ptr+=2
		val = data[ptr:ptr+length]		
		ptr += length
		if(attr_id == 'f101'):
			attribute['val'] = parse_protocol_support(val)
		elif(attr_id == 'f100'):
			attribute['val'] = parse_network_address(val)
		elif(attr_id == '0986'):
			attribute['system_type'] = parse_system_type(val)
		elif(attr_id == '092d'):
			attribute['val'] = parse_product_specification(val)
		elif(attr_id == '0928'):
			attribute['model'] = parse_model(val)
		elif(attr_id == '0937'):
			attribute['locale'] = parse_localization(val,length)
		elif(attr_id == '0984'):
			attribute['label'] = 'NOM_ATTR_SYS_ID'
			attribute['system_id'] = parse_sys_id(val)
		elif(attr_id == '091d'):
			attribute['label'] = 'NOM_ATTR_ID_ASSOC_NO'
			attribute['association_invoke_id'] = parse_assoc_no(val)
		elif(attr_id == '0948'):
			attribute['label'] = 'NOM_ATTR_NOM_VERS'
			attribute['nomenclature'] = parse_nomenclature(val)
		elif(attr_id == '0946'):
			attribute['label'] = 'NOM_ATTR_MODE_OP'
			attribute['operating_mode'] = parse_mode_op(val)
		elif(attr_id == '090d'):
			attribute['label'] = 'NOM_ATTR_AREA_APPL'
			attribute['application_area'] = parse_app_area(val)
		elif(attr_id == '0935'):
			attribute['label'] = 'NOM_ATTR_LINE_FREQ'
			attribute['line_freq'] = parse_line_freq(val)
		elif(attr_id == '0982'):
			attribute['label'] = 'NOM_ATTR_STD_SAFETY'
			attribute['safety_standard'] = parse_safety(val)
		elif(attr_id == '090c'):
			attribute['label'] = 'NOM_ATTR_ALTITUDE'
			attribute['altitude'] = parse_altitude(val)
		elif(attr_id == 'f1fa'):
			attribute['label'] = 'NOM_ATTR_MDS_GEN_INFO'
			attribute['mds_gen_info'] = parse_mds_gen_info(val)
		elif(attr_id == '09a7'):
			attribute['label'] = 'NOM_ATTR_VMS_MDS_STAT'
			attribute['mds_status'] = parse_mds_status(val)
		elif(attr_id == '091e'):
			attribute['label'] = 'NOM_ATTR_ID_BED_LABEL'
			attribute['bed'] = parse_string(val)
		elif(attr_id == '0985'):
			attribute['label'] = 'NOM_ATTR_SYS_SPECN'
			attribute['sys_spec'] = parse_sys_spec(val)
		elif(attr_id == '0987'):
			attribute['label'] = 'NOM_ATTR_TIME_ABS'
			attribute['abs_datetime'] = parse_abs_time(val)
		elif(attr_id == '098f'):
			attribute['label'] = 'NOM_ATTR_TIME_REL'
			attribute['relative_time'] = parse_rel_time(val)
		elif(attr_id == '0921'):
			attribute['label'] = 'NOM_ATTR_ID_HANDLE'
			attribute['handle'] = val.hex()
		elif(attr_id == '0957'):
			attribute['label'] = 'NOM_ATTR_PT_DEMOG_ST'
			states = {0:'EMPTY', 1:'PRE_ADMITTED', 2:'ADMITTED', 8:'DISCHARGED'}
			attribute['pat_dmg_state'] = states[big_int(val)]
		elif(attr_id == 'f001'):
			attribute['label'] = 'NOM_ATTR_PT_ID_INT'
			attribute['internal_patient_id'] = val.hex()
		elif(attr_id == '0962'):
			attribute['label'] = 'NOM_ATTR_PT_TYPE'
			types = {0:'PAT_TYPE_UNSPECIFIED', 1:'ADULT', 2:'PEDIATRIC',3:'NEONATAL'}
			attribute['patient_type'] = types[big_int(val)]
		elif(attr_id == '0a1e'):
			attribute['label'] = 'NOM_ATTR_PT_PACED_MODE'
			attribute['paced_mode'] = val.hex()
		elif(attr_id == '095d'):
			attribute['label'] = 'NOM_ATTR_PT_NAME_GIVEN'
			attribute['given_name'] = parse_string(val)
		# elif(attr_id == '095f'):
		# 	attribute['label'] = ''
		# 	attribute[''] = parse_rel_time(val)
		elif(attr_id == '095c'):
			attribute['label'] = 'NOM_ATTR_PT_NAME_FAMILY'
			attribute['family_name'] = parse_string(val)
		elif(attr_id == '095a'):
			attribute['label'] = 'NOM_ATTR_PT_ID'
			attribute['patient_id'] = val.hex()
		# elif(attr_id == 'f2e1'):
		# 	attribute['label'] = ''
		# 	attribute[''] = parse_rel_time(val)
		elif(attr_id == 'f129'):
			attribute['label'] = 'NOM_ATTR_PT_NOTES1'
			attribute['patient_notes_1'] = parse_string(val)
		elif(attr_id == 'f12a'):
			attribute['label'] = 'NOM_ATTR_PT_NOTES2'
			attribute['patient_notes_2'] = parse_string(val)
		elif(attr_id == '0961'):
			attribute['label'] = 'NOM_ATTR_PT_SEX'
			attribute['patient_sex'] = val.hex()
		elif(attr_id == '0958'):
			attribute['label'] = 'NOM_ATTR_PT_DOB'
			attribute['patient_dob'] = parse_abs_time(val)
		elif(attr_id == '09d8'):
			attribute['label'] = 'NOM_ATTR_PT_AGE'
			attribute['patient_age'] = parse_pat_measure(val)
		elif(attr_id == '09dc'):
			attribute['label'] = 'NOM_ATTR_PT_HEIGHT'
			attribute['patient_height'] = parse_pat_measure(val)
		elif(attr_id == '09df'):
			attribute['label'] = 'NOM_ATTR_PT_WEIGHT'
			attribute['patient_weight'] = parse_pat_measure(val)
		elif(attr_id == '0956'):
			attribute['label'] = 'NOM_ATTR_PT_BSA'
			attribute[''] = parse_pat_measure(val)
		elif(attr_id == 'f1ec'):
			attribute['label'] = 'NOM_ATTR_PT_BSA_FORMULA'
			bsa = {0:'BSA_FORMULA_UNSPEC', 1:'BSA_FORMULA_BOYD', 2:'BSA_FORMULA_DUBOIS'}
			attribute[''] = bsa[big_int(val)]
		# elif(attr_id == 'f2e2'):
		# 	attribute['label'] = ''
		# 	attribute[''] = parse_rel_time(val)
		# elif(attr_id == 'f2e3'):
		# 	attribute['label'] = ''
		# 	attribute[''] = parse_rel_time(val)

		# elif(attr_id == "f27c"):
		# 	parsePoll(val,length)
		else:
			print(attr_id)
			attribute['val'] = val.hex()
		attr_list.append(attribute)
	attrs['list'] = attr_list
	return attrs


# al = parse_attribute_list(b'\x00\x11\x00\xf4\t\x84\x00\x08\x00\x06\x00\t\xfb\x03I\x12\t\x86\x00\x04\x00\x01\x11M\t\x1d\x00\x02\x00\x1f\t(\x00\x12\x00\x08Philips\x00\x00\x06M8000\x00\tH\x00\x04\x00\x01\x00\x00\t7\x00\x08\x062\x062\x00\x01\x00\x0b\tF\x00\x02@\x00\t\r\x00\x02\x00\x02\t5\x00\x02\x00\x02\t\x82\x00\x02\x00\x02\t\x0c\x00\x02\x01,\xf1\xfa\x00\x14\x00\x01\x00\x10\x00\x01\x00\x0c\x00\x06\xff\xff\xff\xff\x00\x06\xff\xff\xff\xff\t\xa7\x00\x02\x00\x06\t\x1e\x00$\x00"\x00M\x00I\x00C\x00U\x001\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x87\x00\x08 \x18\x07\x17\x14\x17E\x00\t\x8f\x00\x04\x01\x99P\x00\t\x85\x004\x00\x01\x000\x01\x02\x00,\x00\x05\x00(\x00\x01\x00!\x00\x00\x00\x01\x00\x01\x00\x06\x00\x00\x00\xc9\x00\x01\x00\t\x00\x00\x00<\x00\x01\x00*\x00\x00\x00\x01\x00\x01\x006\x00\x00\x00\x01')
# print(al)

if __name__ == "__main__":
	demo_resp = parse_protocol_command(b'\xe1\x00\x00\x02\x00\x02\x00\xe8\x00\x01\x00\x07\x00\xe2\x00!\x00\x00\x00\x00\x0c\x16\x00\xd8\x00\x01%#\xad\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x01\x00*\x00\x00\x00\x01\x00\xc0\x00\x00\x00\x01\x00\xba\x00P\x00\x16\x00\xb4\t!\x00\x02\x00P\tW\x00\x02\x00\x08\n\x1a\x00\x02\x00\x00\xf0\x01\x00\n\x00\t\xfb\x03I\x12\x1ad\x03\x1f\tb\x00\x02\x00\x01\n\x1e\x00\x02\x00\x00\t]\x00\x04\x00\x02\x00\x00\t_\x00\x04\x00\x02\x00\x00\t\\\x00\x04\x00\x02\x00\x00\tZ\x00\x04\x00\x02\x00\x00\xf2\xe1\x00\x04\x00\x02\x00\x00\xf1)\x00\x04\x00\x02\x00\x00\xf1*\x00\x04\x00\x02\x00\x00\ta\x00\x02\x00\x00\tX\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\t\xd8\x00\x06\x00\x7f\xff\xff\t@\t\xdc\x00\x06\x00\x7f\xff\xff\x05`\t\xdf\x00\x06\x00\x7f\xff\xff\x06\xe0\tV\x00\x06\x00\x7f\xff\xff\x05\xc0\xf1\xec\x00\x02\x00\x02\xf2\xe2\x00\x04\x80u \x95\xf2\xe3\x00\x04\x80\x8b\r\x98')

	alerts_resp = parse_protocol_command(b'\xe1\x00\x00\x02\x00\x01\x01\x12\x00\x01\x00\x01\x01\x0c\x00!\x00\x00\x00\x00);o\x00\r\x06\x00\xfe\x00!\x00\x00\x00\x00\x00\x11\x00\xf4\t\x84\x00\x08\x00\x06\x00\t\xfb\x03I\x12\t\x86\x00\x04\x00\x01\x11M\t\x1d\x00\x02\x002\t(\x00\x12\x00\x08Philips\x00\x00\x06M8000\x00\tH\x00\x04\x00\x01\x00\x00\t7\x00\x08\x062\x062\x00\x01\x00\x0b\tF\x00\x02@\x00\t\r\x00\x02\x00\x02\t5\x00\x02\x00\x02\t\x82\x00\x02\x00\x02\t\x0c\x00\x02\x01,\xf1\xfa\x00\x14\x00\x01\x00\x10\x00\x01\x00\x0c\x00\x06\xff\xff\xff\xff\x00\x06\xff\xff\xff\xff\t\xa7\x00\x02\x00\x06\t\x1e\x00$\x00"\x00M\x00I\x00C\x00U\x001\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x87\x00\x08 \x18\x07\x18\x13#A\x00\t\x8f\x00\x04);o\x00\t\x85\x004\x00\x01\x000\x01\x02\x00,\x00\x05\x00(\x00\x01\x00!\x00\x00\x00\x01\x00\x01\x00\x06\x00\x00\x00\xc9\x00\x01\x00\t\x00\x00\x00<\x00\x01\x00*\x00\x00\x00\x01\x00\x01\x006\x00\x00\x00\x01'
	)

	get_resp = parse_protocol_command(b'\xe1\x00\x00\x02\x00\x02\x00\x18\x00\x00\x00\x03\x00\x12\x00!\x00\x00\x00\x00\x00\x01\x00\x08\xf2:\x00\x04\x00\x00\x00\x00'
	)

	err = parse_protocol_command(b'\xe1\x00\x00\x02\x00\x03\x00\x16\x00\x00\x00\x07\x00\x10\x00!\x00\x00\x00\x00\x00\x01\x00\x04\x00\x05\xf1*\x00\x00')

	print(err)