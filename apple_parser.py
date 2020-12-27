# https://github.com/furiousMAC/continuity

# https://github.com/hexway/apple_bleee/blob/1f8022959be660b561e6004b808dd93fa252bc90/ble_read_state.py#L387
ble_packets_types = {
    0x01: 'unknown 0x01',
    0x02: 'unknown 0x02',
    0x03: 'airprint',           # https://github.com/furiousMAC/continuity/blob/master/messages/airprint.md
    0x04: 'unknown 0x04',
    0x05: 'airdrop',
    0x06: 'homekit',            # https://github.com/furiousMAC/continuity/blob/master/messages/homekit.md
    0x07: 'airpods',            # https://github.com/furiousMAC/continuity/blob/master/messages/proximity_pairing.md
    0x08: 'hey_siri',           # https://github.com/furiousMAC/continuity/blob/master/messages/hey_siri.md
    0x09: 'airplay',            # https://github.com/furiousMAC/continuity/blob/master/messages/airplay_target.md
    0x10: 'nearby',             # https://github.com/furiousMAC/continuity/blob/master/messages/nearby_info.md
    0x0a: 'airplay_source',     # https://github.com/furiousMAC/continuity/blob/master/messages/airplay_source.md
    0x0b: 'watch_c',            # https://github.com/furiousMAC/continuity/blob/master/messages/magic_switch.md
    0x0c: 'handoff',            # https://github.com/furiousMAC/continuity/blob/master/messages/handoff.md
    0x0d: 'wifi_set',           # https://github.com/furiousMAC/continuity/blob/master/messages/tethering_target.md
    0x0e: 'hotspot',            # https://github.com/furiousMAC/continuity/blob/master/messages/tethering_source.md
    0x0f: 'nearby_action',      # https://github.com/furiousMAC/continuity/blob/master/messages/nearby_action.md
}

# https://github.com/hexway/apple_bleee/blob/1f8022959be660b561e6004b808dd93fa252bc90/ble_read_state.py#L107
# Activity Level codes - https://github.com/furiousMAC/continuity/blob/master/messages/nearby_info.md
phone_states = {
    0x00: 'Activity level is not known',
    0x01: 'Activity reporting is disabled',
    0x02: 'unknown 0x02',
    0x03: 'User is idle',
    0x04: 'unknown 0x04',
    0x05: 'Audio is playing with the screen off',
    0x06: 'unknown 0x06',
    0x07: 'Screen is on',
    0x08: 'unknown 0x08',
    0x09: 'Screen on and video playing',
    0x0a: 'Watch is on wrist and unlocked',
    0x0b: 'Recent user interaction',
    0x0c: 'unknown 0x0c',
    0x0d: 'User is driving a vehicle',
    0x0e: 'Phone call or Facetime',
    0x0f: 'unknown 0x0f',
    #NOTE: removed and usurped by status flags
    # 0x11: 'Home screen',
    # 0x13: 'Off',
    # 0x17: 'Lock screen',
    # 0x18: 'Off',
    # 0x1a: 'Off',
    # 0x1b: 'Home screen',
    # 0x1c: 'Home screen',
    # 0x23: 'Off',
    # 0x47: 'Lock screen',
    # 0x4b: 'Home screen',
    # 0x4e: 'Outgoing call',
    # 0x57: 'Lock screen',
    # 0x5a: 'Off',
    # 0x5b: 'Home screen',
    # 0x5e: 'Outgoing call',
    # 0x67: 'Lock screen',
    # 0x6b: 'Home screen',
    # 0x6e: 'Incoming call',
}

nearby_status_masks = {
    0x01: 'AirPods are connected and the screen is on',
    0x02: 'Authentication Tag is 4 bytes',
    0x04: 'WiFi is on',
    0x08: 'Unknown',
    0x10: 'Authentication Tag is present',
    0x20: 'Apple Watch is locked or not',
    0x40: 'Auto Unlock on the Apple Watch is enabled',
    0x80: 'Auto Unlock is enabled',
}

nearby_action_types = {
	0x01: 'Apple TV Setup',
	0x04: 'Mobile Backup',
	0x05: 'Watch Setup',
	0x06: 'Apple TV Pair',
	0x07: 'Internet Relay',
	0x08: 'WiFi Password',
	0x09: 'iOS Setup',
	0x0A: 'Repair',
	0x0B: 'Speaker Setupd',
	0x0C: 'Apple Pay',
	0x0D: 'Whole Home Audio Setup',
	0x0E: 'Developer Tools Pairing Request',
	0x0F: 'Answered Call',
	0x10: 'Ended Call',
	0x11: 'DD Ping',
	0x12: 'DD Pong',
	0x13: 'Remote Auto Fill',
	0x14: 'Companion Link Proximity',
	0x15: 'Remote Management',
	0x16: 'Remote Auto Fill Pong',
	0x17: 'Remote Display',
}

hey_siri_devices = {
    0x0002: 'iPhone',
    0x0003: 'iPad',
    0x0009: 'MacBook',
    0x000A: 'Watch',
}

airpod_devices = {
    0x0002: 'iPhone',
    0x0003: 'iPad',
    0x0009: 'MacBook',
    0x000A: 'Watch',
}


# private method to add to the device details dict
def __add_details(device,detail,value):
    device.details[detail] = value

def parse_os_wifi_code(code, dev):
    if code == 0x1c:
        if dev == 'MacBook':
            return ('Mac OS', 'On')
        else:
            return ('iOS12', 'On')
    elif code == 0x18:
        if dev == 'MacBook':
            return ('Mac OS', 'Off')
        else:
            return ('iOS12', 'Off')
    elif code == 0x10:
        return ('iOS11', '<unknown>')
    elif code == 0x1e:
        return ('iOS13', 'On')
    elif code == 0x1a:
        return ('iOS13', 'Off')
    elif code == 0x0e:
        return ('iOS13', 'Connecting')
    elif code == 0x0c:
        return ('iOS12', 'On')
    elif code == 0x04:
        return ('iOS13', 'On')
    elif code == 0x00:
        return ('iOS10', '<unknown>')
    elif code == 0x09:
        return ('Mac OS', '<unknown>')
    elif code == 0x14:
        return ('Mac OS', 'On')
    elif code == 0x98:
        return ('WatchOS', '<unknown>')
    else:
        return ('', '')


def process_nearby(data):
    phone_state_id = 0xff
    phone_state = 'Unknown'
    wifi = ''
    _wifi = ''
    os = ''
    phone_status_mask = 0
    masks = []

    try:
        phone_state_id = data[0] & 0b00001111
        phone_state = phone_states[phone_state_id]
    except Exception as e:
        print(e)
        phone_state = "unknown state: " + hex(phone_state_id)

    # nearby status mask
    try:
        phone_status_mask = ( data[0] & 0b11110000 ) >> 4
        #pick each bitwise flag from dict
        masks = [nearby_status_masks[flag] for (index, flag) in enumerate(nearby_status_masks) if (phone_status_mask & 2**index)]
    except Exception as e:
        print(e)

    os, wifi = parse_os_wifi_code(data[1],'')  #we dont know the device type


    Apple = {
        'nearby': {
            'state': phone_state,
            '_state': data[0],
            'masks' : masks,
            '_mask': phone_status_mask,
            'wifi': wifi,
            '_wifi': data[1],
            'os': os
        }
    }

    return Apple

def process_handoff(data):

    clipboard_status = False if data[0] == 0 else True
    seq_num = hex(data[1] << 8 | data[2])
    gcm_auth = hex(data[3])
    payload = data[4:]

    Apple = {
        'handoff': {
            'clipboard': clipboard_status,
            'seq_num': seq_num,
            'gcm_auth': gcm_auth,
            'payload' : payload
        }
    }

    return Apple

def process_nearby_action(data):

    # https://github.com/furiousMAC/continuity/blob/master/messages/nearby_action.md

    Apple = {}
    _action_flags = data[0]
    _action_type = data[1] # 0x8 = wifi_join
    
    #print(_action_flags)
    #print(hex(_action_type))

    try:
        action_type = nearby_action_types[_action_type]
    except Exception as e:
        action_type = "unknown"


    if _action_type == 0x08:
        auth_tag = data[2] << 16 | data[3] << 8 | data[4]

        appleID =  hex(data[5] << 16 | data[6] << 8 | data[7])        # sha256
        phoneNum = hex(data[8] << 16 | data[9] << 8 | data[10])       # sha256
        email =    hex(data[11] << 16 | data[12] << 8 | data[13])     # sha256
        ssid =     hex(data[14] << 16 | data[15] << 8 | data[16])     # sha256
    
        Apple = {
            'nearby_action': {
                'action_type': action_type,
                '_action_type': _action_type,
                'auth_tag': auth_tag,
                'appleID': appleID,
                'phoneNum': phoneNum,
                'email': email,
                'ssid': ssid 
            }
        }
    else:
        Apple = {
            'nearby_action': {
                'action_type': action_type,
                '_action_type': _action_type,
                'payload': data[2:]
            }
        }
    return Apple

def process_hey_siri(data):
    # https://github.com/furiousMAC/continuity/blob/master/messages/hey_siri.md

    Apple = {}
    _action_flags = data[0]
    _action_type = data[1] # 0x8 = wifi_join
    
    try:
        action_type = nearby_action_types[_action_type]
    except Exception as e:
        action_type = "unknown"

    if _action_type == 0x08:
        phash = data[2] << 8 | data[3]

        snr = data[4]
        confidence = data[5]
        _device_class = data[6] << 8 | data[7]
        try:
            device_class = hey_siri_devices[_device_class]
        except Exception as e:
            device_class = "unknown"

        
        unknown = data[8] # random data byte supposedly?

        Apple = {
            'hey_siri': {
                'action_type': action_type,
                '_action_type': _action_type,
                'phash': phash,
                'snr': snr,
                'confidence': confidence,
                'device_class': device_class,
                '_device_class': _device_class,
                'unknown': unknown 
            }
        }
    else:
        Apple = {
            'hey_siri': {
                'action_type': action_type,
                '_action_type': _action_type,
                'payload': data[2:]
            }
        }
    return Apple


def process_airpods(data):
    # https://github.com/furiousMAC/continuity/blob/master/messages/proximity_pairing.md

    Apple = {}

    _undef1 = data[0]    # 0x01
    _device_model = data[1] << 8 | data[2]
    _status = data[3] 
    _batteryRL = data[4]
    _power = data[5]    # '? C R L xxxx' xxxx = case battery
    _lid = data[6]
    _color = data[7]
    _undef2 = data[8]   # 0x00
    _payload = data[9:]
    
    batteryR = (data[4] & 0b11110000) >> 4
    batteryL = (data[4] & 0b00001111)

    C = (data[5] & 0b01000000) >> 7
    R = (data[5] & 0b00100000) >> 6
    L = (data[5] & 0b00010000) >> 5
    case_power = (data[5] & 0b00001111)

    try:
        device_model = airpod_devices[_device_model]
    except Exception as e:
        device_model = "unknown"

    Apple = {
        'airpods': {
            '_undef1': _undef1,
            '_device_model': _device_model,
            'device_model': device_model,
            '_status': _status,
            '_batteryRL': _batteryRL,
            'battery': {
                'R': batteryR,
                'L': batteryL,
            },
            '_power': _power,
            'charging': {
                'case': C,
                'R': R,
                'L': L,
            },
            'case_power': case_power,
            '_lid': _lid,
            '_color': _color,
            '_undef2': _undef2,
            '_payload': _payload,
        }
    }

    return Apple



###########################################################################################
def do_apple_decode(device):
    mf_id = next(iter(device.details['ManufacturerData']))
    mf_data=device.details['ManufacturerData'][mf_id]
    # https://github.com/hexway/apple_bleee/blob/master/ble_read_state.py
    # https://github.com/furiousMAC/continuity/blob/master/messages/nearby_info.md

    action = mf_data[0]
    length = mf_data[1]
    data = mf_data[2:length]

    #print("Action:",hex(action),"Len:",hex(length))

    Apple = {}

    if len(mf_data) > length+2:
        print("WARNING: manufacturers data is greater than one action")
        # TODO: split and run multiple times?

    try:
        device_action = ble_packets_types[action]
    except Exception as e:
        device_action = "Unknown"

    if device_action == 'nearby': 
        # nearby
        Apple = process_nearby(data)
   
    elif device_action == 'handoff': 
        # handoff
        Apple = process_handoff(data)

    elif device_action == 'nearby_action': 
        # nearby_action
        Apple = process_nearby_action(data)

    elif device_action == 'hey_siri': 
        # hey_siri
        Apple = process_hey_siri(data)
    
    elif device_action == 'airpods': 
        # airpods
        Apple = process_airpods(data)
    else:
        print('WARNING: No parser for action',hex(action))




    # common fields
    Apple['action'] = device_action
    Apple['_action'] = action

    __add_details(device,'Apple',Apple)
