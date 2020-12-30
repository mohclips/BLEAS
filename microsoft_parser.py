# see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cdp/77b446d0-8cea-4821-ad21-fabdf4d9a569

# Beacon Data (24 bytes): The beacon data section is further broken down.
# Note that the Scenario and Subtype Specific Data section requirements will differ based on the Scenario and Subtype.

# byte 0 = Scenario Type = Scenario Type (1 byte): Set to 1
# byte 1 = Version and Device Type (see below) -  The high two bits are set to 00 for the version number; the lower6 bits are set to Device Type
# byte 2 = Version and Flags = Version and Flags (1 byte): The high 3 bits are set to 001; the lower 3 bits to 00000.
# byte 3 = Reserved = Reserved (1 byte): Currently set to zero.
# bytes 4-7 = Salt = Salt (4 bytes): Four random bytes.
# bytes Device Hash (24 bytes) = Device Hash (24 bytes): SHA256 Hash of Salt plus Device Thumbprint. Truncated to 16 bytes.

microsoft_device = {
    1: "Xbox One",
    6: "Apple iPhone",
    7: "Apple iPad",
    8: "Android device",
    9: "Windows 10 Desktop",
    11: "Windows 10 Phone",
    12: "Linus device",
    13: "Windows IoT",
    14: "Surface Hub",
}

# private method to add to the device details dict
def __add_details(device,detail,value):
    device.details[detail] = value

def do_microsoft_decode(device):
    mf_id = next(iter(device.details['ManufacturerData']))
    mf_data=device.details['ManufacturerData'][mf_id]

    # eg. 1, 9, 32, 2,

    scenario_type = mf_data[0]  # Set to 1

    device_byte = mf_data[1]    # The high two bits are set to 00 for the version number; the lower6 bits are set to Device Type
    version = device_byte & 0b11000000
    device_type = device_byte & 0b00111111

    try:
        device_name = microsoft_device[device_type]
    except Exception as e:
        device_name = "Unknown: " + str(device_type)

    version_flags = mf_data[2]  # The high 3 bits are set to 001; the lower 3 bits to 00000.
    vf = version_flags & 0b00100000 # always 32 ?

    reserved = mf_data[3]

    _salt = mf_data[4:7] # Salt (4 bytes): Four random bytes.
    salt = ''.join(format(x,'x') for x in _salt)

    _sha256 = mf_data[8:]  # Device Hash (24 bytes): SHA256 Hash of Salt plus Device Thumbprint. Truncated to 16 bytes.
    sha256 = ''.join(format(x,'x') for x in _sha256)

    Microsoft = {
        'scenario_type': scenario_type,
        'version': version,                     # should be always zero
        'device_type': device_type,
        'device_name': device_name,
        'version_flags': version_flags,         # should always be 32, need to check
        '_version_flags': bin(version_flags),   # should always be 32, need to check
        'reserved': reserved,                   # supposedly set to zero, but its not!
        '_reserved': bin(reserved),             # supposedly set to zero, but its not!
        'salt':salt,
        'sha256': sha256
    }

    __add_details(device,'Microsoft',Microsoft)
