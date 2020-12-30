
# private method to add to the device details dict
def __add_details(device,detail,value):
    device.details[detail] = value

def isNHSapp(device):
    if device.details['UUIDs']:
        for uuid in device.details['UUIDs']:
            if uuid == '0000fd6f-0000-1000-8000-00805f9b34fb':
                return True
    return False


def do_nhs_decode(device):

    # https://en.wikipedia.org/wiki/Exposure_Notification
    # https://github.com/nhsx/covid-19-app-android-ag-public
    # https://github.com/google/exposure-notifications-android/
    # https://www.blog.google/documents/70/Exposure_Notification_-_Bluetooth_Specification_v1.2.2.pdf

    # they use a propritary binary "play-services-nearby-exposurenotification-1.7.2-eap.aar"

    # Service Data 16-bit UUID Section — This section shall have two different sections in its payload:
    #     a. A 16 byte Rolling Proximity Identifier.
    #     b. A 4 byte Associated Encrypted Metadata that contains the following (LSB first):
    #     i.
    #     Byte 0 — Versioning.
    #     • Bits 7:6 — Major version (01).
    #     • Bits 5:4 — Minor version (00).
    #     • Bits 3:0 — Reserved for future use.
    #     ii. Byte 1 — Transmit power level.
    #     • This is the measured radiated transmit power of Bluetooth Advertisement packets, and is used to
    #     improve distance approximation. The range of this field shall be -127 to +127 dBm.
    #     iii. Byte 2 — Reserved for future use.
    #     iv. Byte 3 — Reserved for future use.

    nhs_id = next(iter(device.details['ServiceData']))
    nhs_data=device.details['ServiceData'][nhs_id]

    RPI = ''.join(format(x,'x') for x in nhs_data[0:15])
    #print('Rolling Proximity Identifier: [{}]'.format(RPI))
    metadata = ', '.join(format(x, 'x') for x in nhs_data[16:])
    #print('Encrypted Meta data: [{}]'.format(metadata))

    NHS = {
        'RPI': RPI,
        'metadata': metadata
    }
    __add_details(device,'NHS', NHS)

    # overwrite known device
    device.details['Common']['known_device'] = 'NHS contact app'
