import asyncio
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.backends._manufacturers import MANUFACTURERS
#from bleak.uuids import uuidstr_to_str #these are GATT UUIDs in the lookup
from bleak import BleakClient

from elasticsearch import Elasticsearch

import logging
import yaml
import math
import datetime

from es_config import *
from apple_parser import do_apple_decode
from microsoft_parser import do_microsoft_decode
from nhs_parser import do_nhs_decode, isNHSapp

KNOWN_DEVICE_FILE="./known_devices.yml"
known_devices = {}

devices = {}

# https://gist.github.com/hbldh/ef7abc4927940e5844cdd2a5338faa14
# Python representation of <class 'Windows.Devices.Bluetooth.GenericAttributeProfile.GattCharacteristicProperties'>
GattCharacteristicsPropertiesEnum = {
    None: ("None", "The characteristic doesn’t have any properties that apply"),
    1: ("Broadcast", "The characteristic supports broadcasting"),
    2: ("Read", "The characteristic is readable"),
    4: ("WriteWithoutResponse", "The characteristic supports Write Without Response"),
    8: ("Write", "The characteristic is writable"),
    16: ("Notify", "The characteristic is notifiable"),
    32: ("Indicate", "The characteristic is indicatable"),
    64: ("AuthenticatedSignedWrites", "The characteristic supports signed writes"),
    128: ("ExtendedProperties", "The ExtendedProperties Descriptor is present"),
    256: ("ReliableWrites", "The characteristic supports reliable writes"),
    512: ("WritableAuxiliaries", "The characteristic has writable auxiliaries"),
}


###########################################################################
## https://stackoverflow.com/a/59128615/7396553
from pprint import pprint
from inspect import getmembers
from types import FunctionType

def attributes(obj):
    disallowed_names = {
      name for name, value in getmembers(type(obj))
        if isinstance(value, FunctionType)}
    return {
      name: getattr(obj, name) for name in dir(obj)
        if name[0] != '_' and name not in disallowed_names and hasattr(obj, name)}

def print_attributes(obj):
    pprint(attributes(obj))
##########################################################################

def read_known_devices_yml():
    global known_devices
    with open(KNOWN_DEVICE_FILE, 'r') as stream:
        try:
            known_devices = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)

def calc_distance(device):
    # https://dzone.com/articles/formula-to-convert-the-rssi-value-of-the-ble-bluet
    # Distance = 10 ^ ((Measured Power — RSSI)/(10 * N))
    measured_power = -69 # this is approximate
    rssi = device.rssi
    # if "TxPower" in device.details:
    #     N=device.details['TxPower']
    # else:
    #     N=2
    N=2
    distance = int( round( math.pow(10,(( measured_power - rssi )/(10 * N))), 0) )
    # this is approximate (very approximate)
    return distance


def get_manufacturer(device):

    if "ManufacturerData" in device.details:
        mf_id = next(iter(device.details['ManufacturerData']))
        name = MANUFACTURERS.get(mf_id, MANUFACTURERS.get(0xFFFF))
        if len(name) > 50:
            #This value has special meaning depending on the context in which it used. Link Manager Protocol (LMP): This value may be used in the internal and interoperability tests before a Company ID has been assigned. This value shall not be used in shipping end products. Device ID Profile: This value is reserved as the default vendor ID when no Device ID service record is present in a remote device.
            name = "Unknown: "+hex(mf_id)
        return name

    return "Unknown - no manufacturer data"
    # UUIDs in AdvertisementData are service_uuids

def get_known_device(device):
    if device.address in known_devices['known_devices']:
        return known_devices['known_devices'][device.address]
    return "None"

# async def print_services(mac_addr: str):
#     async with BleakClient(mac_addr) as client:
#         svcs = await client.get_services()
#         print("Services:", svcs)


def add_details(device,detail,value):
    device.details[detail] = value

def minus_key(key, dictionary):
    # https://stackoverflow.com/a/5844680/7396553
    shallow_copy = dict(dictionary)
    del shallow_copy[key]
    return shallow_copy

def print_details(device: BLEDevice, advertisement_data: AdvertisementData):

    global devices

    #TODO: advertising interval

    # check DB
    #if device.address not in devices:
    #if device.address != 'CD:B1:46:3D:B8:71':
        # add to DB
        #devices.append(device.address)



    kd = get_known_device(device)
    #print("Known device: " + kd)

    # current date and time
    ct = datetime.datetime.now()
    #print("current time:-", ct)

    #print(device.address, "RSSI:", device.rssi)

    #print("Approx Distance: " + str(calc_distance(device)) +"m")

    Common = {
        'known_device': kd,
        'last_seen': ct.timestamp()*1000,
        'distance': calc_distance(device)
    }
    add_details(device,'Common',Common)

    NHS=False
    if isNHSapp(device):
        NHS=True
        # random mac
        #print("This is the NHS contact app")
        do_nhs_decode(device)

    else:
        #TODO: record first seen, last seen, occurrances

        #TODO: work out service uuids

        manufacturer = get_manufacturer(device)
        #print("Device Manufacturer: " + manufacturer)
        add_details(device,'manufacturer', manufacturer)

        #print(manufacturer)

        #print(advertisement_data)
        #print_attributes(device)

        if 'ManufacturerData' not in device.details:
            print("INFO: no 'ManufacturerData' present")
        else:
            # 'ManufacturerData': {302: [252, 39, 201, 87, 69, 65]},
            mf_id = next(iter(device.details['ManufacturerData']))
            mf_data=device.details['ManufacturerData'][mf_id]

            #print('Manufacturer Data: [{}]'.format(', '.join(format(x, 'x') for x in mf_data)))
            #if 'AddressType' in device.details:
                #print("Address Type:",device.details['AddressType'])

            #
            # Manufacturer Parsers - see https://petsymposium.org/2019/files/papers/issue3/popets-2019-0036.pdf
            #
            if manufacturer == "Apple, Inc.":
                # https://github.com/hexway/apple_bleee/blob/master/ble_read_state.py
                do_apple_decode(device)

            elif manufacturer == "Microsoft":
                # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cdp/77b446d0-8cea-4821-ad21-fabdf4d9a569
                do_microsoft_decode(device)
            else:
                if manufacturer != "ASSA ABLOY":
                    print(ct, "no manufacturer parser:", manufacturer)


    #
    # work out whether to record event or not
    #
    isVFP=False
    if 'Name' in device.details and device.details['Name'] == 'ID152':
        isVFP=True

    send_event=False # send to ES?
    es_dt = ct.timestamp()*1000 # in millisecs from epoch!
    new = ct.timestamp()
    if device.address not in devices: # does not already exist
        devices[device.address] = {}
        devices[device.address]['last_seen'] = new
        device.details['Common']['first_seen'] = es_dt
        send_event = True
        #print("new")
    else: # exists so check
        old = devices[device.address]['last_seen']
        #time_diff = (new - old).total_seconds()
        time_diff = (new - old)
        #print(time_diff)
        if time_diff > 60 and not isVFP: # over 10mins old, dont care if NHS or not
            send_event = True
            devices[device.address]['last_seen'] = new
        elif time_diff > 600 and isVFP:
            # spammy smart watches at home - veryfitpro
            send_event = True
            devices[device.address]['last_seen'] = new
        elif isVFP:
            # < 10mins so ignore
            pass
        elif not NHS: # if < 10mins and not NHS send anyway
            print("not NHS")
            devices[device.address]['last_seen'] = new
            send_event=True
        else: # NHS and less than 10mins old, so ignore
            # dont send as it REALLY REALLY SPAMMY (by design)
            pass

    #FIXME: memory leak, must housekeep the devices dict or it will grow indefinitely
    # cull anything over 10mins?
    for dev in devices:
        ls = devices[dev]['last_seen']
        time_diff = (new - ls)
        if time_diff > 3600:  # one hour
            print("+ Housekeeping: Deleting {} as {} seconds old".format(dev,time_diff))
            # not 100% happy with this and under more load it may fail?
            devices = minus_key(dev,devices)
    #
    # ElasticSearch
    #
    if send_event:


        # set doc id
        _docid = device.address
        if device.details['Common']['known_device'] == 'NHS contact app':

            pass

            # NHS, record by set docid - so can update a doc
            # _docid = device.details['NHS']['RPI']
            # try:
            #     res = es.index(index="bluetooth-alias", id=_docid, body=device.details)
            #     print("ES:",res['result'], res['_id'])
            # except Exception as e:
            #     print(e)
        else:
            # non-NHS - we store every event, to a new doc

            print("==============================================================================================")
            print("current time:-", str(ct))
            add_details(device,'@timestamp',es_dt)# for ES

            #TODO: drop superflouous fields
            # 'Paired': False, 'Trusted': False, 'Blocked': False, 'LegacyPairing': False,
            #  'Connected': False,

            try:
                res = es.index(index="bluetooth-alias", body=device.details)
                print("ES:",res['result'], res['_id'])
            except Exception as e:
                print(e)

            # this is what we are sending to elasticsearch
            print("sent: ",device.details)

            # cleanup
            device.details.pop('Apple',None)
            device.details.pop('Microsoft',None)



async def run():

    scanner = BleakScanner()
    scanner.register_detection_callback(print_details)

    print("+ Run Scanner")


    while True:
        await scanner.start()
        await asyncio.sleep(5.0)
        await scanner.stop()

        #scanned_devices = await scanner.get_discovered_devices()

        # print("+ Connect to new devices")
        # for device in scanned_devices:
        #     if device.address not in completed_devices:
        #         print(chr(9)+device.address)
        #         completed_devices[device.address] = device

        #         #await print_services(device.address)




#
# Main
#

es = Elasticsearch(
    es_hosts,
    #api_key=(api_key_id, api_key_secret)
)

read_known_devices_yml()

loop = asyncio.get_event_loop()
loop.run_until_complete(run())
