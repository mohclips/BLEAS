import asyncio
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.backends._manufacturers import MANUFACTURERS
from bleak.uuids import uuidstr_to_str #these are GATT UUIDs in the lookup
from bleak import BleakClient


#from elasticsearch import Elasticsearch

import sys
import logging
import yaml
import json
import io
#import jsonpickle # for bytearrays
import math
import datetime

from pygments import highlight
from pygments.formatters.terminal256 import Terminal256Formatter
from pygments.lexers.web import JsonLexer

#from es_config import *
from apple_parser import do_apple_decode
from microsoft_parser import do_microsoft_decode
from nhs_parser import do_nhs_decode, isNHSapp

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)


KNOWN_DEVICE_FILE="./known_devices.yml"
known_devices = {} # read from file
devices = {} # list of devices seen - contains last seen - has housekeeping

measured_power = -67 # this is approximate
skip_known_devices = True # only show things we dont know about
skip_chipolo = False
skip_GAEN = True # covid notifications
skip_empty = True


pkt_stats = {
    'received':0,
    'dropped':0,
    'saved':0,
}

# timers (secs)
TIMER_SCANNER = 5.0
TIMER_STATS = 300.0
TIMER_READ_KNOWN_DEVICE = 120.0

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
    print("Attributes:")
    pprint(attributes(obj))
    print("/Attributes")
##########################################################################

def increment_stats(stat):
    
    if stat not in pkt_stats:
        pkt_stats[stat] = 1
    else:
        pkt_stats[stat] += 1
    #print(f'DEBUG: increment_stats {stat} {pkt_stats[stat]}')

def read_known_devices_yml():
    global known_devices
    with open(KNOWN_DEVICE_FILE, 'r') as stream:
        try:
            known_devices = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)

def calc_distance(advertisement_data):
    # https://stackoverflow.com/questions/22784516/estimating-beacon-proximity-distance-based-on-rssi-bluetooth-le
    # Distance = 10 ^ ((Measured Power — RSSI)/(10 * N))
    
    rssi = advertisement_data.rssi
    # needs to be negative, some cards return a positive number
    if rssi >0 :
        rssi = rssi * -1
    # if "TxPower" in device.details:
    #     N=device.details['TxPower']
    # else:
    #     N=2
    N=2
    #  return Math.pow(10d, ((double) txPower - rssi) / (10 * 2));
    # distance = int( round( math.pow(10,(( measured_power - rssi )/(10 * N))), 1) )
    distance = round( math.pow(10,(( measured_power - rssi )/(10 * N))), 2)
    # this is approximate (very approximate)
    return distance


def get_manufacturer(advertisement_data):
    if advertisement_data.manufacturer_data:
        mf_id = next(iter(advertisement_data.manufacturer_data))
        name = MANUFACTURERS.get(mf_id, MANUFACTURERS.get(0xFFFF))
        #print(f'mf_id={mf_id} {name}')
        if len(name) > 50:
            #This value has special meaning depending on the context in which it used. Link Manager Protocol (LMP): This value may be used in the internal and interoperability tests before a Company ID has been assigned. This value shall not be used in shipping end products. Device ID Profile: This value is reserved as the default vendor ID when no Device ID service record is present in a remote device.
            name = f"Unknown: {hex(mf_id)}"
        return name

    return "Unknown - no manufacturer data"
    # UUIDs in AdvertisementData are service_uuids

def get_known_device(device):
    #print(device.address)
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

def print_details(ble_device: BLEDevice, advertisement_data: AdvertisementData):
    global pkts

    global devices

    device = ble_device

    increment_stats('received')

    # dump some packets/devices
    if device.address[:9] == "D9:00:00:":
        increment_stats('chipolo')
        if skip_chipolo:
            return

    # current date and time
    ct = datetime.datetime.now()
    #print("current time:-", ct)

    device_distance = calc_distance(advertisement_data)

    # empty packets - Amazon Echo Show 5+ seem to send these
    if len(advertisement_data.service_data) == 0 and  len(advertisement_data.manufacturer_data) == 0 :
        #print(f"{ct} DEBUG: empty packet from {device.address} (no ad/man data) [{advertisement_data.rssi}] @ {device_distance}m")
        increment_stats('skipped_empty_pkt')
        increment_stats('dropped')
        return


    kd = get_known_device(device)
    #print("Known device: " + kd)

    if skip_known_devices and kd != "None":
        #print(f"DEBUG: skipped known device {kd}")
        increment_stats('skipped_known_device')
        increment_stats('dropped')
        return


    Common = {
        'known_device': kd,
        'last_seen': ct.timestamp()*1000,
        'distance': device_distance
    }
    add_details(device,'Common',Common)

    NHS=False
    if isNHSapp(advertisement_data):
        NHS=True
        increment_stats('nhs')
        # random mac
        #print("This is the NHS contact app")
        do_nhs_decode(device)

    else:
        #TODO: record first seen, last seen, occurrances

        #TODO: work out service uuids

        # Google Exposure Notification System
        # 0000fef3-0000-1000-8000-00805f9b34fb

        if '0000fef3-0000-1000-8000-00805f9b34fb' in advertisement_data.service_data:
            #print(f"DEBUG - skipping Google Exposure Notification System  {device.address} [{advertisement_data.rssi}] @ {device_distance}m")
            device.details['props']['gaen'] = True
            increment_stats('gaen')
            if skip_GAEN:
                increment_stats('dropped')
                return

        manufacturer = get_manufacturer(advertisement_data)
        #print("Device Manufacturer: " + manufacturer)
        add_details(device,'manufacturer_name', manufacturer)

        #print(manufacturer)

        #print(advertisement_data)
        #print_attributes(device)

        if not advertisement_data.manufacturer_data:
            #print("DEBUG: no 'ManufacturerData' present")
            pass
        else:
            #'ManufacturerData': {302: [252, 39, 201, 87, 69, 65]},

            # should there only be one UUID for manufacturer data?
            mf_id = next(iter(advertisement_data.manufacturer_data))
            mf_data=advertisement_data.manufacturer_data[mf_id]

            #print(f'Manufacturer Data: {mf_id} {manufacturer} [{", ".join(format(x, "x") for x in mf_data)}]')

            #
            # Manufacturer Parsers - see https://petsymposium.org/2019/files/papers/issue3/popets-2019-0036.pdf
            #
            if manufacturer == "Apple, Inc.":
                # https://github.com/hexway/apple_bleee/blob/master/ble_read_state.py
                do_apple_decode(device,advertisement_data)
                increment_stats('apple')

            elif manufacturer == "Microsoft":
                # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cdp/77b446d0-8cea-4821-ad21-fabdf4d9a569
                do_microsoft_decode(device, advertisement_data)
                increment_stats('microsoft')
            else:
                if manufacturer != "ASSA ABLOY":
                    print(f"DEBUG: {ct} no manufacturer parser: {manufacturer}")
                increment_stats('unknown_manufacturer')


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
        #
        # Housekeeping
        #
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
            #print("not NHS")
            devices[device.address]['last_seen'] = new
            send_event=True
        else: # NHS and less than 10mins old, so ignore
            # dont send as it REALLY REALLY SPAMMY (by design)
            pass

    # housekeeping
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

        #device.details['Common']['ad'] = advertisement_data

        # set doc id
        #_docid = device.address
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

            print(125 * "=")
            #print("current time:-", str(ct))
            add_details(device,'@timestamp',es_dt)# for ES

            #
            # Drop superflouous fields
            #
            # 'Paired': False, 'Trusted': False, 'Blocked': False, 'LegacyPairing': False,
            #  'Connected': False,
            for f in ['Paired', 'Trusted', 'Blocked', 'LegacyPairing', 'Adapter', 'ServicesResolved']:
                props = device.details['props']
                props.pop(f, None)

            device.details.pop('path', None)

            # if alias==addr skip
            addr = device.details['props']['Address'].replace(':','-')
            alias = device.details['props']['Alias']
            if alias == addr:
                device.details['props']['Alias'] = ''


            #
            # Fix up byte arrays
            #
            if advertisement_data.manufacturer_data:
                device.details['props']['md'] = {}
                for mf_id in advertisement_data.manufacturer_data:
                    md = advertisement_data.manufacturer_data[mf_id]
                    mds = ''
                    for d in md:
                        mds += f'{d:02x} '
                    device.details['props']['md'][mf_id] = mds
                #device.details['props']['ManufacturerData'] = mds

            if advertisement_data.service_data:
                device.details['props']['sd'] = {}
                for sd_id in advertisement_data.service_data:
                    sd = advertisement_data.service_data[sd_id]
                    sds = ''
                    for d in sd:
                        sds += f'{d:02x} '
                    device.details['props']['sd'][sd_id] = sds
                    #device.details['props']['ServiceData'] = sds
            
            if 'ManufacturerData' in device.details['props']:
                device.details['props'].pop('ManufacturerData')

            if 'ServiceData' in device.details['props']:
                device.details['props'].pop('ServiceData')
            
            #device['metadata'] = {}
            #device.metadata = {}

            #uuid = "00001812-0000-1000-8000-00805f9b34fb"
            #print(uuidstr_to_str(uuid))

            if 'UUIDs' in device.details['props']:
                uuids ={}
                device.details['props']['uuids'] = []
                for u in device.details['props']['UUIDs']:
                    s = uuidstr_to_str(u)
                    #uuids.append(f'{u}={s}')
                    uuids[u]=s

                device.details['props']['uuids'] = uuids
                device.details['props'].pop('UUIDs')

            # try:
            #     res = es.index(index="bluetooth-alias", body=device.details)
            #     print("ES:",res['result'], res['_id'])
            # except Exception as e:
            #     print(e)

            # this is what we are sending to elasticsearch

            #jd = jsonpickle.encode(device.details, unpicklable=True)

            device.details['time'] = str(ct)

            #jd = json.dumps(io.BytesIO(device.details))
            try:
                jd = json.dumps(device.details, indent=2)
                # Colorize it
                colorful_json = highlight(
                    jd,
                    lexer=JsonLexer(),
                    formatter=Terminal256Formatter(),
                )
                print(colorful_json)
            except Exception as e:
                print(f"print failed {e}")
                print(device.details)
                return
            
            increment_stats('saved')

            ##print(f"{ct} {device.details}")
            ##print_attributes(device.details)
            
            #print_attributes(device)

            # cleanup - why ???
            device.details.pop('Apple',None)
            device.details.pop('Microsoft',None)

async def log_stats():
    global pkt_stats
    while True:
        # current date and time
        ct = datetime.datetime.now()
        print(f"{ct} Stats: {pkt_stats}")

        # reset counters
        for stat in pkt_stats:
            pkt_stats[stat]=0

        await asyncio.sleep(TIMER_STATS)


async def read_known_devices():
    while True:
        ct = datetime.datetime.now()
        #print(f'{ct} DEBUG: read known devices yaml')
        read_known_devices_yml()
        await asyncio.sleep(TIMER_READ_KNOWN_DEVICE)



async def run_scanner():

    scanner = BleakScanner(print_details)

    print("+ Run Scanner")


    while True:
        try:
            await scanner.start()
            await asyncio.sleep(TIMER_SCANNER)
            await scanner.stop()
        except Exception as e:
            print(f"Scanning failed {e}")
            print(f"Try: sudo hciconfig hci1 reset && hciconfig hci1 up")
            sys.exit(1)
#
# Main
#

print('+ Main')

# es = Elasticsearch(
#     es_hosts,
#     #api_key=(api_key_id, api_key_secret)
# )

# jsonpickle.set_preferred_backend('json')
# jsonpickle.set_encoder_options('json', ensure_ascii=False);


loop = asyncio.get_event_loop()

# sub-tasks
loop.create_task(log_stats())
loop.create_task(read_known_devices())

# main task
loop.run_until_complete(run_scanner())
