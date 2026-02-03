#!/usr/bin/env python3

# MIT License
#
# Copyright (c) 2025-26 University of Bristol
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import asyncio
import time
import struct
# Import the HTTP library in order to push to ThingsBoard
import requests
# Import scanner
from bleak import BleakScanner
from bleak.exc import BleakBluetoothNotAvailableError
from paho.mqtt.client import mqtt_ms_publish

# Auth tokens from external source - not version controlled
try:
    from tokens import tokens
except ModuleNotFoundError as e:
    pass

# Configure a logger.
# We create a separate logger here so we can control ourselves without messing around with bleak
import logging
logger = logging.getLogger('Scanner')

# Command line argument support
import argparse
defaults = {
    'transport': None,
    'transport_const': 'MQTT',
    'debug_level': 'INFO',
    'mqtt_broker': 'localhost',
    'mqtt_port': 1883,
    'https_server': 'localhost',
    'https_port': 443,
    'min_push_interval': 30,
}

choices = {
    'debug_level': ('DEBUG', 'INFO', 'WARN', 'ERROR'),
    'transport': ('MQTT', 'HTTPS'),
}

transport_handlers = {
    'MQTT': 'push_to_cloud_mqtt',
    'HTTPS': 'push_to_cloud_https',
}

__version__ = '2025/26'

# BLE Whitelisting Configuration
# We only process BLE packets from devices with a name that appears in a well-known list
# We only process manufacturer-specific data if the manufacturer is Nordic Semi (0x0059)
ble_whitelist_rules = {
    'device_names': {'EEMEM0018 IoT SP Lab'},
    'company_id': 0x0059,
}

# We have GROUP_ID_COUNT groups, numbered from 0 to (GROUP_ID_COUNT - 1)
# Create a list of MAX_GROUP_NUMBER + 1 elements.
# Element 0 is for the teaching team
GROUP_ID_COUNT = 41
GROUP_ID_TEACHING_TEAM = 0
last_tx_timestamps = [0 for x in range(GROUP_ID_COUNT)]

# ThingsBoard Config
TB_URL = "https://demo.thingsboard.io/api/v1"
TB_ACCESS_TOKEN = "yyg96elwr9hjg19hfgot"  # <--- PASTE TOKEN HERE

def push_to_cloud_mqtt(temperature, grp_id, rssi):
    logger.debug("Pushing over MQTT")
    return

# This function is based on the original code and has not been updated to reflect recent code updates.
# It is not expected to work without adjustments, in particular when it comes to new command line arguments and
# in terms of authentication token handling. Logging/Debugging messages should be OK, but need testing.
def push_to_cloud_https(temperature, grp_id, rssi):
    logger.debug("Pushing over HTTPS")
    """Sends JSON data to ThingsBoard via HTTP"""
    url = f"{TB_URL}/{TB_ACCESS_TOKEN}/telemetry"

    json_key_temp = f"Temperature_{grp_id}"
    json_key_rssi = f"RSSI_{grp_id}"

    # Payload format follows this JSON schema: https://thingsboard.io/docs/reference/http-api/
    payload = {
        json_key_temp: temperature,
        json_key_rssi: rssi
    }

    try:
        response = requests.post(url, json=payload, timeout=2)
        if response.status_code == 200:
            logger.info(f" -> Cloud Upload Success: {payload}")
        elif response.status_code == 400:
            logger.warning(f"Invalid URL, request parameters of body")
        elif response.status_code == 404:
            logger.warning(f"Invalid ACCESS_TOKEN used")
        else:
            logger.warning(f" -> Cloud Error: {response.status_code}")
    except Exception as e:
        logger.error(f" -> Cloud Connection Failed: {e}")

def push_to_cloud(temperature, grp_id, rssi):
    logger.debug("Pushing to Cloud, G=%d" % (grp_id,))
    current_time = time.time()
    delta_from_last_tx = current_time - last_tx_timestamps[grp_id]
    if delta_from_last_tx < args.min_push_interval:
        logger.warning("Suppressing Push: Last attempt was %u ago" % (delta_from_last_tx,))
        return

    try:
        globals()[transport_handlers[args.transport]](temperature, grp_id, rssi)
    except KeyError:
        # If the transport handler has not been set, then it will be None and we get a KeyError.
        # Carry on without pushing
        logger.debug("Suppressing Push: Transport not set")
        pass

    # Update the timestamp of the most recent attempt to send from this device
    last_tx_timestamps[grp_id] = current_time
    logger.info("Pushed G:%d, T:%s" %
                (grp_id,
                 time.strftime(time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(last_tx_timestamps[grp_id])))))

def detection_callback(device, advertisement_data):
    if device.name not in ble_whitelist_rules['device_names']:
        logger.debug("Ignoring device '%s'" % (device.name,))
        return


    try:
        logger.debug("Scanned device '%s'" % (device.name,))
        logger.debug("       Address: %s" % (device.address,))
        logger.debug("     Adv. Data: %s" % (advertisement_data,))
        manufacturer_data_bytes = advertisement_data.manufacturer_data[ble_whitelist_rules['company_id']]
        logger.debug("  Manufacturer: 0x%04x" % (ble_whitelist_rules['company_id'],))
        logger.debug(f"       Payload: {manufacturer_data_bytes.hex(' ')}")
        logger.debug("          RSSI: %d" % (advertisement_data.rssi,))
    except KeyError:
        logger.warning("*** Bad manufacturer 0x%04x ***" % (list(advertisement_data.manufacturer_data.keys())[0],))
        return

    # So now we have a Device Name of interest, with Manufacturer Specific Data inside,
    # and the Manufacturer is also of interest. Try to parse the Manufacturer Specific Payload
    # We expect:
    # * Group number. unsigned 1 byte
    # * Temperature. signed 2 bytes, little-endian

    try:
        # 1. Decode BLE: refer to https://docs.python.org/3/library/struct.html, Section: Format Characters
        unpacked = struct.unpack("<Bh", manufacturer_data_bytes)

        group_id = unpacked[0]
        temperature = unpacked[1]

        if group_id not in range(GROUP_ID_COUNT):
            logger.warning("*** Group ID %d out of bounds ***" % (group_id,))
            return

        # If we reach here we are satisfied with the Manufacturer Specific payload
        logger.info("%s: G=%d, T=%d, RSSI=%d" % (device.name, group_id, temperature, advertisement_data.rssi))
        push_to_cloud(temperature, group_id, advertisement_data.rssi)

    except struct.error as e:
        logger.warning("*** Error unpacking Manufacturer Specific Data ***: %s" % (e,))
        pass

async def main():
    logger.info("Starting BLE scanner")
    scanner = BleakScanner(detection_callback=detection_callback, scanning_mode='active')
    try:
        await scanner.start()
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        await scanner.stop()
        raise

def log_init():
    logger.setLevel(logging.DEBUG)

    # Create a handler and a formatted
    ch = logging.StreamHandler()
    ch.setLevel(args.debug_level)
    formatter = logging.Formatter('[%(asctime)s - %(name)s - %(levelname)s] %(message)s')
    ch.setFormatter(formatter)

    logger.addHandler(ch)

def arg_parser():
    parser = argparse.ArgumentParser(add_help = False,
                                     description = "Scan for BLE advertisement frames and, if their payload meets a "
                                                   "specific format (optionally) push them to the ThingsBoard Cloud.")


    out_group = parser.add_argument_group('Transport Options')
    out_group.add_argument('-t', '--transport', action='store', nargs='?',
                           const=defaults['transport_const'], choices=choices['transport'],
                           default=defaults['transport'],
                           help="Push data to ThingsBoard over TRANSPORT. If -t is specified but TRANSPORT is omitted, "
                                "%s will be used. If the argument is omitted altogether, data will not be pushed."
                                % (defaults['transport_const'],))
    out_group.add_argument('-m', '--min-push-interval', action='store',
                           default=defaults['min_push_interval'],
                           help="Suppress pushing data from a device to the cloud if we have pushed data from the same "
                                "device within the last MIN_PUSH_INTERVAL seconds. "
                                "Default: %s" % (defaults['min_push_interval'],))

    out_group = parser.add_argument_group('MQTT Options')
    out_group.add_argument('-b', '--mqtt-broker', action='store', default=defaults['mqtt_broker'],
                           help="MQTT broker hostname or address. Default: %s" % (defaults['mqtt_broker'],))
    out_group.add_argument('-p', '--mqtt-port', action='store', default=defaults['mqtt_port'],
                           help="MQTT broker port. Default: %d" % (defaults['mqtt_port'],))

    out_group = parser.add_argument_group('HTTPS Options')
    out_group.add_argument('-s', '--https-server', action='store', default=defaults['https_server'],
                           help="HTTPS server hostname or address. Default: %s" % (defaults['https_server'],))
    out_group.add_argument('-P', '--https-port', action='store', default=defaults['https_port'],
                           help="HTTPS server port. Default: %d" % (defaults['https_port'],))

    log_group = parser.add_argument_group('Debugging')
    log_group.add_argument('-D', '--debug-level', action = 'store',
                           choices = choices['debug_level'],
                           default = defaults['debug_level'],
                           help = "Print messages of severity DEBUG_LEVEL "
                                  "or higher (Default %s)"
                                   % (defaults['debug_level'],))

    gen_group = parser.add_argument_group('General Options')
    gen_group.add_argument('-v', '--version', action = 'version',
                           version = 'Scanner v%s' % (__version__))
    gen_group.add_argument('-h', '--help', action = 'help',
                           help = 'Shows this message and exits')

    return parser.parse_args()

if __name__ == "__main__":
    args = arg_parser()
    log_init()
    try:
        logger.info("Starting gateway")
        try:
            asyncio.run(main())
        except BleakBluetoothNotAvailableError as e:
            logger.error("Bluetooth not available. Exiting")
            sys.exit(1)

    except KeyboardInterrupt:
        logger.info("Stopping gateway")
