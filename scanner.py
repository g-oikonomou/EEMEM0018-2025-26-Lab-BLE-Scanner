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

# Configure a logger.
# We create a separate logger here so we can control ourselves without messing around with bleak
import logging
logger = logging.getLogger('Scanner')

# Command line argument support
import argparse
defaults = {
    'transport': 'MQTT',
    'debug_level': 'INFO',
}

choices = {
    'debug_level': ('DEBUG', 'INFO', 'WARN', 'ERROR'),
    'transport': ('MQTT', 'HTTPS'),
}

__version__ = '2025/26'

# CONFIGURATION
TARGET_NAME = {"Lab4-Adv", "LabGroup1"}
COMPANY_ID = 0x0059 

# ThingsBoard Config
TB_URL = "https://demo.thingsboard.io/api/v1"
TB_ACCESS_TOKEN = "yyg96elwr9hjg19hfgot"  # <--- PASTE TOKEN HERE

# State variables for throttling
last_sent_time = 0
UPLOAD_INTERVAL = 2.0 # Send to cloud every 1 second (even if BLE is faster)

def push_to_cloud(temperature, grp_id, grp_rssi):
    """Sends JSON data to ThingsBoard via HTTP"""
    url = f"{TB_URL}/{TB_ACCESS_TOKEN}/telemetry"

    json_key_temp = f"Temperature_{grp_id}"
    json_key_rssi = f"RSSI_{grp_id}"

    # Payload format follows this JSON schema: https://thingsboard.io/docs/reference/http-api/
    payload = {
        json_key_temp: temperature,
        json_key_rssi: grp_rssi
    }

    try:
        response = requests.post(url, json=payload, timeout=2)
        if response.status_code == 200:
            logger.info(" -> Cloud Upload Success: {payload}")
        elif response.status_code == 400:
            logger.warning("Invalid URL, request parameters of body")
        elif response.status_code == 404:
            logger.warning("Invalid ACCESS_TOKEN used")
        else:
            logging.warning(" -> Cloud Error: {response.status_code}")
    except Exception as e:
        logger.error(" -> Cloud Connection Failed: {e}")

def detection_callback(device, advertisement_data):
    global last_sent_time
    
    if device.name and device.name in TARGET_NAME:
        if COMPANY_ID in advertisement_data.manufacturer_data:
            
            # This allows you to debug and observe the raw data from your BLE packet
            raw_packet = advertisement_data.manufacturer_data
            logger.debug(raw_packet)
            
            # We only want the data after the company ID part 
            raw_bytes = advertisement_data.manufacturer_data[COMPANY_ID]
            logger.debug("Actual data payload in HEX is: {raw_bytes.hex(' ')}")

            try:
                # 1. Decode BLE: refer to https://docs.python.org/3/library/struct.html, Section: Format Characters
                unpacked = struct.unpack("<hB", raw_bytes)

                temperature_c = unpacked[0] / 100.0 # Convert to float
                group_id = unpacked[1]
                current_rssi = advertisement_data.rssi

                if group_id < 0:
                    logger.error("Error: Group ID {group_id} is out of bounds from device {device.name}")
                    return

                # Print real-time to console
                logger.info("[{device.address}] BLE Rx: {temperature_c:.2f} °C from Group {group_id:d} with RSSI {current_rssi:d}")

                # 2. Upload to Cloud (Throttled)
                current_time = time.time()
                if (current_time - last_sent_time) >= UPLOAD_INTERVAL:
                    push_to_cloud(temperature_c, group_id, current_rssi)
                    last_sent_time = current_time

            except Exception as e:
                logger.error("Error: {e}")
        else:
            logger.warning("Warning: Company ID mismatch...")

async def main():
    logger.info("Starting BLE scanner")
    scanner = BleakScanner(detection_callback=detection_callback, scanning_mode='active')
    await scanner.start()
    await asyncio.Event().wait()

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
                           const=defaults['transport'], choices=choices['transport'], default=defaults['transport'],
                           help="Push data to ThingsBoard over TRANSPORT. If -t is specified but TRANSPORT is omitted, "
                                "%s will be used. If the argument is omitted altogether, data will not be pushed."
                                % (defaults['transport'],))

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
