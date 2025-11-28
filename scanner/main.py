import asyncio
import struct
from bleak import BleakScanner

# Constants
TARGET_NAME = "Lab4-Adv"
COMPANY_ID = 0x0059 # Nordic Semiconductor

def detection_callback(device, advertisement_data):
    """
    This function is called every time a packet is received.
    """
    
    # 1. Filter by Device Name
    # Note: Sometimes device.name is None (if the packet is purely generic), 
    # so we handle that safely.
    if device.name and device.name == TARGET_NAME:
        
        # 2. Check for Manufacturer Data
        if COMPANY_ID in advertisement_data.manufacturer_data:
            raw_bytes = advertisement_data.manufacturer_data[COMPANY_ID]
            
            # 3. Decode the Data (Little Endian, Signed Integer)
            try:
                # Convert bytes to int16
                temp_int = struct.unpack('<h', raw_bytes)[0]
                
                # Convert fixed-point to float
                temperature_c = temp_int / 100.0
                
                print(f"[{device.address}] Temperature: {temperature_c:.2f} °C")
                
            except Exception as e:
                print(f"Error decoding data: {e}")

async def main():
    print(f"Starting continuous scan for {TARGET_NAME}...")
    
    # Create the scanner object
    # scanning_mode='active' requests the OS to ask for Scan Response packets (names)
    scanner = BleakScanner(detection_callback=detection_callback, scanning_mode='active')
    
    # Start scanning
    await scanner.start()
    
    # This line keeps the script running forever.
    # To stop it, press Ctrl+C in your terminal.
    await asyncio.Event().wait()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\nStopping scanner...")