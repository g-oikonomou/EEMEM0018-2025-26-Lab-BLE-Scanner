# Overview

A simple application demonstrating Bluetooth LE scanner / gateway functionality.
The application will collect BLE advertisements, validate them and push them to the
thingsboard cloud.

This is used for the IoT Systems Prototyping lab exercise (EEMEM0018)
at the University of Bristol, academic year 2025/26.

# Getting Started

The script has been developed and tested on Mac OS and Linux. It should work, but has not
been tested on Windows.

The script needs the following Python packages:

* paho-mqtt
* bleak
* requests

Install them using pip on your site packages or inside a venv.

To print command line arguments: `./scanner -h`

# Running

To run with defaults: `./scanner`. This will enable the BLE scanner, but will not push
data to the cloud.

To push data to the cloud over MQTT: `./scanner -t`. This will push data over MQTT to a
broker running on localhost.

To control debugging output `./scanner -D {DEBUG,INFO,WARN,ERROR}`. Selecting `DEBUG`
will generate the most detailed output.

To push data to ThingsBoard over MQTT:

* First create a new Device on ThingsBoard cloud using the "Customer Gateway Profile"
Device Profile.

* Copy the device's credentials. To do so, open the device's properties on ThingsBoard and
press the "Copy access token" button.

* Back on your computer's terminal, store the copied token in the `ACCESS_TOKEN` environment
variable:

  `export ACCESS_TOKEN=<paste the value here>`

* To push data over MQTT to the ThingsBoard cloud:
`./scanner.py -t -b mqtt.thingsboard.cloud`.

# Alternative Transports

The script was originally developed to push data to the cloud over HTTP. The original code
is still there, but has not been updated to reflect recent code updates. It is not
expected to work without adjustments, in particular when it comes to new command line
arguments and in terms of authentication token handling. Logging/Debugging messages should
be OK, but need testing.
