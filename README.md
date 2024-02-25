# flowerhub-huawei-monitor
Python script to monitor modbus tcp communication between Flowerhub and Huawei inverter. Data is parsed using huawei-solar-lib and published on mqtt broker with homeassistant auto disccovery

[Flower](https://www.flower.se) is the company providing the [Flowerhub device](https://flowerhub.se) and the power grid balancing support service.

BACKGROUND / USE CASE
----
Flower provides balancing service to the Swedish power grid. As a home owner with a high voltage battery it is possible to become a provider in their balancing service. This requires that Flower gets full access and control of the inverter, the Huawei inverter does not accept a second connection on the Modbus TCP port, and currently there is no API in either the flowerhub device or a web based api provided by Flower. Flower provides a dashboard in their web portal but currecntly it does not provide much data, and not in real time.

This means that currently when becoming a provider to Flower you are completely blind to what is happening with your battery. This script tries to mitigate that and provide at least some information to what is going on with the battery.

PREREQUISITES
----
* The script needs access to the Modbus TCP communication between flowerhub and the Huawei inverter, e.g. port mirroring in a switch to the device running this script.
* [Tshark](https://tshark.dev/setup/install/) or Wireshark installed on the device (used by pyshark to sniff the ethernet traffic)  

HOWTO
----
1. Install the script dependencies `python setup.py install` or `pip install -r requirements.txt`
2. Modify the config options in the script, e.g. network interface where modbus traffic is available, hostname to inverter and mqtt broker etc.
3. Run the script `./flowerhub_monitor.py`
