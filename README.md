# flowerhub-huawei-monitor
Python script to monitor modbus tcp communication between Flowerhub and Huawei inverter. Data is parsed using huawei-solar-lib and published on mqtt broker with homeassistant auto disccovery

[Flower](https://www.flower.se) is the company providing the [Flowerhub device](https://flowerhub.se) and the power grid balancing support service.


PREREQUISITES
----
* The script needs access to the Modbus TCP communication between flowerhub and the Huawei inverter, e.g. port mirroring in a switch to the device running this script.
* [Tshark](https://tshark.dev/setup/install/) or Wireshark installed on the device (used by pyshark to sniff the ethernet traffic)  

HOWTO
----
1. Install the script dependencies `python setup.py install` or `pip install -r requirements.txt`
2. Modify the config options in the script, e.g. network interface where modbus traffic is available, hostname to inverter and mqtt broker etc.
3. Run the script `./flowerhub_monitor.py`
