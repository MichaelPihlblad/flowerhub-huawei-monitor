#!/usr/bin/python3
from setuptools import setup, find_packages

setup(
    name = "flowerhub-huawei-monitor",
    version = "0.1.0",
    description = "Monitor Modbus TCP communication from Flowerhub to Huawei inverter",
    packages = find_packages(),
    install_requires = ['huawei-solar', 'pyshark', 'pymodbus', 'paho-mqtt', 'homeassistant-mqtt-binding==2.0.3'] 
)
