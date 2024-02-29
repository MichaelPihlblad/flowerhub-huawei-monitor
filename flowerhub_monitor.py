#!/usr/bin/python3
import argparse
import signal
import sys
import time
import typing
import pyshark
import pyshark.packet
import pyshark.packet.fields
from huawei_solar.registers import RegisterDefinition
import huawei_solar.registers as huawei_registers
import ha_mqtt
from ha_mqtt import *
import ha_mqtt.ha_device
import ha_mqtt.mqtt_sensor
import ha_mqtt.mqtt_device_base
import ha_mqtt.util
from ha_mqtt.util import HaDeviceClass
import paho.mqtt.client
import logging
from huawei_solar.exceptions import *
from pymodbus.payload import BinaryPayloadDecoder
from pymodbus.pdu import ModbusExceptions
from pymodbus.register_read_message import ReadHoldingRegistersResponse
from pymodbus.register_write_message import WriteMultipleRegistersResponse
from pymodbus.constants import Endian
import ssl
from enum import EnumMeta, IntEnum
import re

###
### Config variables
###
INTERFACE="" # network interface where modbus traffic is available, e.g. "enp0s31f6"
INVERTER_IP = "" # IP or hostname to inverter
MQTT_SERVER = "homeassistant" # IP or hostname to MQTT broker
MQTT_PORT = 8883 
MQTT_USER = "" # MQTT broker username
MQTT_PASSWD = "" # MQTT broker password
LOGLEVEL = logging.INFO
REPLAYLOG = "" # debug option for simulating / replaying pcapng files, overrides interface
MQTT_TOPIC = "flowerhub" # root topic for entities under /homeassistant/sensors/ 
HA_DEVICE_NAME = "flowerhub_monitor" 
HA_DEVICE_ID = "1" 

### 
###  Global variables
###
script_exit = False
###
###
###


class MbusPacketHandler:
    
    def __init__(self) -> None:
        self.request_register: RegisterDefinition = None
        self.register_name: str = None
        self.register_id: str
        self.pending_write_values: list[str] = []
        self.value = None
        self.enum = None
        self.complete = False
        self.complete_callback = None
        self.unit = ""
    
    def set_complete_callback(self, function):
        if callable(function):
            logging.debug("Registered callback for action on complete successful req/resp: " + function.__name__)
            self.complete_callback = function
        else:            
            raise TypeError("Callback is not callable: " + function.__name__)
    
    
    def parse_response(self, modbus):
        res = None #response value        
        if not self.request_register:
            logging.debug("Response - no prior request at all, probably due to startup...")
            return
        #Exception / negative response
        if hasattr(modbus, 'exception_code'):    
            mbus_except_code = modbus.exception_code
            mbus_except_name = ModbusExceptions.decode(int(mbus_except_code))    
            logging.warning("Response - Modbus exception! Exception code #" + str(mbus_except_code) + ' ' + mbus_except_name
                            + '  Function code ' + str(modbus.func_code) + '  Register: '
                            + str(self.request_register.register) + ' ' + self.register_name)
            return                

        func_code = modbus.func_code
        response = None
        if func_code == '3':
            # Read request
            register_id = modbus.regnum16
            byte_cnt = int(modbus.byte_cnt)
            value_str = modbus.regval_uint16
            value = int(value_str)
            values = [value]
            if byte_cnt > 2:
                # long register            
                values.extend(self.get_extra_words(modbus))        
            response = ReadHoldingRegistersResponse(values)
        elif func_code == '16':
            # Write request
            register_id = modbus.reference_num
            #byte_cnt = int(modbus.word_cnt) * 2
            response = WriteMultipleRegistersResponse(register_id, len(self.pending_write_values))
            #value_str = ''.join([str(x) for x in self.pending_write_values])  
            #value = int(value_str)
            response.registers.extend(self.pending_write_values)
        else:
            # Unimplemented modbus function
            logging.warning("unimplemented function code: " + func_code)
            return
        
        # Response not for last known request
        if int(register_id) != self.request_register.register:
            # response does not match previous request     
            logging.debug("Response - Does not match previous request. Register " + register_id)
            return

        # Check if we have an extracted response        
        if response is None:
            logging.error("Error in code - should not happen. Have no response object")
            return
        # parse the response value
        decoder = BinaryPayloadDecoder.fromRegisters(response.registers, byteorder=Endian.BIG, wordorder=Endian.BIG)        
        log_enum = ""
        try:
            res = self.request_register.decode(decoder, None)
            if issubclass(type(res), IntEnum):                
                self.value = res.value
                log_enum = " " + self.enum(self.value).name
            else:
                self.value = res
        except (DecodeError, NotImplementedError) as err:
            if len(response.registers) == 1:
                self.value = response.registers[0]
            else:
                value_bytes = b''
                for word in response.registers:
                    value_bytes += word.to_bytes(2, byteorder='big')
                self.value = value_bytes.hex()
            # Log if error while decoding
            if type(err) is DecodeError:
                logging.warning("Response - Decode Error -Register " + str(register_id) + '\tValue ' + str(err.__cause__))
        
        # We have a complete request / response handled!
        logging.info("Response - " + register_id + " Name: " + self.register_name + " Value: " 
                     + str(self.value) + self.unit + log_enum)
        self.complete = True        
        return


    def get_extra_words(self, modbus) -> list[str]:
        # Handle more than 16 bit / 2 byte / 1 word
        extra = dict()        
        for item in modbus._get_all_fields_with_alternates():
            pattern = "Register.*(\d{5}).*:\s(\d{1,5})"
            match = re.search(pattern, item.show)
            if match:
                extra_reg = match.group(1)
                extra_val = match.group(2)
                if extra_reg != self.register_id and extra_reg not in extra:
                    extra[extra_reg] = int(extra_val)
        # return a list of all extra values. assuming one and same multi word register...
        return list(extra.values())
    
    
    def parse_request(self, modbus):
        self.register_id = modbus.reference_num
        length = 0        
        self.complete = False
        self.value = None
        self.request_register = None
        self.register_name = None
        self.enum = None
        self.pending_write_values = []
        self.unit = ""
        # Writerequest        
        if modbus.func_code == '16':                
            #TODO: support writes >2 byte values
            self.pending_write_values = [int(modbus.regval_uint16)]
            length = modbus.byte_cnt
            # Handle more than 16 bit / 2 byte / 1 word
            if int(length) > 2:
                self.pending_write_values.extend(self.get_extra_words(modbus))
        # read request
        elif modbus.func_code == '3':
            length = str(int(modbus.word_cnt) * 2)
        # common 
        for name, item in huawei_registers.REGISTERS.items():               
            if item.register == int(self.register_id):            
                self.request_register = typing.cast(RegisterDefinition, item)
                self.register_name = name
                # Get Unit
                if hasattr(self.request_register, 'unit'):
                    if type(self.request_register.unit) is str:
                        self.unit = self.request_register.unit
                    elif issubclass(type(self.request_register.unit), EnumMeta):
                        self.enum = self.request_register.unit
                break
        if not self.request_register:
            # Failed to find definition for register, create request property manually
            logging.debug("Request - #Failed to find register definition for " + self.register_id )
            self.request_register = RegisterDefinition(int(self.register_id), length)    
            self.register_name = ''
        
        # If write get write values for logging
        log_write = ""
        if self.pending_write_values:
            log_write = " Write: " + str(self.pending_write_values)
        # Log the parsed request
        logging.debug("Request - " + self.register_id + " Name: " + self.register_name + " Function code "
                       + modbus.func_code + log_write)       
        return
        
    

    # Collect packets
    def handle_message(self, packet):
        # separate if req / resp
        if packet.ip.dst == INVERTER_IP:
            # REQUEST
            self.parse_request(packet.modbus) 
            self.complete = False              
        elif(packet.ip.src == INVERTER_IP):
            # RESPONSE
            self.parse_response(packet.modbus)
            if self.complete:
                # Run callback for complete req/resp, if set
                if self.complete_callback:
                    self.complete_callback(self)
        return
# End of class MbusPacketHandler


class MqttHandler:

    def __init__(self) -> None:
        self.client = paho.mqtt.client.Client()
        self.ha_device = ha_mqtt.ha_device.HaDevice(HA_DEVICE_NAME, HA_DEVICE_ID)
        self.sensors: dict[str, ha_mqtt.mqtt_sensor.MqttSensor] = dict()


    def start(self):
        self.client.username_pw_set(MQTT_USER, MQTT_PASSWD)
        self.client.tls_set(cert_reqs=ssl.CERT_NONE)
        self.client.tls_insecure_set(True)
        self.client.connect(MQTT_SERVER, MQTT_PORT)
        self.client.loop_start()


    def stop(self):
        for sensor in self.sensors.values():
            sensor.close()

        mqtt_client.loop_stop()
        mqtt_client.disconnect()
        return
    
    
    def add_sensor(self, request_response:MbusPacketHandler):
        ha_options_enum = None
        ha_device_class = HaDeviceClass.NONE
        register_id_str: str = request_response.register_id
        
        # Decide the name of the sensor
        if request_response.register_name:
            name = request_response.register_name
        else:
            name = register_id_str  
        
        unit = request_response.unit

        # Prepare Homeassistant enum info
        if (request_response.enum):
            ha_options_enum = list(request_response.enum.__members__.keys())
            ha_device_class = HaDeviceClass.ENUM
            unit = None  # unit must be unset if enum in HA
        
        # TODO: Add more device classes ??  ha_mqtt.util.HaDeviceClass
        # Sensor: https://www.home-assistant.io/integrations/sensor/#device-class
        # Binary: https://www.home-assistant.io/integrations/binary_sensor/

        # build unique id string to use as mqtt path
        if name and name != register_id_str:
            name_reg_str = name + "_" + register_id_str
        else:
            name_reg_str = register_id_str

        # Create mqtt sensor (will publish homeassistant discovery so requires connection to broker)
        settings = ha_mqtt.mqtt_device_base.MqttDeviceSettings(name, MQTT_TOPIC+'/'+name_reg_str, self.client, self.ha_device)        
        sensor = ha_mqtt.mqtt_sensor.MqttSensor(settings, unit=unit, device_class=ha_device_class, send_only=True)
        
        if ha_options_enum: 
            sensor.add_config_option("options", ha_options_enum)
        sensor.add_config_option("force_update", True) # forces HA to update value even if unchanged
        #sensor.add_config_option("expire_after", 600) # 10 min, flower is requesting some registers seldom
        sensor._send_discovery(False) # send config topic but not state topic
        # Add new sensor to list over existing sensors
        self.sensors[register_id_str] = sensor
        return


    def mqtt_publish(self, request_response: MbusPacketHandler):
        if not self.client.is_connected():
            logging.warning("MQTT client not connected")
            return
        
        if not request_response.complete:
            logging.warning("MQTT - Cannot publish sensor info, modbus request/response not completed " 
                            + request_response.register_id)
            return
        
        # If sensor does not exist add it
        if request_response.register_id not in self.sensors:
            self.add_sensor(request_response)
        
        
        value = request_response.value
        if request_response.enum:
            if value in iter(request_response.enum):
                value_name = request_response.enum(value).name
                value = value_name#str(dict([(value_name, value)]))
            

        # Publish the sensor data to mqtt server
        sensor = self.sensors.get(request_response.register_id)
        if sensor:
            sensor.publish_state(value)
            logging.info("MQTT Published " + request_response.register_id + '  ' + sensor.name + '\tvalue: '
                         + str(value) + ' ' + str(sensor.unit_of_measurement or "") )    
        else:
            logging.error("Failed to add MQTT Homeassistant sensor for modbus register: "
                           + request_response.register_id + " " + request_response.register_name)
        return
# End class MqttHandler


def main():
    global script_exit
    global MQTT_SERVER
    global MQTT_USER
    global MQTT_PASSWD
    global mqtt_client

    logging.basicConfig(level=LOGLEVEL)

    if REPLAYLOG:        
        capture = pyshark.FileCapture(REPLAYLOG, display_filter='modbus') # , include_raw=True, use_json=True
    else:
        capture = pyshark.LiveCapture(interface=INTERFACE, display_filter='modbus')
           
    req_resp = MbusPacketHandler()
    mqtt_handler = MqttHandler()
    # Set Mqtt publish as callback on every successfully parsed modbus response
    req_resp.set_complete_callback(mqtt_handler.mqtt_publish)
    # Connect to MQTT broker
    mqtt_handler.start()

    while(not script_exit):
        #if not mqtt_client.is_connected:
        #    logging.error("MQTT client not connected, reconnecting...")
        #    mqtt_client.connect(MQTT_SERVER, MQTT_PORT)
        #    mqtt_client.loop_start()
        #    os.sleep(1)
        if not REPLAYLOG:
            capture.sniff(timeout=1)        
        if script_exit:
            logging.info("script_exit set, disconnecting mqtt and exiting...")
            mqtt_handler.mqtt_stop()
            break           
        else:
            # Handle the sniffed messages
            capture.apply_on_packets(req_resp.handle_message)            
        if REPLAYLOG:
            return  


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
                    prog='Flowerhub Huawei sniffer',
                    description='Sniff communication between flowerhub and Huawei inverter, parse the data and publish to mqtt with homeassistant autodiscovery',
                    epilog='Set the configuration options before launching')
    parser.add_argument('-r', '--replay')      # option that takes a value
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()
    if args.replay:
        REPLAYLOG = args.replay
    if args.verbose:
        LOGLEVEL = logging.DEBUG
    
    # Handle exceptions on ctrl+c    
    def quit():
        global script_exit
        script_exit = True
        time.sleep(2)
        sys.exit(130)        

    def interuppt_handler(signum, frame):
        quit() #Terminate process here as catching the signal removes the close process behaviour of Ctrl-C

    signal.signal(signal.SIGINT, interuppt_handler)
    # Do what we suppose to...
    try:
        main()
    except (KeyboardInterrupt):
        logging.info("Received keyboard interrupt, quiting...")
        quit()
    
