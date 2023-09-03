#!/usr/bin/env python3

import time
import os
import logging
import logging.config
import random
import yaml
import zmq
import ast
import sys
from fissureclass import fissure_listener
from fissureclass import fissure_server
from fissure_libutils import *

# Insert Any Argument While Executing to Run Locally
try:
    run_local = sys.argv[1]
except:
    run_local = None

class Hiprfisr():
    """ Class that contains the functions for the HIPRFISR.
    """
    def __init__(self):
        """ The start of the HIPRFISR.
        """
        # Load Startup Settings
        self.initialization()

        # Create the HIPRFISR ZMQ Sockets
        self.connect()

        # Main Event Loop
        self.logger.debug('Start of Main Event Loop')
        self.message_counter = 0
        self.fge_local = False

        try:
            while True:

                # Connect Loop
                while self.connect_loop is True:
                    # Tell the Dashboard the HIPRFISR is Opened
                    time.sleep(0.5)
                    self.hiprfisr_pub_server.sendmsg('Heartbeats', Identifier = 'HIPRFISR', MessageName='Heartbeat', Time=time.time())

                    # Listen for Heartbeats on the SUB
                    self.readSUB_Messages()

                    # Tell Protocol Discovery the FGE Component is Local
                    if self.fge_local == True:
                        if (self.pd_connected == True) and (self.message_counter == 0):
                            # ~ self.hiprfisr_pub_server.sendmsg('Status', Identifier = 'Dashboard', MessageName = 'Connect to FGE', Parameters = '')
                            self.message_counter += 1

                    # Tell Dashboard Everything is Connected
                    if (self.dashboard_connected and self.tsi_connected and self.fge_connected and self.pd_connected) is True:  # How do you test for HIPRFISR PUB and DEALER/DEALER Connections?
                        time.sleep(0.5)
                        self.hiprfisr_pub_server.sendmsg('Status', Identifier = 'HIPRFISR', MessageName='Connected', Parameters='')
                    self.connect_loop = False

                    time.sleep(1)

                # Read the messages in the ZMQ queues
                if self.dashboard_connected == True:
                    self.readDashboardMessages()
                if self.tsi_connected == True:
                    self.readTSI_Messages()
                if self.pd_connected == True:
                    self.readPD_Messages()
                if self.fge_connected == True:
                    self.readFGE_Messages()
                #if self.sub_connected == True:  # What happens if the SUB fails after startup?
                self.readSUB_Messages()

                # Send the HIPRFISR heartbeat if interval time has elapsed
                if self.pub_created == True:
                    self.sendHeartbeat()

                # Check for received heartbeats
                self.checkHeartbeats()

                # SOI Check (and Auto Select)
                if self.process_sois:
                    selected_SOI = self.SOI_Check(int(self.settings_dictionary['SOI_trigger_mode']))
                    #~ print("Selected SOI: " + str(selected_SOI))
                    #~ print("Auto-Start PD: " + str(self.auto_start_pd))
                    #~ if self.auto_start_pd == True:
                        #~ # Start Protocol Discovery
                        #~ print("START PROTOCOL DISCOVERY HERE")
                        #~ startPD()
                        #~ #runFlowGraph(library_entry)
                                #~
                        #~ # Start Protocol Discovery if Set to Automatic
                                        #~
                time.sleep(1)

        except KeyboardInterrupt:
            pass

    def initialization(self):
        """ Loads default HIPRFISR settings from a YAML file and configures the log file
        """
        # Store Collected Wideband and Narrowband Signals in Lists
        self.wideband_list = []
        self.soi_list = []

        # SOI Blacklist
        self.soi_blacklist = []

        # Don't Process SOIs at Start
        self.process_sois = False

        # Create SOI sorting variables
        SOI_priority = (0,1,2)
        SOI_filter = ("Highest","Highest","Containing")
        self.soi_parameters = (None,None,"FSK")

        # Create the Variable
        self.auto_start_pd = False
        self.soi_manually_triggered = False

        # Initialize Connection/Heartbeat Variables
        self.lib_updated = False
        self.dashboard_connected = False
        self.tsi_connected = False
        self.fge_connected = False
        self.pd_connected = False
        self.pub_created = False
        self.sub_connected = False
        self.tsi_heartbeat_time = time.time()
        self.fge_heartbeat_time = time.time()
        self.pd_heartbeat_time = time.time()
        self.dashboard_heartbeat_time = time.time()
        self.hiprfisr_heartbeat_time = time.time()

        # Put all the Settings in one Dictionary Variable
        self.fissure_config_filename = os.path.dirname(os.path.realpath(__file__)) + '/YAML/fissure_config.yaml'
        self.settings_dictionary = self.loadSettings(self.fissure_config_filename)  # Load from YAML File

        # Save the Start Time
        self.settings_dictionary['SOI_trigger_time'] = str(time.time())

        # Configure Log File
        #logging.basicConfig(filename='event.log',level=logging.DEBUG, format='%(asctime)s : %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filemode='w')
        with open(os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", 'rt') as f:
            config = yaml.load(f.read(), yaml.FullLoader)
            config["handlers"]["file"]["filename"] = os.path.dirname(os.path.realpath(__file__)) + "/" + config["handlers"]["file"]["filename"]

        logging.config.dictConfig(config)
        self.logger = logging.getLogger('hiprfisr')

        # Load "library.yaml"
        filename = os.path.dirname(os.path.realpath(__file__)) + "/YAML/library.yaml"
        with open(filename) as yaml_library_file:
            self.pd_library = yaml.load(yaml_library_file, yaml.FullLoader)

        # Put the HIPRFISR in the Connect Loop
        self.connect_loop = True

        self.logger.debug('End of HIPRFISR Initialization')

    def loadSettings(self,filename):
        """ Loads the HIPRFISR settings from a YAML file and stores them in a dictionary
        """
        yaml_file = open(filename)
        dictionary = yaml.load(yaml_file, yaml.FullLoader)
        yaml_file.close()

        return dictionary

    def saveConfiguration(self,filename, data):
        """ Saves the HIPRFISR settings to a YAML file
        """
        stream = open(filename,'w')
        yaml.dump(data, stream)

    def connect(self):
        """ Connects all the 0MQ Servers and Listeners
        """
        dashboard_ip_address = "127.0.0.1"
        hiprfisr_ip_address = "127.0.0.1"
        tsi_ip_address = "127.0.0.1"        # Need to figure out how to set this
        pd_ip_address = "127.0.0.1"         # Need to figure out how to set this
        fge_ip_address = "127.0.0.1"        # Need to figure out how to set this

        # Connect Dashboard & HIPRFISR: DEALER-DEALER
        if self.dashboard_connected is False:
            dashboard_dealer_port = int(self.settings_dictionary['dashboard_hiprfisr_dealer_port'])
            self.dashboard_hiprfisr_listener = fissure_listener(os.path.dirname(os.path.realpath(__file__)) + '/YAML/hiprfisr.yaml',hiprfisr_ip_address,dashboard_dealer_port,zmq.DEALER, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "hiprfisr")

        # Connect TSI & HIPRFISR: DEALER-DEALER
        if self.tsi_connected is False:
            tsi_dealer_port = int(self.settings_dictionary['tsi_hiprfisr_dealer_port'])
            self.tsi_hiprfisr_server = fissure_server(os.path.dirname(os.path.realpath(__file__)) + '/YAML/tsi.yaml',tsi_ip_address,tsi_dealer_port,zmq.DEALER, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "hiprfisr")

        # Connect FGE & HIPRFISR: DEALER-DEALER
        if self.fge_connected is False:
            fge_dealer_port = int(self.settings_dictionary['fge_hiprfisr_dealer_port'])
            self.fge_hiprfisr_server = fissure_server(os.path.dirname(os.path.realpath(__file__)) + '/YAML/fge.yaml',hiprfisr_ip_address,fge_dealer_port,zmq.DEALER, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "hiprfisr")

        # Connect PD & HIPRFISR: DEALER-DEALER
        if self.pd_connected is False:
            pd_dealer_port = int(self.settings_dictionary['pd_hiprfisr_dealer_port'])
            self.pd_hiprfisr_server = fissure_server(os.path.dirname(os.path.realpath(__file__)) + '/YAML/hiprfisr.yaml',hiprfisr_ip_address,pd_dealer_port,zmq.DEALER, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "hiprfisr")

        # Create HIPRFISR PUB
        if self.pub_created is False:
            hiprfisr_pub_port = int(self.settings_dictionary['hiprfisr_pub_port'])
            self.hiprfisr_pub_server = fissure_server(os.path.dirname(os.path.realpath(__file__)) + '/YAML/hiprfisr.yaml',hiprfisr_ip_address,hiprfisr_pub_port,zmq.PUB, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "hiprfisr")
            self.pub_created = True

        # Connect SUB to all the PUBS
        if self.sub_connected is False:
            dashboard_pub_port = int(self.settings_dictionary['dashboard_pub_port'])

            tsi_pub_port = int(self.settings_dictionary['tsi_pub_port'])
            tsi_pub_port_id = int(self.settings_dictionary['tsi_pub_port_id'])
            tsi_pub_port_classification = int(self.settings_dictionary['tsi_pub_port_classification'])

            fge_pub_port = int(self.settings_dictionary['fge_pub_port'])

            pd_pub_port = int(self.settings_dictionary['pd_pub_port'])
            temp_sub_connected = True

            # Dashboard PUB
            try:
                self.hiprfisr_sub_listener = fissure_listener(os.path.dirname(os.path.realpath(__file__)) + '/YAML/hiprfisr.yaml',dashboard_ip_address,dashboard_pub_port,zmq.SUB, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "hiprfisr")
            except:
                print("Unable to connect HIPRFISR SUB to Dashboard PUB")
                temp_sub_connected = False

            # TSI PUBs
            try:
                self.hiprfisr_sub_listener.initialize_port(tsi_ip_address,tsi_pub_port)
                self.hiprfisr_sub_listener.initialize_port(tsi_ip_address,tsi_pub_port_id)
                self.hiprfisr_sub_listener.initialize_port(tsi_ip_address,tsi_pub_port_classification)

            except:
                print("Unable to connect HIPRFISR SUB to TSI PUB")
                temp_sub_connected = False

            # FGE PUB
            try:
                self.hiprfisr_sub_listener.initialize_port(fge_ip_address,fge_pub_port)

            except:
                print("Unable to connect HIPRFISR SUB to FGE PUB")
                temp_sub_connected = False

            # PD PUB
            try:
                self.hiprfisr_sub_listener.initialize_port(pd_ip_address,pd_pub_port)

            except:
                print("Unable to connect HIPRFISR SUB to PD PUB")
                temp_sub_connected = False

            self.sub_connected = temp_sub_connected

    def readTSI_Messages(self):
        """ Sort through any TSI messages
        """
        # Check for Messages
        parsed = ''
        while parsed != None:
            parsed = self.tsi_hiprfisr_server.recvmsg()
            if parsed != None:

                # Handle Messages/Execute Callbacks
                # Add SOI or Wideband Message to their List  # Moved to PUB/SUB
                #if parsed['Type'] == 'SOI':
                    #new_SOI = (parsed['ModulationType'], parsed['Frequency'], parsed['Power'])
                    #print(new_SOI)
                    #self.soi_list.append(new_SOI)
                #elif parsed['Type'] == 'Wideband':
                    #new_wideband = (parsed['Frequency'], parsed['Power'], parsed['Timestamp'])
                    #print(new_wideband)
                    #self.wideband_list.append(new_wideband)

                pass

    def readFGE_Messages(self):
        """ Sort through any FGE messages
        """
        # Check for Messages
        parsed = ''
        while parsed != None:
            parsed = self.fge_hiprfisr_server.recvmsg()
            if parsed != None:
                pass
                ## Handle Messages/Execute Callbacks
                #globalslocalcontext=globals().copy() #if the callback is a function...
                ##globalslocalcontext.update(locals())  #if it was a class member, you'd just pass the class in here
                #fge_hiprfisr_listener.runcallback(globalslocalcontext,parsed)

    def readPD_Messages(self):
        """ Sort through any PD messages
        """
        # Check for Messages
        parsed = ''
        while parsed != None:
            parsed = self.pd_hiprfisr_server.recvmsg()
            if parsed != None:
                pass
                #~ # Handle Messages/Execute Callbacks
                #~ globalslocalcontext=globals().copy() #if the callback is a function...
                #~ #globalslocalcontext.update(locals())  #if it was a class member, you'd just pass the class in here
                #~ self.pd_hiprfisr_server.runcallback(globalslocalcontext,parsed)

    def readDashboardMessages(self):
        """ Carry out all the commands in dashboard_message_list
        """
        # Check for Messages
        parsed = ''
        while parsed != None:
            parsed = self.dashboard_hiprfisr_listener.recvmsg()
            if parsed != None:
                # Handle Messages/Execute Callbacks
                self.dashboard_hiprfisr_listener.runcallback(self,parsed)

    def readSUB_Messages(self):
        """ Read all the messages in the self.hiprfisr_sub_listener and handle accordingly
        """
        # Check for Messages
        parsed = ''
        while parsed != None:
            parsed = self.hiprfisr_sub_listener.recvmsg()
            if parsed != None:
                # Check for Heartbeats in the Connect Loop
                if self.connect_loop == True:

                    if parsed['Identifier'] == 'Dashboard':
                        self.dashboard_connected = True

                        if parsed['Type'] == 'Status':
                            # Check for the "Exit Connect Loop" Message
                            if parsed['MessageName'] == 'Exit Connect Loop':
                                self.connect_loop = False

                            # TSI Pushbutton Pressed
                            elif parsed['MessageName'] == 'Connect to TSI':
                                self.connectToTSI()

                            # FGE Pushbutton Pressed
                            elif parsed['MessageName'] == 'Connect to FGE':
                                self.connectToFGE()

                    elif parsed['Identifier'] == 'TSI':
                        self.tsi_connected = True
                    elif parsed['Identifier'] == 'FGE':
                        self.fge_connected = True
                    elif parsed['Identifier'] == 'PD':
                        self.pd_connected = True

                # Handle Messages/Execute Callbacks as Usual
                else:
                    #refresh the full library (if we haven't updated yet)
                    # Heartbeats
                    if parsed['Type'] == 'Heartbeats':
                        if parsed['Identifier'] == 'TSI':
                            self.tsi_heartbeat_time = parsed['Time']
                        elif parsed['Identifier'] == 'FGE':
                            self.fge_heartbeat_time = parsed['Time']
                        elif parsed['Identifier'] == 'PD':
                            self.pd_heartbeat_time = parsed['Time']
                        elif parsed['Identifier'] == 'Dashboard':
                            self.dashboard_heartbeat_time = parsed['Time']

                    # Narrowband
                    if parsed['Type'] == 'SOI':
                        new_SOI = (parsed['ModulationType'], str(float(parsed['Frequency'])/1e6), parsed['Power'])

                        # Check if SOI is Blacklisted
                        blacklisted = False
                        for soi in self.soi_blacklist:
                            if soi == new_SOI[1] + "," + new_SOI[0]:
                                blacklisted = True

                        # Add it to the SOI List
                        if blacklisted == False:
                            self.soi_list.append(new_SOI)

                    # Wideband
                    elif parsed['Type'] == 'Wideband':
                        new_wideband = (parsed['Frequency'], parsed['Power'], parsed['Timestamp'])
                        self.wideband_list.append(new_wideband)

                    elif parsed['Identifier'] == 'PD':
                        pass
                        # if parsed['MessageName'] == 'Full Library':  # HIPRFISR will be responsible for changes to the library
                             # self.lib_updated = True
                             # self.pd_library = yaml.load(parsed['Parameters'], yaml.FullLoader)

    def setAutomation(self, level):
        """ Adjusts what gets automated in the HIPRFISR
        """
        # Low
        if level == 0:
            # TSI Wideband Search
            # TSI Narrowband Processing
            self.settings_dictionary['SOI_trigger_mode'] = "2"
            self.settings_dictionary['SOI_trigger_timeout'] = "3"
            # SOI Priority
            self.settings_dictionary['SOI_priority'] = ["2"]  # Highest Power
            # SOI Execution
            self.settings_dictionary['load_flow_graph_automatically'] = "True"
            # FGE Flow Graph Selection/Custom Editing
            # PD Observations
            # Logging
            self.settings_dictionary['log_wideband_signals'] = "True"
            self.settings_dictionary['log_narrowband_signals'] = "True"
            self.settings_dictionary['log_tsi_status'] = "True"
            self.settings_dictionary['log_fge_status'] = "True"
            self.settings_dictionary['log_dashbaord_messages'] = "True"
            self.settings_dictionary['log_pd_messages'] = "True"
            # I/Q Recording
            self.settings_dictionary['continuously_record_iq_data'] = "False"

        # Medium
        elif level == 1:
            # TSI Wideband Search
            # TSI Narrowband Processing
            self.settings_dictionary['SOI_trigger_mode'] = "2"
            self.settings_dictionary['SOI_trigger_timeout'] = "3"
            # SOI Priority
            self.settings_dictionary['SOI_priority'] = ["2"]  # Highest Power
            # SOI Execution
            self.settings_dictionary['load_flow_graph_automatically'] = "True"
            # FGE Flow Graph Selection/Custom Editing
            # PD Observations
            # Logging
            self.settings_dictionary['log_wideband_signals'] = "True"
            self.settings_dictionary['log_narrowband_signals'] = "True"
            self.settings_dictionary['log_tsi_status'] = "True"
            self.settings_dictionary['log_fge_status'] = "True"
            self.settings_dictionary['log_dashbaord_messages'] = "True"
            self.settings_dictionary['log_pd_messages'] = "True"
            # I/Q Recording
            self.settings_dictionary['continuously_record_iq_data'] = "False"

        # High
        elif level == 2:
            # TSI Wideband Search
            # TSI Narrowband Processing
            self.settings_dictionary['SOI_trigger_mode'] = "2"
            self.settings_dictionary['SOI_trigger_timeout'] = "3"
            # SOI Priority
            self.settings_dictionary['SOI_priority'] = ["2"]  # Highest Power
            # SOI Execution
            self.settings_dictionary['load_flow_graph_automatically'] = "True"
            # FGE Flow Graph Selection/Custom Editing
            # PD Observations
            # Logging
            self.settings_dictionary['log_wideband_signals'] = "True"
            self.settings_dictionary['log_narrowband_signals'] = "True"
            self.settings_dictionary['log_tsi_status'] = "True"
            self.settings_dictionary['log_fge_status'] = "True"
            self.settings_dictionary['log_dashbaord_messages'] = "True"
            self.settings_dictionary['log_pd_messages'] = "True"
            # I/Q Recording
            self.settings_dictionary['continuously_record_iq_data'] = "False"

        # Default
        elif level == 'Default':
            # Load in settings from the initialization config file
            temp_dictionary = self.loadSettings(self.fissure_config_filename)

            # TSI Wideband Search
            # TSI Narrowband Processing
            self.settings_dictionary['SOI_trigger_mode'] = temp_dictionary['SOI_trigger_mode']
            self.settings_dictionary['SOI_trigger_timeout'] = temp_dictionary['SOI_trigger_timeout']
            # SOI Priority
            self.settings_dictionary['SOI_priority'] = temp_dictionary['SOI_priority']
            # SOI Execution
            self.settings_dictionary['load_flow_graph_automatically'] = temp_dictionary['load_flow_graph_automatically']
            # FGE Flow Graph Selection/Custom Editing
            # PD Observations
            # Logging
            self.settings_dictionary['log_wideband_signals'] = temp_dictionary['log_wideband_signals']
            self.settings_dictionary['log_narrowband_signals'] = temp_dictionary['log_narrowband_signals']
            self.settings_dictionary['log_tsi_status'] = temp_dictionary['log_tsi_status']
            self.settings_dictionary['log_fge_status'] = temp_dictionary['log_fge_status']
            self.settings_dictionary['log_dashbaord_messages'] = temp_dictionary['log_dashbaord_messages']
            self.settings_dictionary['log_pd_messages'] = temp_dictionary['log_pd_messages']
            # I/Q Recording
            self.settings_dictionary['continuously_record_iq_data'] = temp_dictionary['continuously_record_iq_data']

    def sendHeartbeat(self):
        """ Sends the heartbeat to all subscribers
        """
        current_time = time.time()
        if self.hiprfisr_heartbeat_time < current_time - float(self.settings_dictionary['heartbeat_interval']):
            self.hiprfisr_heartbeat_time = current_time
            self.hiprfisr_pub_server.sendmsg('Heartbeats', Identifier = 'HIPRFISR', MessageName='Heartbeat', Time=current_time)

    def checkHeartbeats(self):
        """ Checks if heartbeats were not received within the heartbeat_interval and performs an action
        """
        current_time = time.time()

        # Dashboard Check
        # Failed Heartbeat Check While Previously Connected
        if float(self.dashboard_heartbeat_time) < current_time - (float(self.settings_dictionary['failure_multiple']) * float(self.settings_dictionary['heartbeat_interval'])) and self.dashboard_connected is True:
            self.dashboard_hiprfisr_listener.sendmsg('Status', Identifier = 'HIPRFISR', MessageName = 'Disconnected', Parameters = 'Dashboard')
            self.dashboard_connected = False

        # Passed Heartbeat Check While Previously Disconnected
        elif float(self.dashboard_heartbeat_time) > current_time - (float(self.settings_dictionary['failure_multiple']) * float(self.settings_dictionary['heartbeat_interval'])) and self.dashboard_connected is False:
            self.dashboard_hiprfisr_listener.sendmsg('Status', Identifier = 'HIPRFISR', MessageName = 'Connected', Parameters = 'Dashboard')
            self.dashboard_connected = True

        # TSI Check
        # Failed Heartbeat Check While Previously Connected
        if float(self.tsi_heartbeat_time) < current_time - (float(self.settings_dictionary['failure_multiple']) * float(self.settings_dictionary['heartbeat_interval'])) and self.tsi_connected is True:
            self.dashboard_hiprfisr_listener.sendmsg('Status', Identifier = 'HIPRFISR', MessageName = 'Disconnected', Parameters = 'TSI')
            self.tsi_connected = False

        # Passed Heartbeat Check While Previously Disconnected
        elif float(self.tsi_heartbeat_time) > current_time - (float(self.settings_dictionary['failure_multiple']) * float(self.settings_dictionary['heartbeat_interval'])) and self.tsi_connected is False:
            self.dashboard_hiprfisr_listener.sendmsg('Status', Identifier = 'HIPRFISR', MessageName = 'Connected', Parameters = 'TSI')
            self.tsi_connected = True

        # FGE Check
        # Failed Heartbeat Check While Previously Connected
        if float(self.fge_heartbeat_time) < current_time - (float(self.settings_dictionary['failure_multiple']) * float(self.settings_dictionary['heartbeat_interval'])) and self.fge_connected is True:
            self.dashboard_hiprfisr_listener.sendmsg('Status', Identifier = 'HIPRFISR', MessageName = 'Disconnected', Parameters = 'FGE')
            self.fge_connected = False

        # Passed Heartbeat Check While Previously Disconnected
        elif float(self.fge_heartbeat_time) > current_time - (float(self.settings_dictionary['failure_multiple']) * float(self.settings_dictionary['heartbeat_interval'])) and self.fge_connected is False:
            self.dashboard_hiprfisr_listener.sendmsg('Status', Identifier = 'HIPRFISR', MessageName = 'Connected', Parameters = 'FGE')
            self.fge_connected = True

        # PD Check
        # Failed Heartbeat Check While Previously Connected
        if float(self.pd_heartbeat_time) < current_time - (float(self.settings_dictionary['failure_multiple']) * float(self.settings_dictionary['heartbeat_interval'])) and self.pd_connected is True:
            self.dashboard_hiprfisr_listener.sendmsg('Status', Identifier = 'HIPRFISR', MessageName = 'Disconnected', Parameters = 'PD')
            self.pd_connected = False

        # Passed Heartbeat Check While Previously Disconnected
        elif float(self.pd_heartbeat_time) > current_time - (float(self.settings_dictionary['failure_multiple']) * float(self.settings_dictionary['heartbeat_interval'])) and self.pd_connected is False:
            self.dashboard_hiprfisr_listener.sendmsg('Status', Identifier = 'HIPRFISR', MessageName = 'Connected', Parameters = 'PD')
            self.pd_connected = True


    ############################## HIPRFISR callbacks that react to outside messages received by the HIPRFISR  #################################

    def updateFISSURE_Configuration(self):
        """ Reload fissure_config.yaml after changes.
        """
        # Update HIPRFISR
        self.settings_dictionary = self.loadSettings(self.fissure_config_filename)

        # Update Other Components
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Update FISSURE Configuration')
        self.tsi_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Update FISSURE Configuration')
        self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Update FISSURE Configuration')

    def clear_SOI_List(self):
        """ Clears the SOI List
        """
        self.logger.debug("Executing Callback: Clear SOI List")
        self.soi_list = []

    def clearWidebandList(self):
        """ Clears the Wideband List
        """
        self.logger.debug("Executing Callback: Clear Wideband List")
        self.wideband_list = []

    def protocolDiscoveryFG_Start(self, flow_graph_filepath, variable_names, variable_values):
        """ Sends message to FGE to run a flow graph
        """
        # Send Message to FGE
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Run PD Flow Graph', Parameters = [flow_graph_filepath, variable_names, variable_values])

    def protocolDiscoveryFG_Stop(self, parameter):
        """ Sends message to FGE to stop a running flow graph.
        """
        # Send Message to FGE
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Stop PD Flow Graph', Parameters = '')

    def attackFlowGraphStart(self, flow_graph_filepath, variable_names, variable_values, file_type, run_with_sudo):
        """ Command for loading an attack.
        """
        # Send Message to FGE
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Run Attack Flow Graph', Parameters = [flow_graph_filepath, variable_names, variable_values, file_type, run_with_sudo])

    def iqFlowGraphStart(self, flow_graph_filepath, variable_names, variable_values, file_type):
        """ Command for loading an attack.
        """
        # Send Message to FGE
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Run IQ Flow Graph', Parameters = [flow_graph_filepath, variable_names, variable_values, file_type])

    def attackFlowGraphStop(self, parameter):
        """ Sends message to FGE to stop a running attack flow graph.
        """
        # Send Message to FGE,PD
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Stop Attack Flow Graph', Parameters = [parameter])

    def iqFlowGraphStop(self, parameter):
        """ Sends message to FGE to stop a running attack flow graph.
        """
        # Send Message to FGE,PD
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Stop IQ Flow Graph', Parameters = [parameter])

    def inspectionFlowGraphStart(self, flow_graph_filepath, variable_names, variable_values, file_type):
        """ Command for loading an attack.
        """
        # Send Message to FGE
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Run Inspection Flow Graph', Parameters = [flow_graph_filepath, variable_names, variable_values, file_type])

    def inspectionFlowGraphStop(self, parameter):
        """ Sends message to FGE to stop a running attack flow graph.
        """
        # Send Message to FGE,PD
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Stop Inspection Flow Graph', Parameters = [parameter])

    def snifferFlowGraphStart(self, flow_graph_filepath, variable_names, variable_values):
        """ Command for loading an attack.
        """
        # Send Message to FGE
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Run Sniffer Flow Graph', Parameters = [flow_graph_filepath, variable_names, variable_values])

    def snifferFlowGraphStop(self, parameter):
        """ Sends message to FGE to stop a running attack flow graph.
        """
        # Send Message to FGE,PD
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Stop Sniffer Flow Graph', Parameters = [parameter])

    def setHeartbeatInterval(self, interval):
        """ Saves the settings changes made in the Dashboard to the HIPRFISR.
        """
        self.settings_dictionary['heartbeat_interval'] = str(int(interval[0]))

        # Send Change to TSI
        self.tsi_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Set Heartbeat Interval', Parameters = interval)

    def setSOI_SelectionMode(self, mode):
        """ Sets the SOI selection mode for deciding when to load flow graphs.
        """
        self.settings_dictionary['SOI_trigger_mode'] = str(int(mode[0]))

    def setProcessSOIs(self, enabled, priorities, filters, parameters):
        """ Enables/Disables SOI Check in the main event loop.
        """
        # Assign to Variables
        if enabled == True:
            self.process_sois = True
            self.soi_priorities = priorities
            self.soi_filters = filters
            self.soi_parameters = parameters
        elif enabled == False:
            self.process_sois = False

    def setTargetSOI(self, frequency, modulation, bandwidth, continuous, start_frequency, end_frequency):
        """ The Dashboard has selected a target SOI to examine. This SOI will be looked up in the
            library to find a best-fit flow graph.
        """
        # Save the SOI
        self.settings_dictionary['target_SOI'] = str([frequency, modulation, bandwidth, continuous, start_frequency, end_frequency])

        # System has now been Manually Triggered
        self.soi_manually_triggered = True

        self.process_sois = True

    def setVariable(self, flow_graph, variable, value):
        """ Sends a message to FGE to change the variable of the running flow graph.
        """
        # Send Message to FGE
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Set Variable', Parameters = [flow_graph, variable, value])

    def setAutoStartPD(self, value):
        """ Controls whether Protocol Discovery will begin immediately when a target signal is selected.
        """
        if value[0] == "True":
            self.auto_start_pd = True
        elif value[0] == "False":
            self.auto_start_pd = False

    def startTSI_Detector(self, detector, variable_names, variable_values):
        """ Signals to TSI to start TSI detector.
        """
        # Send Message
        self.tsi_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Start TSI Detector', Parameters = [detector,variable_names,variable_values])

    def stopTSI_Detector(self):
        """ Signals to TSI to stop TSI detector.
        """
        # Send Message
        self.tsi_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Stop TSI Detector')
        
    def startTSI_Conditioner(self, common_parameter_names, common_parameter_values, method_parameter_names, method_parameter_values):
        """ Signals to TSI to start TSI Conditioner.
        """
        # Send Message
        self.tsi_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Start TSI Conditioner', Parameters = [common_parameter_names, common_parameter_values, method_parameter_names, method_parameter_values])

    def stopTSI_Conditioner(self):
        """ Signals to TSI to stop TSI conditioner.
        """
        # Send Message
        self.tsi_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Stop TSI Conditioner')
        
    def startTSI_FE(self, common_parameter_names, common_parameter_values):
        """ Signals to TSI to start TSI feature extractor.
        """
        # Send Message
        self.tsi_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Start TSI FE', Parameters = [common_parameter_names, common_parameter_values])

    def stopTSI_FE(self):
        """ Signals to TSI to stop TSI feature extractor.
        """
        # Send Message
        self.tsi_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Stop TSI FE')

    def stopPD(self):
        """ Signals to PD to stop protocol discovery.
        """
        # Send Message
        self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Stop PD')

    def SOI_Check(self, trigger_mode):
        """ The methods for deciding when to examine SOIs
        """
        returned_SOI = None

        # Manual Selection
        if trigger_mode == 0:
            print("TRIGGER MODE 0")
            if self.soi_manually_triggered == True:
                self.process_sois = False
                self.soi_manually_triggered = False
                print('SOI Triggered Manually: New Target Selected')
                returned_SOI = self.settings_dictionary['target_SOI']

                # Search Library for Flow Graphs
                #~ searchLibraryForFlowGraphs([returned_SOI[0],returned_SOI[1],returned_SOI[2],returned_SOI[3],returned_SOI[4],returned_SOI[5],0,0,0,0])
                self.searchLibraryForFlowGraphs(["",returned_SOI[1],"","","","",0,0,0,0],None)  # Modulation Only

        # Time Elapsed
        elif trigger_mode == 1:
            print("TRIGGER MODE 1")
            current_time = time.time()
            if (current_time-float(self.settings_dictionary['SOI_trigger_time'])) > float(self.settings_dictionary['SOI_trigger_timeout']):  # SOI_trigger_time should not be in YAML
                self.settings_dictionary['SOI_trigger_time'] = str(current_time)
                print('SOI Timeout: Selecting New Target')

                if len(self.soi_list) > 0:  # If the SOI list is not empty
                    # Choose SOI from the current list
                    returned_SOI = SOI_AutoSelect( self.soi_list, self.soi_priorities, self.soi_filters ) # What happens if nothing is returned?
                    # Send Message to Dashboard to Check Radio Button
                    self.dashboard_hiprfisr_listener.sendmsg('Status', Identifier = 'HIPRFISR', MessageName = 'SOI Chosen' , Parameters = returned_SOI )

        # SOI quantity reached
        elif trigger_mode == 2:
            if len(self.soi_list) >= int(self.settings_dictionary['SOI_quantity_limit']):
                self.process_sois = False
                print('SOI Quantity Reached: Selecting New Target')
                # Choose SOI from the current list
                returned_SOI = SOI_AutoSelect( self.soi_list, self.soi_priorities, self.soi_filters  ) # What happens if nothing is returned?
                # Send Message to Dashboard to Check Radio Button
                self.dashboard_hiprfisr_listener.sendmsg('Status', Identifier = 'HIPRFISR', MessageName = 'SOI Chosen' , Parameters = returned_SOI )

        return returned_SOI

    def searchLibraryForFlowGraphs(self, soi_data, hardware):
        """ Queries protocol discovery to look in its version of the library to recommend flow graphs for the SOI.
        """
        # Send Message to Protocol Discovery
        self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Search Library for Flow Graphs', Parameters = [soi_data, hardware])

    def SOI_AutoSelect(self, list1, SOI_priorities, SOI_filters):
        """ Sort the SOI list using specified criteria and choose the best SOI to examine.
            "priority" is a list specifying which list elements in the SOI list will be sorted by.
            priority = (2, 0, 1) will produce a list that is sorted by element2, then element0, and then element1
            "must_contain" is a list containing elements that narrows the SOI list further by checking for matches after the SOI list is sorted by priority
        """
        # Sort the List by Element Priority
        descending = False
        for x in reversed(range(0,len(SOI_priorities))):
            if SOI_filters[x] == "Highest":
                list1 = sorted(list1, key=lambda list1: float(list1[SOI_priorities[x]]), reverse=True)

            elif SOI_filters[x] == "Lowest":
                list1 = sorted(list1, key=lambda list1: float(list1[SOI_priorities[x]]), reverse=False)

            elif SOI_filters[x] == "Nearest to":
                # Take Absolute Value of Value Differences and then Sort
                new_list_matching = []
                abs_value_list = []

                # Absolute Value
                for soi in range(0,len(list1)):
                    abs_value_list.append(abs(float(self.soi_parameters[x]) - float(list1[soi][SOI_priorities[x]])))

                # Sort from Absolute Value
                sorted_index = sorted(range(len(abs_value_list)),key=lambda x:abs_value_list[x])
                for index in range(0,len(sorted_index)):
                    new_list_matching.append(list1[sorted_index[index]])
                list1 = new_list_matching

            elif SOI_filters[x] == "Greater than":
                # Keep Things that Fit Criteria
                new_list_matching = []
                for soi in range(0,len(list1)):
                    if float(list1[soi][SOI_priorities[x]]) > float(self.soi_parameters[x]):
                        new_list_matching.append(list1[soi])
                list1 = new_list_matching

            elif SOI_filters[x] == "Less than":
                # Keep Things that Fit Criteria
                new_list_matching = []
                for soi in range(0,len(list1)):
                    if float(list1[soi][SOI_priorities[x]]) < float(self.soi_parameters[x]):
                        new_list_matching.append(list1[soi])
                list1 = new_list_matching

            elif SOI_filters[x] == "Containing":
                # Keep Things that Fit Criteria
                new_list_matching = []
                for soi in range(0,len(list1)):
                    if list1[soi][0] in self.soi_parameters[x]:
                        new_list_matching.append(list1[soi])
                list1 = new_list_matching

        # Check if the list is empty
        if len(list1) > 0:
            soi = list1[0]
        else:
            print("No SOI Matches the Criteria")
            soi = []

        print('Selected SOI: {}' .format(soi))

        return soi

    def ignoreSOIs(self, dashboard_soi_blacklist):
        """ Copies the Dashboard's blacklisted items to the HIPRFISR. These items will be removed from the HIPRFISR SOI list.
        """
        # Copy the Dashboard Blacklist
        self.soi_blacklist = dashboard_soi_blacklist

        # Remove Blacklisted SOIs from SOI List
        for soi in dashboard_soi_blacklist:
            for x in reversed(range(0,len(self.soi_list))):
                if soi == self.soi_list[x][1] + ',' + self.soi_list[x][0]:
                    del self.soi_list[x]

    def addBlacklist(self, start_frequency, end_frequency):
        """ Forwards Add Blacklist message to TSI.
        """
        # Send Message to TSI
        self.tsi_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Add Blacklist', Parameters = [start_frequency, end_frequency])

    def removeBlacklist(self, start_frequency, end_frequency):
        """ Forwards Remove Blacklist message to TSI.
        """
        # Send Message to TSI
        self.tsi_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Remove Blacklist', Parameters = [start_frequency, end_frequency])

    def updateConfiguration(self, start_frequency, end_frequency, step_size, dwell_time):
        """ Forwards the Update Configuration message to TSI.
        """
        # Send Message
        self.tsi_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Update Configuration', Parameters = [start_frequency, end_frequency, step_size, dwell_time])

    def physicalFuzzingStart(self, fuzzing_variables, fuzzing_type, fuzzing_min, fuzzing_max, fuzzing_update_period, fuzzing_seed_step):
        """ Command for starting physical fuzzing on a running flow graph.
        """
        # Send Message to FGE
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Start Physical Fuzzing', Parameters = [fuzzing_variables, fuzzing_type, fuzzing_min, fuzzing_max, fuzzing_update_period, fuzzing_seed_step])

    def physicalFuzzingStop(self):
        """ Sends message to FGE to stop the physical fuzzing thread being performed on a running flow graph.
        """
        # Send Message to FGE,PD
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Stop Physical Fuzzing')

    def startPD(self):
        """ Sends a message to PD to start processing on any incoming bits.
        """
        # Send Message to PD
        self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Start PD')

    def multiStageAttackStart(self, filenames, variable_names, variable_values, durations, repeat, file_types):
        """ Sends message to FGE/PD to start multi-stage attack.
        """
        # Send Message to FGE
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Start Multi-Stage Attack', Parameters = [filenames, variable_names, variable_values, durations, repeat, file_types])

    def multiStageAttackStop(self, parameter):
        """ Sends message to FGE/PD to stop multi-stage attack.
        """
        # Send Message to FGE
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Stop Multi-Stage Attack', Parameters = '')

    def archivePlaylistStart(self, flow_graph, filenames, frequencies, sample_rates, formats, channels, gains, durations, repeat, ip_address, serial):
        """ Sends message to FGE/PD to start multi-stage attack.
        """
        # Send Message to FGE
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Start Archive Playlist', Parameters = [flow_graph, filenames, frequencies, sample_rates, formats, channels, gains, durations, repeat, ip_address, serial])

    def archivePlaylistStop(self, parameter):
        """ Sends message to FGE/PD to stop multi-stage attack.
        """
        # Send Message to FGE
        self.fge_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Stop Archive Playlist', Parameters = '')

    def setWindowParameters(self, window_min, window_max, ranking, std_deviations):
        """ Sends message to PD with updated bit slicing window parameters from the Dashboard.
        """
        # Send Message to PD
        self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Set Window Parameters', Parameters = [window_min, window_max, ranking, std_deviations])

    def findPreambles(self):
        """ Sends message to PD to search the buffer for preambles.
        """
        # Send Message to PD
        self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Find Preambles')

    def searchLibrary(self, soi_data, field_data):
        """ Sends message to PD to search library.yaml for occurences of hex_str.
        """
        # Send Message to PD
        self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Search Library', Parameters = [soi_data, field_data])

    def sliceByPreamble(self, preamble, first_n, estimated_length):
        """ Sends message to PD to slice the data by a single preamble.
        """
        # Send Message to PD
        self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Slice By Preamble', Parameters = [preamble, first_n, estimated_length])

    def setBufferSize(self, min_buffer_size, max_buffer_size):
        """ Sends message to PD with the new sizes for the protocol discovery buffer.
        """
        # Send Message to PD
        self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Set Buffer Size', Parameters = [min_buffer_size, max_buffer_size])

    def clearPD_Buffer(self):
        """ Sends a message to Protocol Discovery to clear its buffer.
        """
        # Send Message to PD
        self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Clear PD Buffer')

    # def addToLibrary(self, protocol_name, packet_name, packet_data, soi_data, statistical_data, modulation_type, demodulation_fg_data, attack, dissector):
        # """ Sends a message to Protocol Discovery to add new data to the library.
        # """
        # # Send Message to PD
        # self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Add To Library', Parameters = [protocol_name, packet_name, packet_data, soi_data, statistical_data, modulation_type, demodulation_fg_data, attack, dissector])

    # def removeDemodulationFlowGraph(self, protocol_name, modulation_type, hardware, demodulation_fg):
        # """ Sends a message to Protocol Discovery to remove demodulation flow graph from the library.
        # """
        # # Send Message to PD
        # self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Remove Demodulation Flow Graph', Parameters = [protocol_name, modulation_type, hardware, demodulation_fg])

    # def removeSOI(self, protocol_name, soi):
        # """ Sends a message to Protocol Discovery to remove SOI from the library.
        # """
        # # Send Message to PD
        # self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Remove SOI', Parameters = [protocol_name, soi])

    # def removePacketType(self, protocol_name, packet_type):
        # """ Sends a message to Protocol Discovery to remove packet type from the library.
        # """
        # # Send Message to PD
        # self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Remove Packet Type', Parameters = [protocol_name, packet_type])

    # def removeModulationType(self, protocol_name, modulation_type):
        # """ Sends a message to Protocol Discovery to remove modulation type from the library.
        # """
        # # Send Message to PD
        # self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Remove Modulation Type', Parameters = [protocol_name, modulation_type])

    # def removeAttackFromLibrary(self, protocol_name, attacks, modulations, hardware, all_content, remove_flow_graphs):
        # """ Sends a message to Protocol Discovery to remove attack from the library.
        # """
        # # Send Message to PD
        # self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Remove Attack from Library', Parameters = [protocol_name, attacks, modulations, hardware, all_content, remove_flow_graphs])

    def findEntropy(self, message_length, preamble):
        """ Sends a message to Protocol Discovery to find the entropy for the bit positions of fixed-length messages.
        """
        # Send Message to PD
        self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Find Entropy', Parameters = [message_length, preamble])

    def connectToTSI(self):
        """ Connects the HIPRFISR SUB to TSI PUB. The initial connections are removed.
        """
        # Remove Connections
        tsi_default_ip_address = "127.0.0.1"
        tsi_pub_port = str(self.settings_dictionary['tsi_pub_port'])
        tsi_pub_port_id = str(self.settings_dictionary['tsi_pub_port_id'])
        tsi_pub_port_classification = str(self.settings_dictionary['tsi_pub_port_classification'])

        self.hiprfisr_sub_listener.socket.disconnect('tcp://' + tsi_default_ip_address + ':' + tsi_pub_port)
        self.hiprfisr_sub_listener.socket.disconnect('tcp://' + tsi_default_ip_address + ':' + tsi_pub_port_id)
        self.hiprfisr_sub_listener.socket.disconnect('tcp://' + tsi_default_ip_address + ':' + tsi_pub_port_classification)

        # Reconnect
        hiprfisr_default_ip_address = "127.0.0.1"
        self.hiprfisr_sub_listener.initialize_port(hiprfisr_default_ip_address,tsi_pub_port)
        self.hiprfisr_sub_listener.initialize_port(hiprfisr_default_ip_address,tsi_pub_port_id)
        self.hiprfisr_sub_listener.initialize_port(hiprfisr_default_ip_address,tsi_pub_port_classification)

    def connectToFGE(self):
        """ Connects the HIPRFISR SUB to FGE PUB. The initial connections are removed.
        """
        # Remove Connections
        fge_default_ip_address = "127.0.0.1"
        fge_pub_port = str(self.settings_dictionary['fge_pub_port'])
        self.hiprfisr_sub_listener.socket.disconnect('tcp://' + fge_default_ip_address + ':' + fge_pub_port)

        # Reconnect
        hiprfisr_default_ip_address = "127.0.0.1"
        self.hiprfisr_sub_listener.initialize_port(hiprfisr_default_ip_address,fge_pub_port)

        self.fge_local = True

        # Send the FGE Local Message Only Once
        if self.pd_connected == True:
            self.message_counter += 1

    def addPubSocket(self, ip_address, port):
        """ Signals to Protocol Discovery to add an additional ZMQ PUB for reading bits.
        """
        # Send Message to PD
        self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Add Pub Socket', Parameters = [ip_address, port])

    def removePubSocket(self, address):
        """ Signals to Protocol Discovery to remove a ZMQ PUB.
        """
        # Send Message to PD
        self.pd_hiprfisr_server.sendmsg('Commands', Identifier = 'HIPRFISR', MessageName = 'Remove Pub Socket', Parameters = [address])


########################################################################
########################## Library Functions ###########################
########################################################################

    def addToLibrary(self,protocol_name, packet_name, packet_data, soi_data, statistical_data, modulation_type, demodulation_fg_data, attack, dissector):
        """ Adds new data to the library.
        """
        # Make a Backup of the Current Library
        stream = open(os.path.dirname(os.path.realpath(__file__)) + '/YAML/Library Backups/library_backup_add.yaml', 'w')
        yaml.dump(self.pd_library, stream, default_flow_style=False, indent=5)

        # Check Protocol
        protocol_exists = False
        for protocol in getProtocols(self.pd_library):
            # Existing Protocol
            if protocol == protocol_name:
                protocol_exists = True

                # Add New Modulation Type
                if len(modulation_type) > 0:
                    if modulation_type not in getModulations(self.pd_library, protocol):
                        addModulation(self.pd_library, protocol, modulation_type)

                # Add New Packet Type
                if len(packet_data) > 0:
                    all_new_fields = {}
                    for n in range(0,len(packet_data)):
                        field_name = packet_data[n][0]
                        field_length = packet_data[n][1]
                        field_default = packet_data[n][2]
                        field_order = n+1
                        is_crc = packet_data[n][3]
                        crc_range = packet_data[n][4]

                        field_to_add  = newField(field_name,field_default,field_length,field_order,is_crc,crc_range)
                        all_new_fields.update(field_to_add)

                    # Create New Packet Type
                    packet_to_add = newPacket(packet_name,all_new_fields)
                    packet_to_add[packet_name]['Sort Order'] = len(getPacketTypes(self.pd_library,protocol)) + 1  # Makes the packet appear on the bottom of any list

                    # Add it to the Protocol
                    addPacketType(self.pd_library, protocol, packet_to_add)
                    addDissector(self.pd_library, protocol, packet_name, None, None)

                # Add Dissector
                if len(dissector) > 0:
                    addDissector(self.pd_library, protocol, packet_name, dissector[0], dissector[1])

                # Add SOI Data
                if len(soi_data) > 0:
                    soi = newSOI(soi_data[0], soi_data[1], soi_data[2], soi_data[3], soi_data[4], soi_data[5], soi_data[6], soi_data[7])
                    addSOI(self.pd_library, protocol, soi)

                # Add Demodulation Flow Graph
                if len(demodulation_fg_data) > 0:
                    if (len(demodulation_fg_data[0]) > 0) and (len(demodulation_fg_data[1]) > 0) and (len(demodulation_fg_data[2]) > 0) and (len(demodulation_fg_data[3]) > 0):
                        addDemodulationFlowGraph(self.pd_library, protocol, demodulation_fg_data[0], demodulation_fg_data[1], demodulation_fg_data[2], demodulation_fg_data[3])  # [0] = mod. type, [1] = flow graph name, [2] = hardware

                # Add Attack
                if len(attack) > 0:
                    attack_dict = {attack[0]:{attack[1]:{attack[2]:{attack[3]:{attack[4]:attack[5]}}}}}
                    addAttack(self.pd_library, protocol_name, attack)

        # New Protocol
        if protocol_exists == False:
            make_new_protocol = newProtocol(protocolname=protocol_name)
            addProtocol(self.pd_library, make_new_protocol)

        # Save File
        stream = open(os.path.dirname(os.path.realpath(__file__)) + '/YAML/library.yaml', 'w')
        yaml.dump(self.pd_library, stream, default_flow_style=False, indent=5)

        # Send Message to Components to Update Library
        self.hiprfisr_pub_server.sendmsg('Status', Identifier = 'HIPRFISR', MessageName='Full Library', Parameters=self.pd_library)


    def removeDemodulationFlowGraph(self, protocol_name, modulation_type, hardware, demodulation_fg):
        """ Removes demodulation flow graph from the library.
        """
        # Make a Backup of the Current Library
        stream = open(os.path.dirname(os.path.realpath(__file__)) + '/YAML/Library Backups/library_backup_remove.yaml', 'w')
        yaml.dump(self.pd_library, stream, default_flow_style=False, indent=5)

        # Delete Demodulation Flow Graph From Library
        removeDemodulationFlowGraph(self.pd_library, protocol_name, modulation_type, hardware, demodulation_fg)

        # Delete Files (*.py, *.pyc, *.grc) from Flow Graph Library
        if demodulation_fg != None:
            try:
                os.remove(os.path.dirname(os.path.realpath(__file__)) + "/Flow Graph Library/PD Flow Graphs/" + demodulation_fg)
            except:
                pass
            try:
                os.remove(os.path.dirname(os.path.realpath(__file__)) + "/Flow Graph Library/PD Flow Graphs/" + demodulation_fg.replace(".py",".pyc"))
            except:
                pass
            try:
                os.remove(os.path.dirname(os.path.realpath(__file__)) + "/Flow Graph Library/PD Flow Graphs/" + demodulation_fg.replace(".py",".grc"))
            except:
                pass

        # Save File
        stream = open(os.path.dirname(os.path.realpath(__file__)) + '/YAML/library.yaml', 'w')
        yaml.dump(self.pd_library, stream, default_flow_style=False, indent=5)

        # Send Message to Components to Update Library
        self.hiprfisr_pub_server.sendmsg('Status', Identifier = 'HIPRFISR', MessageName='Full Library', Parameters=self.pd_library)

    def removeSOI(self, protocol_name, soi):
        """ Removes SOI from the library.
        """
        # Make a Backup of the Current Library
        stream = open(os.path.dirname(os.path.realpath(__file__)) + '/YAML/Library Backups/library_backup_remove.yaml', 'w')
        yaml.dump(self.pd_library, stream, default_flow_style=False, indent=5)

        # Delete SOI From Library
        removeSOI(self.pd_library, protocol_name, soi)

        # Save File
        stream = open(os.path.dirname(os.path.realpath(__file__)) + '/YAML/library.yaml', 'w')
        yaml.dump(self.pd_library, stream, default_flow_style=False, indent=5)

        # Send Message to Components to Update Library
        self.hiprfisr_pub_server.sendmsg('Status', Identifier = 'HIPRFISR', MessageName='Full Library', Parameters=self.pd_library)

    def removePacketType(self, protocol_name, packet_type):
        """ Removes packet type from the library.
        """
        # Make a Backup of the Current Library
        stream = open(os.path.dirname(os.path.realpath(__file__)) + '/YAML/Library Backups/library_backup_remove.yaml', 'w')
        yaml.dump(self.pd_library, stream, default_flow_style=False, indent=5)

        # Delete Packet Type From Library
        removePacketType(self.pd_library, protocol_name, packet_type)

        # Save File
        stream = open(os.path.dirname(os.path.realpath(__file__)) + '/YAML/library.yaml', 'w')
        yaml.dump(self.pd_library, stream, default_flow_style=False, indent=5)

        # Send Message to Components to Update Library
        self.hiprfisr_pub_server.sendmsg('Status', Identifier = 'HIPRFISR', MessageName='Full Library', Parameters=self.pd_library)

    def removeModulationType(self, protocol_name, modulation_type):
        """ Removes modulation type from the library.
        """
        # Make a Backup of the Current Library
        stream = open(os.path.dirname(os.path.realpath(__file__)) + '/YAML/Library Backups/library_backup_remove.yaml', 'w')
        yaml.dump(self.pd_library, stream, default_flow_style=False, indent=5)

        # Delete Modulation Type From Library
        removeModulationType(self.pd_library, protocol_name, modulation_type)

        # Save File
        stream = open(os.path.dirname(os.path.realpath(__file__)) + '/YAML/library.yaml', 'w')
        yaml.dump(self.pd_library, stream, default_flow_style=False, indent=5)

        # Send Message to Components to Update Library
        self.hiprfisr_pub_server.sendmsg('Status', Identifier = 'HIPRFISR', MessageName='Full Library', Parameters=self.pd_library)

    def removeAttackFromLibrary(self,protocol_name, attacks, modulations, hardware, all_content, remove_flow_graphs):
        """ Removes attacks from the library.
        """
        # Make a Backup of the Current Library
        stream = open(os.path.dirname(os.path.realpath(__file__)) + '/YAML/Library Backups/library_backup_remove.yaml', 'w')
        yaml.dump(self.pd_library, stream, default_flow_style=False, indent=5)

        # Delete Attacks From Library
        flow_graph_delete_list = []
        for a in attacks:
            for m in modulations:
                if len(self.pd_library["Protocols"][protocol_name]["Attacks"][a]) > 0:
                    if m in self.pd_library["Protocols"][protocol_name]["Attacks"][a]:
                        for h in hardware:
                            if len(self.pd_library["Protocols"][protocol_name]["Attacks"][a][m]) > 0:
                                if h in self.pd_library["Protocols"][protocol_name]["Attacks"][a][m]["Hardware"].keys():
                                    # Get the Flow Graph Name
                                    get_file_type = self.pd_library["Protocols"][protocol_name]["Attacks"][a][m]["Hardware"][h].keys()[0]
                                    flow_graph_delete_list.append(self.pd_library["Protocols"][protocol_name]["Attacks"][a][m]["Hardware"][h][get_file_type])
                                    del self.pd_library["Protocols"][protocol_name]["Attacks"][a][m]["Hardware"][h]
                                    if len(self.pd_library["Protocols"][protocol_name]["Attacks"][a][m]["Hardware"]) == 0:
                                        del self.pd_library["Protocols"][protocol_name]["Attacks"][a][m]["Hardware"]
                        if len(self.pd_library["Protocols"][protocol_name]["Attacks"][a][m]) == 0:
                            del self.pd_library["Protocols"][protocol_name]["Attacks"][a][m]
            if len(self.pd_library["Protocols"][protocol_name]["Attacks"][a]) == 0:
                del self.pd_library["Protocols"][protocol_name]["Attacks"][a]
        try:
            if len(self.pd_library["Protocols"][protocol_name]["Attacks"]) == 0:
                del self.pd_library["Protocols"][protocol_name]["Attacks"]
        except:
            # Avoids ["Attacks"] Key Errors
            pass

        # Determine if Deleted Attack was the Last of its Name
        no_more_attacks = len(attacks)*[False]
        for n in range(0,len(attacks)):
            try:
                if len(self.pd_library["Protocols"][protocol_name]["Attacks"][n]) == 0:
                    no_more_attacks[n] = True
            except KeyError as e:
                no_more_attacks[n] = True

        # Delete Attacks from Library Tree
        for n in range(0,len(no_more_attacks)):
            if no_more_attacks[n] == True:
                try:
                    self.pd_library["Attacks"]["Single-Stage Attacks"].remove([item for item in self.pd_library["Attacks"]["Single-Stage Attacks"] if item.split(',')[0] == attacks[n]][0])
                    self.pd_library["Attacks"]["Multi-Stage Attacks"].remove([item for item in self.pd_library["Attacks"]["Multi-Stage Attacks"] if item.split(',')[0] == attacks[n]][0])
                    self.pd_library["Attacks"]["Fuzzing Attacks"].remove([item for item in self.pd_library["Attacks"]["Fuzzing Attacks"] if item.split(',')[0] == attacks[n]][0])
                except:
                    pass

        # Delete Files (*.py, *.pyc, *.grc) from Flow Graph Library
        if remove_flow_graphs == True:
            if len(flow_graph_delete_list) > 0:
                for f in flow_graph_delete_list:
                    if f != "None":
                        try:
                            os.remove(os.path.dirname(os.path.realpath(__file__)) + "/Flow Graph Library/Single-Stage Flow Graphs/" + f)
                        except:
                            pass
                        try:
                            os.remove(os.path.dirname(os.path.realpath(__file__)) + "/Flow Graph Library/Single-Stage Flow Graphs/" + f.replace(".py",".pyc"))
                        except:
                            pass
                        try:
                            os.remove(os.path.dirname(os.path.realpath(__file__)) + "/Flow Graph Library/Single-Stage Flow Graphs/" + f.replace(".py",".grc"))
                        except:
                            pass

        # Delete All Protocol Content
        if all_content == True:
            del self.pd_library["Protocols"][protocol_name]

        # Save File
        stream = open(os.path.dirname(os.path.realpath(__file__)) + '/YAML/library.yaml', 'w')
        yaml.dump(self.pd_library, stream, default_flow_style=False, indent=5)

        # Send Message to Components to Update Library
        self.hiprfisr_pub_server.sendmsg('Status', Identifier = 'HIPRFISR', MessageName='Full Library', Parameters=self.pd_library)

########################################################################

if __name__=="__main__":
    # Create HIPRFISR Object
    hiprfisr_object = Hiprfisr()



