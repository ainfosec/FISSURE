#!/usr/bin/env python

import time
import random
import yaml
import zmq
import threading
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/Flow Graph Library/TSI Flow Graphs')
# from gnuradio import blocks 
# from gnuradio import gr
# from gnuradio import uhd
# from gnuradio import zeromq
# from gnuradio import audio
import inspect,types
import csv
from fissureclass import fissure_listener
from fissureclass import fissure_server
import subprocess

    
# Insert Any Argument While Executing to Run Locally
try:
    run_local = sys.argv[1]
except:
    run_local = None   
    
class TSI_Component: 
    """ Class that contains the functions for the TSI component. 
    """
    #######################  FISSURE Functions  ########################
    def __init__(self):
        """ The start of the TSI component.
        """
        self.dashboard_connected = False
        self.hiprfisr_connected = False

        self.heartbeat_interval = 5
        self.tsi_heartbeat_time = 0
        self.running_TSI = False
        self.running_TSI_simulator = False
        self.blacklist = []
        self.running_TSI_wideband = False
        self.configuration_update = False
        self.detector_script_name = ""
        
        # Create the TSI ZMQ Sockets
        self.connect()

        # Main Event Loop
        try:
            while True:
                #print("TSI LOOPING")
                # TSI Activated
                if self.running_TSI == True:                 
                    # Add Messages Randomly (For Testing)
                    if (self.dashboard_connected | self.hiprfisr_connected) == True:
                        pass
                        #self.addRandomTSI_Message(random.random())
                        #self.addRandomAMC_Message(random.random())                   
                
                # Read Messages in the ZMQ Queues
                if self.hiprfisr_connected == True:
                    self.readHIPRFISR_Messages()
                self.readSUB_Messages()
                
                # Send the TSI Heartbeat if Interval Time has Elapsed
                self.sendHeartbeat()
                                        
                # Check for Received Heartbeats
                #self.checkHeartbeats()  # TSI Error Handling
                     
                time.sleep(1)

        except KeyboardInterrupt:       
            pass
            
    def connect(self):
        """ Connects all the 0MQ Servers and Listeners 
        """  
        # Load Settings from YAML File
        self.loadConfiguration()
        
        # Create Connections
        hiprfisr_ip_address = "127.0.0.1"
            
        # TSI Dealer
        tsi_dealer_port = int(self.settings_dictionary['tsi_hiprfisr_dealer_port'])
        self.tsi_hiprfisr_listener = fissure_listener(os.path.dirname(os.path.realpath(__file__)) + '/YAML/tsi.yaml','localhost',tsi_dealer_port,zmq.DEALER, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "tsi")
                
        # TSI PUB
        tsi_pub_port = int(self.settings_dictionary['tsi_pub_port'])
        self.tsi_pub_server = fissure_server(os.path.dirname(os.path.realpath(__file__)) + '/YAML/tsi.yaml','*',tsi_pub_port,zmq.PUB, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "tsi")
            
        # TSI SUB
        dashboard_pub_port = int(self.settings_dictionary['dashboard_pub_port'])
        hiprfisr_pub_port = int(self.settings_dictionary['hiprfisr_pub_port'])

        # TSI SUB to HIPRFISR PUB
        try:
            self.tsi_sub_listener = fissure_listener(os.path.dirname(os.path.realpath(__file__)) + '/YAML/tsi.yaml',hiprfisr_ip_address,hiprfisr_pub_port,zmq.SUB, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "tsi")
            sub_connected = True
        except:
            print("Error creating TSI SUB and connecting to HIPRFISR PUB")
            
        # TSI SUB to Dashboard PUB
        try:
            self.tsi_sub_listener.initialize_port(hiprfisr_ip_address,dashboard_pub_port)  
        except:
            print("Unable to connect TSI SUB to Dashboard PUB") 
            
    def readSUB_Messages(self):
        """ Read all the messages in the self.tsi_sub_listener and handle accordingly
        """ 
        # Check for Messages
        parsed = ''
        while parsed != None:
            parsed = self.tsi_sub_listener.recvmsg()   
            if parsed != None:               
                # Check for Heartbeats
                if parsed['Identifier'] == 'Dashboard':
                    self.dashboard_connected = True
                                            
                elif parsed['Identifier'] == 'HIPRFISR':
                    self.hiprfisr_connected = True
                    if parsed['Type'] == 'Status':  
                        if parsed['MessageName'] == 'Full Library':                        
                            pass
                            #self.pd_library = yaml.load(parsed['Parameters'], yaml.FullLoader)  # Not used for anything yet

                # Handle Messages/Execute Callbacks as Usual
                else:
                    if parsed['Type'] == 'Heartbeats':
                        # Update Heartbeat Related Variables    
                        pass        

    def readHIPRFISR_Messages(self):
        """ Sort through any HIPRFISR messages
        """     
        # Check for Messages
        parsed = ''
        while parsed != None:
            parsed = self.tsi_hiprfisr_listener.recvmsg()   
            if parsed != None:                              
                # Handle Messages/Execute Callbacks 
                self.tsi_hiprfisr_listener.runcallback(self,parsed)  # Calls the function associated with the callback
            
    def sendHeartbeat(self):
        """ Sends the heartbeat to all subscribers
        """       
        current_time = time.time()
        if self.tsi_heartbeat_time < current_time - self.heartbeat_interval:
            self.tsi_heartbeat_time = current_time
            self.tsi_pub_server.sendmsg('Heartbeats', Identifier = 'TSI', MessageName='Heartbeat', Time=current_time)                        
            
    def loadConfiguration(self):
        """ Loads a configuration YAML file with all the FISSURE user settings.
        """
        # Load Settings from YAML File
        filename = os.path.dirname(os.path.realpath(__file__)) + "/YAML/fissure_config.yaml"
        yaml_config_file = open(filename)
        self.settings_dictionary = yaml.load(yaml_config_file, yaml.FullLoader)
        yaml_config_file.close()   
       
            
    #######################  Generic Functions  ########################
    
    def updateFISSURE_Configuration(self):
        """ Reload fissure_config.yaml after changes.
        """
        # Update FGE Dictionary
        self.settings_dictionary = self.loadConfiguration()

    def isFloat(self, x):
        """ Returns "True" if the input is a Float. Returns "False" otherwise.
        """
        try:
            float(x)
        except ValueError:
            return False
        return True
        
    def overwriteFlowGraphVariables(self, flow_graph_filename, variable_names, variable_values):
        # Check for string_variables
        for n in range(0,len(variable_names)):
            if variable_names[n] == "string_variables":
                fix_strings = True
                fix_strings_index = n
                break
            else:
                fix_strings = False
                fix_strings_index = None
        
        # Load New Flow Graph
        flow_graph_filename = flow_graph_filename.rsplit("/",1)[-1]            
        flow_graph_filename = flow_graph_filename.replace(".py","")          
        loadedmod = __import__(flow_graph_filename)  # Don't need to reload() because the original never changes
        
        # Update the Text in the Code
        stistr = inspect.getsource(loadedmod)
        variable_line_position = 0
        new_stistr = ""        
        for line in iter(stistr.splitlines()):
            if len(variable_names) > 0:

                # Change Variable Values
                if variable_line_position == 2:
                    
                    # Reached the End of the Variables Section
                    if line.strip() == "":
                        variable_line_position = 3
                        
                    # Change Value    
                    else:             
                        variable_name = line.split("=",2)[1]  # Only the first two '=' in case value has '='
                        
                        # Ignore Notes
                        if variable_name.replace(' ','') != "notes":
                            old_value = line.split("=",2)[-1]  
                            index = variable_names.index(variable_name.replace(" ",""))
                            new_value = variable_values[index]                       
                            
                            # A Number
                            if self.isFloat(new_value):
                                # Make Numerical Value a String
                                if fix_strings == True:
                                    if variable_name.strip() in variable_values[fix_strings_index]:
                                        new_value = '"' + new_value + '"'                                   

                            # A String
                            else:
                                new_value = '"' + new_value + '"'
                            
                            new_line = line.split("=",2)[0] + " = " + line.split("=",2)[1] + ' = ' + new_value + "\n"
                            new_stistr += new_line

                # Write Unreplaced Contents
                if variable_line_position != 2:    
                    new_stistr += line + "\n"
                    
                # Skip "#################################" Line after "# Variables"
                if variable_line_position == 1:
                    variable_line_position = 2
                    
                # Find Line Containing "# Variables"    
                if "# Variables" in line:
                    variable_line_position = 1
                
            # Find Class Name
            if "class " in line and "(gr." in line:    
                class_name = line.split(" ")[1]
                class_name = class_name.split("(")[0]
        
        # Compile
        sticode=compile(new_stistr,'<string>','exec')
        loadedmod = types.ModuleType('stiimp')
        exec(sticode, loadedmod.__dict__)
        
        return loadedmod, class_name
        
    def setVariable(self, flow_graph, variable, value):
        """ Sets a variable of a specified running flow graph.
        """
        # Make it Match GNU Radio Format
        formatted_name = "set_" + variable
        isNumber = self.isFloat(value)   
        if isNumber:
            if flow_graph == "Wideband":
                getattr(self.wideband_flowtoexec,formatted_name)(float(value))
        else:
            if flow_graph == "Wideband":
                getattr(self.wideband_flowtoexec,formatted_name)(value)  
            
    #######################  TSI Detector Flow Graphs  ##########################
    def startTSI_Detector(self, detector, variable_names, variable_values):
        """ Begins TSI processing of signals after receiving the command from the HIPRFISR
        """        
        self.running_TSI = True
        print("TSI: Starting TSI Detector...")
        
        # Make a New Wideband Thread
        if len(detector) > 0:
            if detector == "wideband_x3x0.py":
                flow_graph_filename = "wideband_x3x0.py"
            elif detector == "wideband_b2x0.py":
                flow_graph_filename = "wideband_b2x0.py"  
            elif detector == "wideband_hackrf.py":
                flow_graph_filename = "wideband_hackrf.py"
            elif detector == "wideband_b20xmini.py":
                flow_graph_filename = "wideband_b20xmini.py"         
            elif detector == "wideband_rtl2832u.py":
                flow_graph_filename = "wideband_rtl2832u.py"
            elif detector == "wideband_limesdr.py":
                flow_graph_filename = "wideband_limesdr.py"
            elif detector == "wideband_bladerf.py":
                flow_graph_filename = "wideband_bladerf.py"
            elif detector == "wideband_plutosdr.py":
                flow_graph_filename = "wideband_plutosdr.py"
            elif detector == "wideband_usrp2.py":
                flow_graph_filename = "wideband_usrp2.py"
            elif detector == "wideband_usrp_n2xx.py":
                flow_graph_filename = "wideband_usrp_n2xx.py"
            elif detector == "wideband_bladerf2.py":
                flow_graph_filename = "wideband_bladerf2.py"
            elif detector == "wideband_usrp_x410.py":
                flow_graph_filename = "wideband_usrp_x410.py"
            elif detector == "IQ File":
                flow_graph_filename = "iq_file.py"
            elif "fixed_threshold" in detector:
                if detector == "fixed_threshold_x3x0.py":
                    flow_graph_filename = "fixed_threshold_x3x0.py"
                elif detector == "fixed_threshold_b2x0.py":
                    flow_graph_filename = "fixed_threshold_b2x0.py"  
                elif detector == "fixed_threshold_hackrf.py":
                    flow_graph_filename = "fixed_threshold_hackrf.py"
                elif detector == "fixed_threshold_b20xmini.py":
                    flow_graph_filename = "fixed_threshold_b20xmini.py"         
                elif detector == "fixed_threshold_rtl2832u.py":
                    flow_graph_filename = "fixed_threshold_rtl2832u.py"
                elif detector == "fixed_threshold_limesdr.py":
                    flow_graph_filename = "fixed_threshold_limesdr.py"
                elif detector == "fixed_threshold_bladerf.py":
                    flow_graph_filename = "fixed_threshold_bladerf.py"
                elif detector == "fixed_threshold_plutosdr.py":
                    flow_graph_filename = "fixed_threshold_plutosdr.py"
                elif detector == "fixed_threshold_usrp2.py":
                    flow_graph_filename = "fixed_threshold_usrp2.py"
                elif detector == "fixed_threshold_usrp_n2xx.py":
                    flow_graph_filename = "fixed_threshold_usrp_n2xx.py"
                elif detector == "fixed_threshold_bladerf2.py":
                    flow_graph_filename = "fixed_threshold_bladerf2.py"
                elif detector == "fixed_threshold_usrp_x410.py":
                    flow_graph_filename = "fixed_threshold_usrp_x410.py"
                elif detector == "fixed_threshold_simulator.py":
                    flow_graph_filename = "fixed_threshold_simulator.py"
                stop_event = threading.Event()
                c_thread = threading.Thread(target=self.detectorFlowGraphGUI_Thread, args=(stop_event,flow_graph_filename,variable_names,variable_values))
                c_thread.daemon = True
                c_thread.start()
                return
            
            # Simulator Detector Thread
            if detector == "Simulator":
                stop_event = threading.Event()
                c_thread = threading.Thread(target=self.runDetectorSimulatorThread, args=(variable_names,variable_values))
                c_thread.start()  
                
            # Flow Graph Detector Thread
            else:                               
                class_name = flow_graph_filename.replace(".py","")
                stop_event = threading.Event()
                c_thread = threading.Thread(target=self.runWidebandThread, args=(stop_event,class_name,variable_names,variable_values))
                c_thread.start()  
        
    def startWidebandThread(self):
        """ Begins TSI wideband sweeping
        """          
        self.running_TSI_wideband = True             
        
        variable_names = []
        variable_values = []
        class_name = []
        
        # Make a New Wideband Update Thread
        stop_event2 = threading.Event()
        c_thread2 = threading.Thread(target=self.widebandUpdateThread, args=(stop_event2,class_name,variable_names,variable_values))
        c_thread2.start()
        
    def stopWidebandThread(self):
        """ Stops TSI wideband sweeping
        """                       
        # Make a New Wideband Update Thread
        self.running_TSI_wideband = False   
                        
    def runWidebandThread(self, stop_event, flow_graph_filename, variable_names, variable_values):
        """ Runs the flow graph in the new thread.
        """       
        # Stop Any Running Wideband Flow Graphs
        try:
            self.wideband_flowtoexec.stop()
            self.wideband_flowtoexec.wait()         
            del self.wideband_flowtoexec  # Free up the ports
        except:
            pass
        
        # Overwrite Variables
        loadedmod, class_name = self.overwriteFlowGraphVariables(flow_graph_filename, variable_names, variable_values)
        
        # Call the "__init__" Function
        self.wideband_flowtoexec = getattr(loadedmod,class_name)() 
        
        # Start it
        self.wideband_flowtoexec.start()      
        self.wideband_flowtoexec.wait()            
                    
        # # Error Loading Flow Graph              
        # except Exception as e:
            # print("Error: " + str(e))
            # self.running_TSI = False
            # self.running_wideband = False
            # self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Detector Flow Graph Error', Parameters = e)  
        
    def runDetectorSimulatorThread(self, variable_names, variable_values):
        """ Runs the simulator in the new thread.
        """       
        print("SIMULATOR THREAD STARTED")
        self.running_TSI_simulator = True
        
        while self.running_TSI_simulator == True:      
            
            # Open CSV Simulator File
            with open(variable_values[0], "r") as f:
                reader = csv.reader(f, delimiter=",")
                      
                for i, line in enumerate(reader):
                    # Skip First Row
                    if int(i) > 0:
                        self.tsi_pub_server.sendmsg('Wideband', Identifier = 'TSI', MessageName = 'Signal Found', Frequency = int(line[0]), Power = int(line[1]), Timestamp = time.time())
                        time.sleep(float(line[2]))
 
    def widebandUpdateThread(self, stop_event, class_name, variable_names, variable_values):
        """ Updates the wideband flow graph parameters in the new thread.
        """ 
        print("WIDEBAND UPDATE THREAD STARTED!!!")
        #print(self.running_TSI_wideband)
        #print(self.wideband_band)
        #print(self.wideband_start_freq[self.wideband_band])
        
        # Wideband Sweep Logic
        new_freq = self.wideband_start_freq[self.wideband_band]
        while self.running_TSI_wideband == True:
            try:
                # Check for Configuration Update
                if self.configuration_updated == True:
                    new_freq = self.wideband_start_freq[0]
                    self.configuration_updated = False
                    
                # Update Flow Graph
                self.setVariable("Wideband","rx_freq",new_freq)
                
                # Send Frequency and Band Status to Dashboard
                self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'BandID', Parameters = [self.wideband_band+1,new_freq]) 

                # Step Frequency
                new_freq = new_freq + self.wideband_step_size[self.wideband_band]
                
                # Passed Stop Frequency
                if new_freq > self.wideband_stop_freq[self.wideband_band]:
                    # Increase Band
                    self.wideband_band = self.wideband_band + 1
                    
                    # Reset Band
                    if self.wideband_band >= len(self.wideband_start_freq):
                        self.wideband_band = 0
                    
                    # Begin at Start Frequency
                    new_freq = self.wideband_start_freq[self.wideband_band]

                # Check Blacklist
                not_in_blacklist = False
                while not_in_blacklist == False:
                    not_in_blacklist = True
                    for n in range(0,len(self.blacklist)):                        
                        if self.blacklist[n][0] <= new_freq <= self.blacklist[n][1]:
                            not_in_blacklist = False

                            # Step Frequency
                            new_freq = new_freq + self.wideband_step_size[self.wideband_band]
                            
                            # Passed Stop Frequency
                            if new_freq > self.wideband_stop_freq[self.wideband_band]:
                                # Increase Band
                                self.wideband_band = self.wideband_band + 1
                                
                                # Reset Band
                                if self.wideband_band >= len(self.wideband_start_freq):
                                    self.wideband_band = 0
                                
                                # Begin at Start Frequency
                                new_freq = self.wideband_start_freq[self.wideband_band]                                                   
            except:
                pass
                
            # Dwell on Frequency
            time.sleep(self.wideband_dwell[self.wideband_band])
                    
    def stopTSI_Detector(self):
        """ Pauses TSI processing of signals after receiving the command from the HIPRFISR
        """    
        print("TSI: Stopping TSI Detector...")
        self.running_TSI = False
        self.running_TSI_wideband = False
        
        if self.running_TSI_simulator == True:            
            self.running_TSI_simulator = False
        elif len(self.detector_script_name) > 0:
            self.detectorFlowGraphStop('Flow Graph - GUI')
        else:        
            try:
                # Stop Flow Graphs
                self.wideband_flowtoexec.stop()
                self.wideband_flowtoexec.wait()         
                del self.wideband_flowtoexec  # Free up the ports
            except:
                pass
            
########################################################################
    def detectorFlowGraphStop(self, parameter):
        """ Stop the currently running detector flow graph.
        """
        # Only Supports Flow Graphs with GUIs
        if (parameter == "Flow Graph - GUI") and (len(self.detector_script_name) > 0):
            os.system("pkill -f " + '"' + self.detector_script_name +'"')
            self.detector_script_name = ""
            
    def detectorFlowGraphGUI_Thread(self, stop_event, flow_graph_filename, variable_names, variable_values):
        """ Runs the detector flow graph in the new thread.
        """
        try:                      
            # Start it
            filepath = os.path.dirname(os.path.realpath(__file__)) + '/Flow Graph Library/TSI Flow Graphs/' + flow_graph_filename
            arguments = ""            
            for n in range(0,len(variable_names)):
                arguments = arguments + '--' + variable_names[n] + '="' + variable_values[n] + '" '
                
            osCommandString = "python3 " + '"' + filepath + '" ' + arguments
            proc = subprocess.Popen(osCommandString + " &", shell=True)
              
            #self.flowGraphStarted("Inspection")  # Signals to other components 
            self.detector_script_name = flow_graph_filename
 
        # Error Loading Flow Graph              
        except Exception as e:
            print(str(e))
            print("ERROR")
            #self.flowGraphStarted("Inspection")
            #self.flowGraphFinished("Inspection")     
            # ~ self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Error', Parameters = e)  # Custom error message if necessary
            #~ #raise e

########################################################################                    
            
    def addRandomTSI_Message(self, random_number):
        """ Sends a random message over a connection for testing purposes
        """ 
        # Pick a Random Message to Send to the Dashboard/HIPRFISR
        if 0 < random_number <= 0.05:
            self.tsi_pub_server.sendmsg('Wideband', Identifier = 'TSI', MessageName = 'Signal Found', Frequency = 1240000000, Power = -13, Timestamp = time.time() )
        elif 0.05< random_number <= 0.10:
            self.tsi_pub_server.sendmsg('Wideband', Identifier = 'TSI', MessageName = 'Signal Found', Frequency = 2260000000, Power = -55, Timestamp = time.time() )
        elif 0.10 < random_number <= 0.15:
            self.tsi_pub_server.sendmsg('Wideband', Identifier = 'TSI', MessageName = 'Signal Found', Frequency = 4860000000, Power = 15, Timestamp = time.time() )
        elif 0.15 < random_number <= 0.20:
            self.tsi_pub_server.sendmsg('Wideband', Identifier = 'TSI', MessageName = 'Signal Found', Frequency = 2400000000, Power = -19, Timestamp = time.time() )
        elif 0.20 < random_number <= 0.25:
            self.tsi_pub_server.sendmsg('Wideband', Identifier = 'TSI', MessageName = 'Signal Found', Frequency = 5200000000, Power = -33, Timestamp = time.time() )
        elif 0.25 < random_number <= 0.30:
            self.tsi_pub_server.sendmsg('Wideband', Identifier = 'TSI', MessageName = 'Signal Found', Frequency = 4400000000, Power = -54, Timestamp = time.time() )
        elif 0.30 < random_number <= 0.35:
            pass
        elif 0.35 < random_number <= 0.40:
            pass
        elif 0.40 < random_number <= 0.45:
            pass
        elif 0.45 < random_number <= 0.50:
            pass
        elif 0.50 < random_number <= 0.55:
            pass
        elif 0.55 < random_number <= 0.60:
            pass
        elif 0.60 < random_number <= 0.65:
            pass
        elif 0.65 < random_number <= 0.70:
            pass        
        elif 0.70 < random_number <= 0.75:
            pass    
        elif 0.75 < random_number <= 0.80:
            pass
        elif 0.80 < random_number <= 0.85:
            pass
        elif 0.85 < random_number <= 0.90:
            pass
        elif 0.90 < random_number <= 0.95:
            pass
        elif 0.95 < random_number <= 1.00:
            pass
        
            
    def addRandomAMC_Message(self, random_number):
        """ Sends a random message over a connection for testing purposes
        """ 
        # Pick a Random Message to Send to the Dashboard/HIPRFISR
        if 0 < random_number <= 0.05:
            self.tsi_pub_server.sendmsg('SOI', Identifier = 'TSI', MessageName = 'Signal Classification', ModulationType = 'FSK', Frequency = 92000000, Power = -25, Bandwidth = 1000000, Continuous = False, StartFrequency = 920000000, EndFrequency = 920000000, Timestamp = time.time(), Confidence = 99.0  )
        elif 0.05< random_number <= 0.10:
            self.tsi_pub_server.sendmsg('SOI', Identifier = 'TSI', MessageName = 'Signal Classification', ModulationType = 'FSK', Frequency = 2450000000, Power = -43, Bandwidth = 1000000, Continuous = False, StartFrequency = 920000000, EndFrequency = 920000000, Timestamp = time.time(), Confidence = 94.0)
        elif 0.10 < random_number <= 0.15:
            self.tsi_pub_server.sendmsg('SOI', Identifier = 'TSI', MessageName = 'Signal Classification', ModulationType = 'FSK', Frequency = 2310000000, Power = -36, Bandwidth = 1000000, Continuous = False, StartFrequency = 920000000, EndFrequency = 920000000, Timestamp = time.time(), Confidence = 93.0)
        elif 0.15 < random_number <= 0.20:
            self.tsi_pub_server.sendmsg('SOI', Identifier = 'TSI', MessageName = 'Signal Classification', ModulationType = 'FM', Frequency = 96900000, Power = 16, Bandwidth = 1000000, Continuous = False, StartFrequency = 920000000, EndFrequency = 920000000, Timestamp = time.time(), Confidence = 45.0)
        elif 0.20 < random_number <= 0.25:
            self.tsi_pub_server.sendmsg('SOI', Identifier = 'TSI', MessageName = 'Signal Classification', ModulationType = 'FM', Frequency = 94900000, Power = 17, Bandwidth = 1000000, Continuous = False, StartFrequency = 920000000, EndFrequency = 920000000, Timestamp = time.time(), Confidence = 39.0)
        elif 0.25 < random_number <= 0.30:
            self.tsi_pub_server.sendmsg('SOI', Identifier = 'TSI', MessageName = 'Signal Classification', ModulationType = 'FM', Frequency = 102500000, Power = 18, Bandwidth = 1000000, Continuous = False, StartFrequency = 920000000, EndFrequency = 920000000, Timestamp = time.time(), Confidence = 34.0)
        elif 0.30 < random_number <= 0.35:
            self.tsi_pub_server.sendmsg('SOI', Identifier = 'TSI', MessageName = 'Signal Classification', ModulationType = 'GFSK', Frequency = 1970000000, Power = -5, Bandwidth = 1000000, Continuous = False, StartFrequency = 920000000, EndFrequency = 920000000, Timestamp = time.time(), Confidence = 43.0)
        elif 0.35 < random_number <= 0.40:
            self.tsi_pub_server.sendmsg('SOI', Identifier = 'TSI', MessageName = 'Signal Classification', ModulationType = 'BPSK', Frequency = 920000000, Power = -25, Bandwidth = 1000000, Continuous = False, StartFrequency = 920000000, EndFrequency = 920000000, Timestamp = time.time(), Confidence = 12.4)
        elif 0.40 < random_number <= 0.45:
            self.tsi_pub_server.sendmsg('SOI', Identifier = 'TSI', MessageName = 'Signal Classification', ModulationType = 'QPSK', Frequency = 3920000000, Power = 15, Bandwidth = 1000000, Continuous = False, StartFrequency = 920000000, EndFrequency = 920000000, Timestamp = time.time(), Confidence = 9.4) 
        elif 0.45 < random_number <= 0.50:
            self.tsi_pub_server.sendmsg('SOI', Identifier = 'TSI', MessageName = 'Signal Classification', ModulationType = 'MSK', Frequency = 3920000000, Power = 15, Bandwidth = 1000000, Continuous = False, StartFrequency = 920000000, EndFrequency = 920000000, Timestamp = time.time(), Confidence = 9.4)  
        elif 0.50 < random_number <= 0.55:
            self.tsi_pub_server.sendmsg('SOI', Identifier = 'TSI', MessageName = 'Signal Classification', ModulationType = 'MSK', Frequency = 3920000000, Power = 15, Bandwidth = 1000000, Continuous = False, StartFrequency = 920000000, EndFrequency = 920000000, Timestamp = time.time(), Confidence = 9.4)
        elif 0.55 < random_number <= 0.60:
            self.tsi_pub_server.sendmsg('SOI', Identifier = 'TSI', MessageName = 'Signal Classification', ModulationType = 'MSK', Frequency = 3920000000, Power = 15, Bandwidth = 1000000, Continuous = False, StartFrequency = 920000000, EndFrequency = 920000000, Timestamp = time.time(), Confidence = 9.4)
        elif 0.60 < random_number <= 0.65:
            self.tsi_pub_server.sendmsg('SOI', Identifier = 'TSI', MessageName = 'Signal Classification', ModulationType = 'MSK', Frequency = 3920000000, Power = 15, Bandwidth = 1000000, Continuous = False, StartFrequency = 920000000, EndFrequency = 920000000, Timestamp = time.time(), Confidence = 9.4)
        elif 0.65 < random_number <= 0.70:
            pass        
        elif 0.70 < random_number <= 0.75:
            pass    
        elif 0.75 < random_number <= 0.80:
            pass
        elif 0.80 < random_number <= 0.85:
            pass
        elif 0.85 < random_number <= 0.90:
            pass
        elif 0.90 < random_number <= 0.95:
            pass
        elif 0.95 < random_number <= 1.00:
            pass
            
            
    def addBlacklist(self, start_frequency, end_frequency):
        """ Specifies a frequency range to not perform TSI on.
        """ 
        # Add to Blacklist
        self.blacklist.append((float(start_frequency), float(end_frequency)))
        
        
    def removeBlacklist(self, start_frequency, end_frequency):
        """ Removes an existing blacklisted frequency range for TSI.
        """ 
        remove_tuple = (float(start_frequency),float(end_frequency))
        
        # Remove from List
        for t in self.blacklist:
            if t == remove_tuple:
                self.blacklist.remove(t)
        

    def updateConfiguration(self, start_frequency, end_frequency, step_size, dwell_time):
        """ Updates the TSI Configuration with the specified values.
        """ 
        # Stop the Current Sweep
        #if self.running_TSI_wideband == True:
            #self.stopWidebandThread()
        
        # Update the Sweep Variables
        self.wideband_start_freq = []
        self.wideband_stop_freq = []
        self.wideband_step_size = []
        self.wideband_dwell = []
        for n in range(0,len(start_frequency)):
            self.wideband_start_freq.append(float(start_frequency[n]))
            self.wideband_stop_freq.append(float(end_frequency[n]))
            self.wideband_step_size.append(float(step_size[n]))
            self.wideband_dwell.append(float(dwell_time[n]))
        self.wideband_band = 0
        self.configuration_updated = True
        
        # Start a New Sweep
        if self.running_TSI_wideband == False:
            self.startWidebandThread()

        
    def setHeartbeatInterval(self, interval):
        """ Updates the heartbeat interval to match the rest of the system components.
        """
        print("\nUPDATE HEARTBEAT INTERVAL")
        print(interval)
        
    
        
if __name__=="__main__":
    # Create TSI Object
    tsi_object = TSI_Component()
