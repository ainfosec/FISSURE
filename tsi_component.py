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
import struct
import numpy as np
from scipy.fftpack import fft,fftfreq,next_fast_len
import scipy.stats as stats


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

    def startTSI_Conditioner(self, common_parameter_names, common_parameter_values, method_parameter_names, method_parameter_values):
        """ Accepts a Start message from the HIPRFISR and begins the new thread.
        """
        # Create a New Thread
        self.conditioner_stop_event = threading.Event()
        c_thread = threading.Thread(target=self.startTSI_ConditionerThread, args=(self.conditioner_stop_event, common_parameter_names, common_parameter_values, method_parameter_names, method_parameter_values))
        c_thread.start()
        
    def startTSI_ConditionerThread(self, stop_event, common_parameter_names, common_parameter_values, method_parameter_names, method_parameter_values):
        """ Performs the signal conditioning actions.
        """        
        # Common Parameters
        for n in range(len(common_parameter_names)):
            if common_parameter_names[n] == 'category':
                get_category = common_parameter_values[n]
            elif common_parameter_names[n] == 'method':
                get_method = common_parameter_values[n]
            elif common_parameter_names[n] == 'output_directory':
                get_output_directory = common_parameter_values[n]
            elif common_parameter_names[n] == 'prefix':
                get_prefix = common_parameter_values[n]
            elif common_parameter_names[n] == 'sample_rate':
                get_sample_rate = common_parameter_values[n]
            elif common_parameter_names[n] == 'tuned_frequency':
                get_tuned_freq = common_parameter_values[n]
            elif common_parameter_names[n] == 'data_type':
                get_type = common_parameter_values[n]
            elif common_parameter_names[n] == 'max_files':
                get_max_files = common_parameter_values[n]
            elif common_parameter_names[n] == 'min_samples':
                get_min_samples = common_parameter_values[n]
            elif common_parameter_names[n] == 'all_filepaths':
                get_all_filepaths = common_parameter_values[n]
            elif common_parameter_names[n] == 'detect_saturation':
                get_detect_saturation = common_parameter_values[n]
            elif common_parameter_names[n] == 'saturation_min':
                get_saturation_min = common_parameter_values[n]
            elif common_parameter_names[n] == 'saturation_max':
                get_saturation_max = common_parameter_values[n]
            elif common_parameter_names[n] == 'normalize_output':
                get_normalize_output = common_parameter_values[n]
            elif common_parameter_names[n] == 'normalize_min':
                try:
                    get_normalize_min = float(common_parameter_values[n])
                except:
                    get_normalize_min = ''
            elif common_parameter_names[n] == 'normalize_max':
                try:
                    get_normalize_max = float(common_parameter_values[n])
                except:
                    get_normalize_max = ''
            
        # Flow Graph Directory
        if get_type == "Complex Float 32":
            fg_directory = os.path.dirname(os.path.realpath(__file__)) + "/Flow\ Graph\ Library/TSI\ Flow\ Graphs/Conditioner/Flow_Graphs/ComplexFloat32"
        elif get_type == "Complex Int 16":
            fg_directory = os.path.dirname(os.path.realpath(__file__)) + "/Flow\ Graph\ Library/TSI\ Flow\ Graphs/Conditioner/Flow_Graphs/ComplexInt16"
        
        # Method1: burst_tagger
        if (get_category == "Energy - Burst Tagger") and (get_method == "Normal"):    
            count = 0   
            new_files = []
            original_filenames = []         
            
            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(get_output_directory+"/"+fname):
                        file_names.append(fname)
                            
            for n in range(0,len(get_all_filepaths)):

                # Stop Conditioner Triggered
                if self.conditioner_stop_event.is_set():
                    print("TSI Conditioner Stopped")
                    return
                            
                # Update Progress Bar
                progress_value = 1+int((float((n+1)/len(get_all_filepaths))*90))
                self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n]) 
                
                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == 'threshold':
                        get_threshold = method_parameter_values[m]
                                    
                # Run the Flow Graph                       
                cmd = "python3 " + fg_directory + "/burst_tagger/normal.py --filepath '" + get_all_filepaths[n] \
                    + "' --sample-rate " + get_sample_rate + " --threshold " + get_threshold
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()                     
                
                # Rename the New Files        
                if get_output_directory != "":                        
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(get_output_directory + "/" + fname):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(get_output_directory + "/" + fname, get_output_directory + "/" + get_prefix + str(count).zfill(5) + ".iq")
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")  
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])

            # Update Progress Bar
            progress_value = 95
            self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n]) 
        
        # Method2: burst_tagger with Decay
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Normal Decay"):    
            count = 0   
            new_files = []
            original_filenames = []         
            
            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(get_output_directory+"/"+fname):
                        file_names.append(fname)
                            
            for n in range(0,len(get_all_filepaths)):
                
                # Stop Conditioner Triggered
                if self.conditioner_stop_event.is_set():
                    print("TSI Conditioner Stopped")
                    return

                # Update Progress Bar
                progress_value = 1+int((float((n+1)/len(get_all_filepaths))*90))
                self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n])
                
                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == 'threshold':
                        get_threshold = method_parameter_values[m]
                    elif method_parameter_names[m] == 'decay':
                        get_decay = method_parameter_values[m]
                                    
                # Run the Flow Graph                       
                cmd = "python3 "  + fg_directory + "/burst_tagger/normal_decay.py --filepath '" + get_all_filepaths[n] \
                    + "' --sample-rate " + get_sample_rate + " --threshold " + get_threshold + " --decay " + get_decay
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait() 
                
                # Rename the New Files        
                if get_output_directory != "":                        
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(get_output_directory + "/" + fname):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(get_output_directory + "/" + fname, get_output_directory + "/" + get_prefix + str(count).zfill(5) + ".iq")
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")  
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])
                                
            # Update Progress Bar
            progress_value = 95
            self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n]) 
        
        # Method3: power_squelch_with_burst_tagger
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Power Squelch"):
            count = 0   
            new_files = []
            original_filenames = []         
            
            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(get_output_directory+"/"+fname):
                        file_names.append(fname)
                            
            for n in range(0,len(get_all_filepaths)):

                # Stop Conditioner Triggered
                if self.conditioner_stop_event.is_set():
                    print("TSI Conditioner Stopped")
                    return
                
                # Update Progress Bar
                progress_value = 1+int((float((n+1)/len(get_all_filepaths))*90))
                self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n])
                    
                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == 'squelch':
                        get_squelch = method_parameter_values[m]
                    elif method_parameter_names[m] == 'threshold':
                        get_threshold = method_parameter_values[m]
                        
                # Run the Flow Graph                       
                cmd = "python3 " + fg_directory + "/burst_tagger/power_squelch.py --filepath '" + get_all_filepaths[n] \
                    + "' --sample-rate " + get_sample_rate + " --threshold " + get_threshold + " --squelch " + get_squelch
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()         
                
                # Rename the New Files        
                if get_output_directory != "":                        
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(get_output_directory + "/" + fname):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(get_output_directory + "/" + fname, get_output_directory + "/" + get_prefix + str(count).zfill(5) + ".iq")
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")  
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])

            # Update Progress Bar
            progress_value = 95
            self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n]) 
        
        # Method4: lowpass_filter
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Lowpass"):
            count = 0   
            new_files = []
            original_filenames = []         
            
            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(get_output_directory+"/"+fname):
                        file_names.append(fname)
                            
            for n in range(0,len(get_all_filepaths)):
                
                # Stop Conditioner Triggered
                if self.conditioner_stop_event.is_set():
                    print("TSI Conditioner Stopped")
                    return

                # Update Progress Bar
                progress_value = 1+int((float((n+1)/len(get_all_filepaths))*90))
                self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n])
                    
                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == 'threshold':
                        get_threshold = method_parameter_values[m]
                    elif method_parameter_names[m] == 'cutoff':
                        get_cutoff = method_parameter_values[m]
                    elif method_parameter_names[m] == 'transition':
                        get_transition = method_parameter_values[m]
                    elif method_parameter_names[m] == 'beta':
                        get_beta = method_parameter_values[m]
                        
                # Run the Flow Graph                       
                cmd = "python3 " + fg_directory + "/burst_tagger/lowpass.py --filepath '" + get_all_filepaths[n] \
                    + "' --sample-rate " + get_sample_rate + " --threshold " + get_threshold + " --cutoff-freq " + get_cutoff + " --transition-width " + get_transition \
                    + " --beta " + get_beta
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()         
                
                # Rename the New Files        
                if get_output_directory != "":                        
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(get_output_directory + "/" + fname):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(get_output_directory + "/" + fname, get_output_directory + "/" + get_prefix + str(count).zfill(5) + ".iq")
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")  
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])

            # Update Progress Bar
            progress_value = 95
            self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n]) 
        
        # Method5: power_squelch_lowpass
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Power Squelch then Lowpass"):
            count = 0   
            new_files = []
            original_filenames = []         
            
            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(get_output_directory+"/"+fname):
                        file_names.append(fname)
                            
            for n in range(0,len(get_all_filepaths)):
                
                # Stop Conditioner Triggered
                if self.conditioner_stop_event.is_set():
                    print("TSI Conditioner Stopped")
                    return

                # Update Progress Bar
                progress_value = 1+int((float((n+1)/len(get_all_filepaths))*90))
                self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n])
                
                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == 'squelch':
                        get_squelch = method_parameter_values[m]
                    elif method_parameter_names[m] == 'cutoff':
                        get_cutoff = method_parameter_values[m]
                    elif method_parameter_names[m] == 'transition':
                        get_transition = method_parameter_values[m]
                    elif method_parameter_names[m] == 'beta':
                        get_beta = method_parameter_values[m]
                    elif method_parameter_names[m] == 'threshold':
                        get_threshold = method_parameter_values[m]
                        
                # Run the Flow Graph                       
                cmd = "python3 " + fg_directory + "/burst_tagger/power_squelch_lowpass.py --filepath '" + get_all_filepaths[n] \
                    + "' --sample-rate " + get_sample_rate + " --threshold " + get_threshold + " --cutoff-freq " + get_cutoff + " --transition-width " + get_transition \
                    + " --beta " + get_beta + " --squelch " + get_squelch
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()  
                
                # Rename the New Files        
                if get_output_directory != "":                        
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(get_output_directory + "/" + fname):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(get_output_directory + "/" + fname, get_output_directory + "/" + get_prefix + str(count).zfill(5) + ".iq")
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")  
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])

            # Update Progress Bar
            progress_value = 95
            self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n])  
            
        # Method6: bandpass_filter
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Bandpass"):
            count = 0   
            new_files = []
            original_filenames = []         
            
            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(get_output_directory+"/"+fname):
                        file_names.append(fname)
                            
            for n in range(0,len(get_all_filepaths)):
                
                # Stop Conditioner Triggered
                if self.conditioner_stop_event.is_set():
                    print("TSI Conditioner Stopped")
                    return

                # Update Progress Bar
                progress_value = 1+int((float((n+1)/len(get_all_filepaths))*90))
                self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n])
                    
                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == 'bandpass_frequency':
                        get_bandpass_freq = method_parameter_values[m]
                    elif method_parameter_names[m] == 'bandpass_width':
                        get_bandpass_width = method_parameter_values[m]
                    elif method_parameter_names[m] == 'transition':
                        get_transition = method_parameter_values[m]
                    elif method_parameter_names[m] == 'beta':
                        get_beta = method_parameter_values[m]
                    elif method_parameter_names[m] == 'threshold':
                        get_threshold = method_parameter_values[m]
                        
                # Run the Flow Graph                       
                cmd = "python3 " + fg_directory + "/burst_tagger/bandpass.py --filepath '" + get_all_filepaths[n] \
                    + "' --sample-rate " + get_sample_rate + " --threshold " + get_threshold + " --bandpass-freq " + get_bandpass_freq + " --transition-width " + get_transition \
                    + " --beta " + get_beta + " --bandpass-width " + get_bandpass_width
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()
                
                # Rename the New Files        
                if get_output_directory != "":                        
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(get_output_directory + "/" + fname):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(get_output_directory + "/" + fname, get_output_directory + "/" + get_prefix + str(count).zfill(5) + ".iq")
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")  
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])

            # Update Progress Bar
            progress_value = 95
            self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n]) 
            
        # Method7: strongest
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Strongest Frequency then Bandpass"):
            #self.textEdit_tsi_settings_bt_sfb_freq.setPlainText("?")
            #self.textEdit_tsi_settings_bt_sfb_freq.setAlignment(QtCore.Qt.AlignCenter)
            count = 0   
            new_files = []
            original_filenames = []         
            
            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(get_output_directory+"/"+fname):
                        file_names.append(fname)
                            
            for n in range(0,len(get_all_filepaths)):

                # Stop Conditioner Triggered
                if self.conditioner_stop_event.is_set():
                    print("TSI Conditioner Stopped")
                    return

                # Update Progress Bar
                progress_value = 1+int((float((n+1)/len(get_all_filepaths))*90))
                self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n])
                    
                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == 'fft_size':
                        get_fft_size = method_parameter_values[m]
                    elif method_parameter_names[m] == 'fft_threshold':
                        get_fft_threshold = method_parameter_values[m]
                    elif method_parameter_names[m] == 'bandpass_width':
                        get_bandpass_width = method_parameter_values[m]
                    elif method_parameter_names[m] == 'transition':
                        get_transition = method_parameter_values[m]
                    elif method_parameter_names[m] == 'beta':
                        get_beta = method_parameter_values[m]
                    elif method_parameter_names[m] == 'threshold':
                        get_threshold = method_parameter_values[m]

                # Acquire Number of Samples
                file_bytes = os.path.getsize(get_all_filepaths[n])
                file_samples = "-1"
                if file_bytes > 0:            
                    if get_type == "Complex Float 32":
                        file_samples = str(int(file_bytes/8))
                    elif get_type == "Float/Float 32":
                        file_samples = str(int(file_bytes/4))
                    elif get_type == "Short/Int 16":
                        file_samples = str(int(file_bytes/2))
                    elif get_type == "Int/Int 32":
                        file_samples = str(int(file_bytes/4))
                    elif get_type == "Byte/Int 8":
                        file_samples = str(int(file_bytes/1))
                    elif get_type == "Complex Int 16":
                        file_samples = str(int(file_bytes/4))
                    elif get_type == "Complex Int 8":
                        file_samples = str(int(file_bytes/2))
                    elif get_type == "Complex Float 64":
                        file_samples = str(int(file_bytes/16))
                    elif get_type == "Complex Int 64":
                        file_samples = str(int(file_bytes/16))
                else:
                    continue       
                
                # Where to Store Strongest Frequency Results
                peak_file_location =  os.path.dirname(os.path.realpath(__file__)) + "/Flow\ Graph\ Library/TSI\ Flow\ Graphs/Conditioner/peaks.txt"
                
                # Run the Flow Graph                       
                cmd = "python3 " + fg_directory + "/fft/strongest.py --filepath '" + get_all_filepaths[n] \
                    + "' --sample-rate " + get_sample_rate + " --fft-threshold " + get_fft_threshold + " --samples " + file_samples + " --peak-file-location " + peak_file_location \
                    + " --fft-size " + get_fft_size
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()

                # Read the Frequency Result
                file = open(peak_file_location.replace('\\',''),"r")                    
                freq_result = str(round(float(file.read()),2))
                file.close()
                
                # Bandpass Filter is Applied to Negative and Positive Sides
                if float(freq_result) < 0:
                    freq_result = str(abs(float(freq_result)))
                    
                # Avoid Errors with Filter Width
                if (float(freq_result) + float(get_bandpass_width)/2) > float(get_sample_rate)/2:
                    freq_result = str(float(get_sample_rate)/2 - float(get_bandpass_width)/2)
                elif (float(freq_result) - float(get_bandpass_width)/2) < 0:
                    freq_result = str(float(get_bandpass_width)/2)
                    
                # Strongest Frequency Result
                print("Strongest Frequency Detected at: " + str(freq_result))
                #self.textEdit_settings_bt_sfb_freq.setPlainText(freq_result)
                #self.textEdit_settings_bt_sfb_freq.setAlignment(QtCore.Qt.AlignCenter)
                #get_bandpass_freq = str(self.textEdit_settings_bt_sfb_freq.toPlainText())
                                        
                # Run the Bandpass Flow Graph                    
                cmd = "python3 " + fg_directory + "/burst_tagger/bandpass.py --filepath '" + get_all_filepaths[n] \
                    + "' --sample-rate " + get_sample_rate + " --threshold " + get_threshold + " --bandpass-freq " + freq_result + " --transition-width " + get_transition \
                    + " --beta " + get_beta + " --bandpass-width " + get_bandpass_width
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait() 
                
                # Rename the New Files        
                if get_output_directory != "":                        
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(get_output_directory + "/" + fname):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(get_output_directory + "/" + fname, get_output_directory + "/" + get_prefix + str(count).zfill(5) + ".iq")
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")  
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])

            # Update Progress Bar
            progress_value = 95
            self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'Conditioner Progress Bar', Parameters = [progress_value,n])    
            
        # Invalid Method
        else:
            print("Invalid method")
            self.finishedTSI_Conditioner()
            return
            
        # Remove Files with Too Few Samples
        temp_files = new_files
        for n,fname in reversed(list(enumerate(temp_files))):
            get_bytes = os.path.getsize(get_output_directory + "/" + fname)
            get_samples = "-1"
            if get_bytes > 0:            
                if get_type == "Complex Float 32":
                    get_samples = int(get_bytes/8)
                elif get_type == "Float/Float 32":
                    get_samples = int(get_bytes/4)
                elif get_type == "Short/Int 16":
                    get_samples = int(get_bytes/2)
                elif get_type == "Int/Int 32":
                    get_samples = int(get_bytes/4)
                elif get_type == "Byte/Int 8":
                    get_samples = int(get_bytes/1)
                elif get_type == "Complex Int 16":
                    get_samples = int(get_bytes/4)
                elif get_type == "Complex Int 8":
                    get_samples = int(get_bytes/2)
                elif get_type == "Complex Float 64":
                    get_samples = int(get_bytes/16)
                elif get_type == "Complex Int 64":
                    get_samples = int(get_bytes/16)  
            
            # Remove File
            if get_samples < get_min_samples:
                temp_files.pop(n)
        new_files = temp_files
                                
        # File Count
        file_count = str(len(new_files))
         
        # Generate Results for Table
        table_strings = []
        for n, fname in enumerate(new_files):
            new_table_row = ['','','','','','','','','']
            
            # Filename
            new_table_row[0] = fname
            
            # File Size
            get_bytes = os.path.getsize(get_output_directory + "/" + fname)
            new_table_row[1] = str(round(get_bytes/1048576,2))

            # Samples
            get_samples = "-1"
            if get_bytes > 0:            
                if get_type == "Complex Float 32":
                    get_samples = str(int(get_bytes/8))
                elif get_type == "Float/Float 32":
                    get_samples = str(int(get_bytes/4))
                elif get_type == "Short/Int 16":
                    get_samples = str(int(get_bytes/2))
                elif get_type == "Int/Int 32":
                    get_samples = str(int(get_bytes/4))
                elif get_type == "Byte/Int 8":
                    get_samples = str(int(get_bytes/1))
                elif get_type == "Complex Int 16":
                    get_samples = str(int(get_bytes/4))
                elif get_type == "Complex Int 8":
                    get_samples = str(int(get_bytes/2))
                elif get_type == "Complex Float 64":
                    get_samples = str(int(get_bytes/16))
                elif get_type == "Complex Int 64":
                    get_samples = str(int(get_bytes/16))
            new_table_row[2] = str(get_samples)
            
            # Format
            new_table_row[3] = get_type
            
            # Sample Rate
            new_table_row[4] = get_sample_rate
            
            # Saturated
            new_table_row[5] = ''
            if get_detect_saturation == 'True':                
                get_original_file = get_output_directory + "/" + fname 
                if (len(get_original_file) > 0) and (len(fname) > 0):
                    # Read the Data 
                    file = open(get_original_file,"rb")                    
                    plot_data = file.read() 
                    file.close()
                    
                    # Complex Float 64
                    if (get_type == "Complex Float 64"):                
                        # Normalize and Write
                        number_of_bytes = os.path.getsize(get_original_file)
                        plot_data_formatted = struct.unpack(int(number_of_bytes/8)*'d', plot_data)                
                        np_data = np.asarray(plot_data_formatted, dtype=np.float64)
                        array_min = float(min(np_data))
                        array_max = float(max(np_data))                                     
                          
                    # Complex Float 32
                    elif (get_type == "Complex Float 32") or (get_type == "Float/Float 32"):                
                        # Normalize and Write
                        number_of_bytes = os.path.getsize(get_original_file)
                        plot_data_formatted = struct.unpack(int(number_of_bytes/4)*'f', plot_data)                
                        np_data = np.asarray(plot_data_formatted, dtype=np.float32)
                        array_min = float(min(np_data))
                        array_max = float(max(np_data))            
                    
                    # Complex Int 16
                    elif (get_type == "Complex Int 16") or (get_type == "Short/Int 16"):               
                        # Convert and Write
                        number_of_bytes = os.path.getsize(get_original_file)
                        plot_data_formatted = struct.unpack(int(number_of_bytes/2)*'h', plot_data)
                        np_data = np.array(plot_data_formatted, dtype=np.int16)
                        array_min = float(min(np_data))
                        array_max = float(max(np_data))
                    
                    # Complex Int 64
                    elif (get_type == "Complex Int 64"):               
                        # Convert and Write
                        number_of_bytes = os.path.getsize(get_original_file)
                        plot_data_formatted = struct.unpack(int(number_of_bytes/8)*'l', plot_data)
                        np_data = np.array(plot_data_formatted, dtype=np.int64)
                        array_min = float(min(np_data))
                        array_max = float(max(np_data))
                        
                    # Int/Int 32
                    elif (get_type == "Int/Int 32"):               
                        # Convert and Write
                        number_of_bytes = os.path.getsize(get_original_file)
                        plot_data_formatted = struct.unpack(int(number_of_bytes/4)*'h', plot_data)
                        np_data = np.array(plot_data_formatted, dtype=np.int32)
                        array_min = float(min(np_data))
                        array_max = float(max(np_data))
                        
                    # Complex Int 8
                    elif (get_type == "Complex Int 8") or (get_type == "Byte/Int 8"):               
                        # Convert and Write
                        number_of_bytes = os.path.getsize(get_original_file)
                        plot_data_formatted = struct.unpack(int(number_of_bytes)*'b', plot_data)
                        np_data = np.array(plot_data_formatted, dtype=np.int8)
                        array_min = float(min(np_data))
                        array_max = float(max(np_data))
                    
                    # Unknown
                    else:
                        print("Cannot normalize " + get_type + ".")
                        
                    # Detect
                    if (array_min <= float(get_saturation_min)) or (array_max >= float(get_saturation_max)):
                        new_table_row[5] = 'Yes'
                    else:
                        new_table_row[5] = 'No'
            
            # Tuned Frequency
            new_table_row[6] = get_tuned_freq
            
            # Source
            new_table_row[7] = original_filenames[n]
            
            # Notes
            new_table_row[8] = ''
            
            # Append the Row
            table_strings.append(new_table_row)
        
        # Normalize Output
        if get_normalize_output == 'True':           
            # Load the Data
            get_original_file = get_output_directory + "/" + fname 
            get_new_file = get_original_file        

            # Files Selected
            if (len(get_output_directory) > 0) and (len(fname) > 0):
                # Read the Data 
                file = open(get_original_file,"rb")                    
                plot_data = file.read() 
                file.close()
                
                # Complex Float 64
                if (get_type == "Complex Float 64"):                
                    # Normalize and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/8)*'d', plot_data)                
                    np_data = np.asarray(plot_data_formatted, dtype=np.float64)
                    array_min = float(min(np_data))
                    array_max = float(max(np_data))
                    for n in range(0, len(np_data)):
                        np_data[n] = (np_data[n] - array_min)*(get_normalize_max-get_normalize_min)/(array_max-array_min) + get_normalize_min
                    np_data.tofile(get_new_file)            
                      
                # Complex Float 32
                elif (get_type == "Complex Float 32") or (get_type == "Float/Float 32"):                
                    # Normalize and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/4)*'f', plot_data)                
                    np_data = np.asarray(plot_data_formatted, dtype=np.float32)
                    array_min = float(min(np_data))
                    array_max = float(max(np_data))
                    for n in range(0, len(np_data)):
                        np_data[n] = (np_data[n] - array_min)*(get_normalize_max-get_normalize_min)/(array_max-array_min) + get_normalize_min
                    np_data.tofile(get_new_file)              
                
                # Complex Int 16
                elif (get_type == "Complex Int 16") or (get_type == "Short/Int 16"):               
                    # Convert and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/2)*'h', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int16)
                    array_min = float(min(np_data))
                    array_max = float(max(np_data))
                    for n in range(0, len(np_data)):
                        np_data[n] = (float(np_data[n]) - array_min)*(get_normalize_max-get_normalize_min)/(array_max-array_min) + get_normalize_min
                    np_data.tofile(get_new_file)
                
                # Complex Int 64
                elif (get_type == "Complex Int 64"):               
                    # Convert and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/8)*'l', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int64)
                    array_min = float(min(np_data))
                    array_max = float(max(np_data))
                    for n in range(0, len(np_data)):
                        np_data[n] = (float(np_data[n]) - array_min)*(get_normalize_max-get_normalize_min)/(array_max-array_min) + get_normalize_min
                    np_data.tofile(get_new_file)
                    
                # Int/Int 32
                elif (get_type == "Int/Int 32"):               
                    # Convert and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/4)*'h', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int32)
                    array_min = float(min(np_data))
                    array_max = float(max(np_data))
                    for n in range(0, len(np_data)):
                        np_data[n] = (float(np_data[n]) - array_min)*(get_normalize_max-get_normalize_min)/(array_max-array_min) + get_normalize_min
                    np_data.tofile(get_new_file)
                    
                # Complex Int 8
                elif (get_type == "Complex Int 8") or (get_type == "Byte/Int 8"):               
                    # Convert and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes)*'b', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int8)
                    array_min = float(min(np_data))
                    array_max = float(max(np_data))
                    for n in range(0, len(np_data)):
                        np_data[n] = (float(np_data[n]) - array_min)*(get_normalize_max-get_normalize_min)/(array_max-array_min) + get_normalize_min
                    np_data.tofile(get_new_file)
                
                # Unknown
                else:
                    print("Cannot normalize " + get_type + ".")
                    
        # Return the Table Data
        self.finishedTSI_Conditioner(table_strings)
        
    def stopTSI_Conditioner(self):
        """ Accepts a Stop message from the HIPRFISR to stop the signal conditioning operation.
        """
        # Stop the Thread
        print("Stopping TSI Conditioner...")
        self.conditioner_stop_event.set()
        
    def finishedTSI_Conditioner(self, table_strings=""):
        """ Sends a message to the HIPRFISR to signal the signal conditioner operation is complete.
        """
        # Send the Message
        print("TSI Conditioner Complete. Returning Table Data...")
        self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'TSI Conditioner Finished', Parameters = table_strings)

########################################################################

    def startTSI_FE(self, common_parameter_names, common_parameter_values):
        """ Accepts a Start message from the HIPRFISR and begins the new thread.
        """
        # Create a New Thread
        self.fe_stop_event = threading.Event()
        c_thread = threading.Thread(target=self.startTSI_FE_Thread, args=(self.fe_stop_event, common_parameter_names, common_parameter_values))
        c_thread.start()
        
    def startTSI_FE_Thread(self, stop_event, common_parameter_names, common_parameter_values):
        """ Performs the feature extractor actions.
        """     
        # Common Parameters
        for n in range(len(common_parameter_names)):
            if common_parameter_names[n] == 'checkboxes':
                get_checkboxes = common_parameter_values[n]
            elif common_parameter_names[n] == 'data_type':
                get_data_type = common_parameter_values[n]
            elif common_parameter_names[n] == 'all_filepaths':
                get_all_filepaths = common_parameter_values[n]
                
        # Table Headers
        header_strings = ['File']
        for n in range(0,len(get_checkboxes)):
            header_strings.append(get_checkboxes[n])
        table_strings = [header_strings]
                
        # Features that Require FFT Operation
        fft_features = ["Mean of Band Power Spectrum","Max of Band Power Spectrum","Sum of Total Band Power","Peak of Band Power",
                    "Variance of Band Power","Standard Deviation of Band Power","Skewness of Band Power","Kurtosis of Band Power",
                    "Relative Spectral Peak per Band"]
            
        # Cycle Through Each File
        for n in range(0,len(get_all_filepaths)):
            
            # Start a New Row
            new_table_row = ['']
                
            # Files Selected
            if (len(get_all_filepaths[n]) > 0):
                
                # Filepath
                new_table_row[0] = str(get_all_filepaths[n].split('/')[-1])
                
                # Read the Data 
                file = open(get_all_filepaths[n],"rb")                    
                plot_data = file.read() 
                file.close()
                number_of_bytes = os.path.getsize(get_all_filepaths[n])

                # Complex Float 64
                if (get_data_type == "Complex Float 64"):                
                    plot_data_formatted = struct.unpack(int(number_of_bytes/8)*'d', plot_data)                
                    np_data = np.asarray(plot_data_formatted, dtype=np.float64)
                      
                # Complex Float 32
                elif (get_data_type == "Complex Float 32") or (get_data_type == "Float/Float 32"):                
                    plot_data_formatted = struct.unpack(int(number_of_bytes/4)*'f', plot_data)                
                    np_data = np.asarray(plot_data_formatted, dtype=np.float32)
                
                # Complex Int 16
                elif (get_data_type == "Complex Int 16") or (get_data_type == "Short/Int 16"):               
                    plot_data_formatted = struct.unpack(int(number_of_bytes/2)*'h', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int16)
                
                # Complex Int 64
                elif (get_data_type == "Complex Int 64"):               
                    plot_data_formatted = struct.unpack(int(number_of_bytes/8)*'l', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int64)
                    
                # Int/Int 32
                elif (get_data_type == "Int/Int 32"):               
                    plot_data_formatted = struct.unpack(int(number_of_bytes/4)*'h', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int32)
                    
                # Complex Int 8
                elif (get_data_type == "Complex Int 8") or (get_data_type == "Byte/Int 8"):               
                    plot_data_formatted = struct.unpack(int(number_of_bytes)*'b', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int8)
                
                # Unknown
                else:
                    print("Cannot read  " + get_data_type + ".")
                    continue
                    
                # Do FFT Once
                for m in get_checkboxes:
                    if m in fft_features:
                        ft = fft(np_data,next_fast_len(len(np_data)))
                        S = np.abs(ft**2)/len(np_data)
                        break
            
                # Time Domain: Mean
                col_count = 0
                if "Mean" in get_checkboxes:                    
                    # Obtain the Value
                    array_mean = str(float(np.mean(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_mean)
                    
                # Time Domain: Max
                if "Max" in get_checkboxes:
                    # Obtain the Value
                    array_max = str(float(max(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_max)
                    
                # Time Domain: Peak
                if "Peak" in get_checkboxes:
                    # Obtain the Value
                    array_peak = str(float(np.max(np.abs(np_data))))

                    # Add Value to Table
                    new_table_row.append(array_peak)
                    
                # Time Domain: Peak to Peak
                if "Peak to Peak" in get_checkboxes:
                    # Obtain the Value
                    array_peak_to_peak = str(float(np.ptp(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_peak_to_peak)
                    
                # Time Domain: RMS
                if "RMS" in get_checkboxes:
                    # Obtain the Value
                    array_rms = str(float(np.sqrt(np.mean(np_data**2))))

                    # Add Value to Table
                    new_table_row.append(array_rms)
                    
                # Time Domain: Variance
                if "Variance" in get_checkboxes:
                    # Obtain the Value
                    array_variance = str(float(np.var(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_variance)
                    
                # Time Domain: Standard Deviation
                if "Standard Deviation" in get_checkboxes:
                    # Obtain the Value
                    array_std_dev = str(float(np.std(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_std_dev)
                    
                # Time Domain: Power
                if "Power" in get_checkboxes:
                    # Obtain the Value
                    array_power = str(float(np.mean(np_data**2)))

                    # Add Value to Table
                    new_table_row.append(array_power)

                # Time Domain: Crest Factor
                if "Crest Factor" in get_checkboxes:
                    # Obtain the Value
                    array_crest_factor = str(float(np.max(np.abs(np_data))/np.sqrt(np.mean(np_data**2))))

                    # Add Value to Table
                    new_table_row.append(array_crest_factor)
                    
                # Time Domain: Pulse Indicator
                if "Pulse Indicator" in get_checkboxes:
                    # Obtain the Value
                    array_pulse_indicator = str(float(np.max(np.abs(np_data))/np.mean(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_pulse_indicator)
                    
                # Time Domain: Margin
                if "Margin" in get_checkboxes:
                    # Obtain the Value
                    array_margin = str(float(np.max(np.abs(np_data))/(np.abs(np.mean(np.sqrt(np.abs(np_data))))**2)))

                    # Add Value to Table
                    new_table_row.append(array_margin)
                    
                # Time Domain: Kurtosis
                if "Kurtosis" in get_checkboxes:
                    # Obtain the Value
                    array_kurtosis = str(float(stats.kurtosis(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_kurtosis)
                    
                # Time Domain: Skewness
                if "Skewness" in get_checkboxes:
                    # Obtain the Value
                    array_skewness = str(float(stats.skew(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_skewness)
                    
                # Time Domain: Zero Crossings
                if "Zero Crossings" in get_checkboxes:
                    # Obtain the Value
                    count1 = np.where(np.diff(np.sign( [i for i in np_data[::2] if i] )))[0].shape[0]
                    count2 = np.where(np.diff(np.sign( [i for i in np_data[1::2] if i] )))[0].shape[0]                        
                    array_zero_crossings = str(count1 + count2)

                    # Add Value to Table
                    new_table_row.append(array_zero_crossings)
                    
                # Time Domain: Samples
                if "Samples" in get_checkboxes:
                    # Obtain the Value
                    if "Complex" in get_data_type:     
                        array_samples = str(int(len(np_data)/2))
                    else:
                        array_samples = str(int(len(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_samples)
                    
                # Frequency Domain: Mean of Band Power Spectrum
                if "Mean of Band Power Spectrum" in get_checkboxes:
                    # Obtain the Value
                    array_mean_bps = str(float(np.mean(S)))

                    # Add Value to Table
                    new_table_row.append(array_mean_bps)
                    
                # Frequency Domain: Max of Band Power Spectrum
                if "Max of Band Power Spectrum" in get_checkboxes:
                    # Obtain the Value
                    array_max_bps = str(float(np.max(S)))

                    # Add Value to Table
                    new_table_row.append(array_max_bps)
                    
                # Frequency Domain: Sum of Total Band Power
                if "Sum of Total Band Power" in get_checkboxes:
                    # Obtain the Value
                    array_sum_tbp = str(float(np.sum(S)))

                    # Add Value to Table
                    new_table_row.append(array_sum_tbp)
                    
                # Frequency Domain: Peak of Band Power
                if "Peak of Band Power" in get_checkboxes:
                    # Obtain the Value
                    array_peak_bp = str(float(np.max(np.abs(S))))

                    # Add Value to Table
                    new_table_row.append(array_peak_bp)
                    
                # Frequency Domain: Variance of Band Power
                if "Variance of Band Power" in get_checkboxes:
                    # Obtain the Value
                    array_var_bp = str(float(np.var(S)))

                    # Add Value to Table
                    new_table_row.append(array_var_bp)
                
                # Frequency Domain: Standard Deviation of Band Power
                if "Standard Deviation of Band Power" in get_checkboxes:
                    # Obtain the Value
                    array_std_dev_bp = str(float(np.std(S)))
                  
                    # Add Value to Table
                    new_table_row.append(array_std_dev_bp)
                    
                # Frequency Domain: Skewness of Band Power
                if "Skewness of Band Power" in get_checkboxes:
                    # Obtain the Value
                    array_skewness_bp = str(float(stats.skew(S)))

                    # Add Value to Table
                    new_table_row.append(array_skewness_bp)
                    
                # Frequency Domain: Kurtosis of Band Power
                if "Kurtosis of Band Power" in get_checkboxes:
                    # Obtain the Value
                    array_kurtosis_bp = str(float(stats.kurtosis(S)))

                    # Add Value to Table
                    new_table_row.append(array_kurtosis_bp)
                    
                # Frequency Domain: Relative Spectral Peak per Band
                if "Relative Spectral Peak per Band" in get_checkboxes:
                    # Obtain the Value
                    array_rsppb = str(float(np.max(S)/np.mean(S)))

                    # Add Value to Table
                    new_table_row.append(array_rsppb)
            
            # Append the Row
            table_strings.append(new_table_row)
            
            # Update Progress Bar
            progress_value = 1+int((float((n+1)/len(get_all_filepaths))*99))
            self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'FE Progress Bar', Parameters = [progress_value,n])
                    
            # Check for Break
            if self.fe_stop_event.is_set():
                print("TSI Feature Extractor Stopped")
                return        
                
        # Return the Table Data
        self.finishedTSI_FE(table_strings)
        
    def stopTSI_FE(self):
        """ Accepts a Stop message from the HIPRFISR to stop the feature extractor operation.
        """
        # Stop the Thread
        print("Stopping TSI Feature Extractor...")
        self.fe_stop_event.set()
        
    def finishedTSI_FE(self, table_strings=""):
        """ Sends a message to the HIPRFISR to signal the feature extractor operation is complete.
        """
        # Send the Message
        print("TSI Feature Extractor Complete. Returning Table Data...")
        self.tsi_pub_server.sendmsg('Status', Identifier = 'TSI', MessageName = 'TSI FE Finished', Parameters = table_strings)
        
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
