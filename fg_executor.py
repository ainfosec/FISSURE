#!/usr/bin/env python3

import time
import random
import yaml
import zmq
import os   
import threading
import sys
from tempfile import mkstemp
from shutil import move
from os import remove, close
import inspect,sys,types
import subprocess
from fissureclass import fissure_listener
from fissureclass import fissure_server

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/Flow Graph Library/PD Flow Graphs')
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/Flow Graph Library/Single-Stage Flow Graphs')
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/Flow Graph Library/Fuzzing Flow Graphs')
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/Flow Graph Library/IQ Flow Graphs')	
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/Flow Graph Library/Archive Flow Graphs')
sys.path.insert(0, '/tmp')
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/Flow Graph Library/Sniffer Flow Graphs')
    
# from gnuradio import blocks 
# from gnuradio import gr
# from gnuradio import uhd
# from gnuradio import zeromq
# from gnuradio import audio
    
    
# Insert Any Argument While Executing to Run Locally
try:
    run_local = sys.argv[1]
except:
    run_local = None
    
class FGE_Executor():
    """ Class that contains the functions for the FGE Executor.
    """  
    #######################  FISSURE Functions  ########################
    def __init__(self):
        """ The start of the FGE Executor.
        """     
        self.hiprfisr_connected = False
        self.dashboard_connected = False
        
        self.heartbeat_interval = 5
        self.fge_heartbeat_time = 0
        self.attack_flow_graph_loaded = False
        self.archive_flow_graph_loaded = False
        
        self.attack_script_name = ""
        self.inspection_script_name = ""
        
        # Create the FGE ZMQ Sockets
        self.connect()
        
        # Main Event Loop
        try:
            while True:      
                #print("FGE LOOPING!!!")
                # Read Messages in the ZMQ Queues
                if self.hiprfisr_connected == True:
                    self.readHIPRFISR_Messages()
                #if sub_connected == True:
                self.readSUB_Messages()
                
                # Send the FGE Heartbeat
                self.sendHeartbeat()

                time.sleep(1)

        except KeyboardInterrupt:       
            pass
            
    def connect(self):
        """ Connects all the 0MQ Servers and Listeners 
        """            
        # Load Settings from YAML File
        self.loadConfiguration()

        # Create Connections       
        dashboard_ip_address = "127.0.0.1"
        hiprfisr_ip_address = "127.0.0.1"
        fge_ip_address = "127.0.0.1"
        
        fge_dealer_port = int(self.settings_dictionary['fge_hiprfisr_dealer_port'])
        fge_pub_port = int(self.settings_dictionary['fge_pub_port'])
        
        # FGE DEALER
        self.fge_hiprfisr_listener = fissure_listener(os.path.dirname(os.path.realpath(__file__)) + '/YAML/fge.yaml',hiprfisr_ip_address,fge_dealer_port,zmq.DEALER, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "fge")

        # FGE PUB       
        self.fge_pub_server = fissure_server(os.path.dirname(os.path.realpath(__file__)) + '/YAML/fge.yaml',fge_ip_address,fge_pub_port,zmq.PUB, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "fge")
            
        # FGE SUB   
        dashboard_pub_port = int(self.settings_dictionary['dashboard_pub_port'])
        hiprfisr_pub_port = int(self.settings_dictionary['hiprfisr_pub_port'])
        
        # FGE SUB to HIPRFISR PUB
        try:
            self.fge_sub_listener = fissure_listener(os.path.dirname(os.path.realpath(__file__)) + '/YAML/fge.yaml',hiprfisr_ip_address,hiprfisr_pub_port,zmq.SUB, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "fge")
            sub_connected = True
        except:
            print("Error creating FGE SUB and connecting to HIPRFISR PUB")
            
        # FGE SUB to Dashboard PUB    
        try:
            self.fge_sub_listener.initialize_port(dashboard_ip_address,dashboard_pub_port) 
        except:
            print("Unable to connect FGE SUB to Dashboard PUB")
                
    def readSUB_Messages(self):
        """ Read all the messages in the self.fge_sub_listener and handle accordingly
        """
        # Check for Messages
        parsed = ''
        while parsed != None:
            parsed = self.fge_sub_listener.recvmsg()   
            if parsed != None:   
                # Check for Connection
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
                        ## Update Stored Heartbeat Time in settings_dictionary
                        #settings_dictionary[parsed['Identifier'].lower() + '_heartbeat_time'] = parsed['Time']
                    
                        ## Update Other Heartbeat Related Variables 
                        pass        

    def readHIPRFISR_Messages(self):
        """ Sort through any HIPRFISR messages
        """     
        # Check for Messages
        parsed = ''
        while parsed != None:
            parsed = self.fge_hiprfisr_listener.recvmsg()   
            if parsed != None:  
                # Handle Messages/Execute Callbacks 
                self.fge_hiprfisr_listener.runcallback(self,parsed)
            
    def sendHeartbeat(self):
        """ Sends the heartbeat to all subscribers
        """        
        current_time = time.time()
        if self.fge_heartbeat_time < current_time - self.heartbeat_interval:
            self.fge_heartbeat_time = current_time
            self.fge_pub_server.sendmsg('Heartbeats', Identifier = 'FGE', MessageName='Heartbeat', Time=current_time)     
            
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
        
    def setVariable(self, flow_graph, variable, value):
        """ Sets a variable of a specified running flow graph.
        """
        # Make it Match GNU Radio Format
        formatted_name = "set_" + variable
        isNumber = self.isFloat(value)   
        if isNumber:
            if flow_graph == "Protocol Discovery":
                getattr(self.pdflowtoexec,formatted_name)(float(value))
            elif flow_graph == "Attack":
                getattr(self.attackflowtoexec,formatted_name)(float(value))
            elif flow_graph == "Sniffer":
                getattr(self.snifferflowtoexec,formatted_name)(float(value))
        else:
            if flow_graph == "Protocol Discovery":
                getattr(self.pdflowtoexec,formatted_name)(value)   
            elif flow_graph == "Attack":
                getattr(self.attackflowtoexec,formatted_name)(value)             
            elif flow_graph == "Sniffer":
                getattr(self.snifferflowtoexec,formatted_name)(value)             

    def flowGraphFinished(self, flow_graph_type):
        """ Signals to all components that the flow graph has finished.
        """ 
        # Send Message
        if flow_graph_type == "PD":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Finished', Parameters = "PD") 
        elif flow_graph_type == "Attack":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Finished', Parameters = "Attack") 
        elif flow_graph_type == "IQ":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Finished IQ', Parameters = []) 
        elif flow_graph_type == "IQ Playback":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Finished IQ Playback', Parameters = []) 
        elif flow_graph_type == "Inspection":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Finished IQ Inspection', Parameters = []) 
        elif flow_graph_type == "Sniffer - Stream":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Finished Sniffer', Parameters = "Stream") 
        elif flow_graph_type == "Sniffer - Tagged Stream":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Finished Sniffer', Parameters = "Tagged Stream") 
        elif flow_graph_type == "Sniffer - Message/PDU":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Finished Sniffer', Parameters = "Message/PDU") 
            
    def flowGraphStarted(self, flow_graph_type):
        """ Signals to all components that the flow graph has started.
        """ 
        # Send Message
        if flow_graph_type == "PD":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Started', Parameters = "PD") 
        elif flow_graph_type == "Attack":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Started', Parameters = "Attack")         
        elif flow_graph_type == "IQ":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Started IQ', Parameters = [])       
        elif flow_graph_type == "IQ Playback":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Started IQ Playback', Parameters = [])       
        elif flow_graph_type == "Inspection":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Started IQ Inspection', Parameters = [])    
        elif flow_graph_type == "Sniffer - Stream":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Started Sniffer', Parameters = "Stream")    
        elif flow_graph_type == "Sniffer - Tagged Stream":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Started Sniffer', Parameters = "Tagged Stream")    
        elif flow_graph_type == "Sniffer - Message/PDU":
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Started Sniffer', Parameters = "Message/PDU")    

    def runFlowGraphGUI_Thread(self, stop_event, flow_graph_filename, variable_names, variable_values):
        """ Runs the attack flow graph in the new thread.
        """
        # Stop Any Running Attack Flow Graphs
        try:
            self.attackFlowGraphStop(None)
        except:
            pass
            
        try:                      
            # Start it
            filepath = flow_graph_filename
            flow_graph_filename = flow_graph_filename.rsplit("/",1)[1]
            arguments = ""
            for n in variable_values:
                arguments = arguments + n + " "
                
            osCommandString = "python3 " + '"' + filepath + '" ' + arguments
            proc = subprocess.Popen(osCommandString + " &", shell=True)#, stderr=subprocess.PIPE) 
            #output, error = proc.communicate()
              
            self.flowGraphStarted("Attack")  # Signals to other components 
            self.attack_script_name = flow_graph_filename
 
        # Error Loading Flow Graph              
        except Exception as e:
            self.flowGraphStarted("Attack")
            self.flowGraphFinished("Attack")     
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Error', Parameters = e)  
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Multi-Stage Attack Finished', Parameters = "")  
            #~ #raise e
                
    def runPythonScriptThread(self, stop_event, file_type, flow_graph_filename, variable_names, variable_values):
        """ Runs the attack flow graph in the new thread.
        """            
        # Stop Any Running Attack Flow Graphs
        try:
            self.attackFlowGraphStop(None)
        except:
            pass
            
        try:          
            # Check for Quotes and Backticks
            for n in range(0,len(variable_values)):
                variable_values[n] = variable_values[n].replace('`','\\`')
                variable_values[n] = variable_values[n].replace('"','\\"')
                        
            # Start it
            arguments = ""
            for n in variable_values:
                arguments = arguments + '"' + n + '" '
            
            # Python3
            if file_type == "Python3 Script":
                osCommandString = "sudo python3 " + '"' + flow_graph_filename + '" ' + arguments
                
            # Python2
            else:
                osCommandString = "sudo python2 " + '"' + flow_graph_filename + '" ' + arguments
                print(osCommandString)
                
            # In FISSURE Dashboard
            #proc = subprocess.Popen(osCommandString + " &", shell=True)#, stderr=subprocess.PIPE) 
            #output, error = proc.communicate()
            
            # In New Terminal
            proc = subprocess.Popen('gnome-terminal -- ' + osCommandString + " &", shell=True)            
              
            self.flowGraphStarted("Attack")  # Signals to other components
            self.attack_script_name = flow_graph_filename
            
            # Restore the Start Button for Scripts
            self.flowGraphFinished("Attack")     
            #self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Multi-Stage Attack Finished', Parameters = "")  
 
        # Error Loading Flow Graph              
        except Exception as e:
            self.flowGraphStarted("Attack")
            self.flowGraphFinished("Attack")     
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Error', Parameters = e)  
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Multi-Stage Attack Finished', Parameters = "")  
            #~ #raise e
            
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
            

    ######################  Attack Flow Graphs  ########################
    def attackFlowGraphStart(self, flow_graph_filename, variable_names, variable_values, file_type):
        """ Runs the flow graph with the specified file path.
        """       
        # Make a new Thread
        stop_event = threading.Event()
        if file_type == "Flow Graph":
            c_thread = threading.Thread(target=self.runFlowGraphThread, args=(stop_event,flow_graph_filename,variable_names,variable_values))
        elif file_type == "Flow Graph - GUI":
            c_thread = threading.Thread(target=self.runFlowGraphGUI_Thread, args=(stop_event,flow_graph_filename,variable_names,variable_values))
        # Python2, Python3
        else:
            #print(variable_names)
            #print(variable_values)
            #print(type(variable_values))
            #print(repr(variable_values))
            #print type(repr(variable_values))
            #for n in range(0,len(variable_values)):
                #print("asdfasd")
                #print(variable_values[n])
                #variable_values[n] = variable_values[n].replace('`','\`')
            #print("after")
            #print(variable_values)
            #print("function")
            c_thread = threading.Thread(target=self.runPythonScriptThread, args=(stop_event,file_type,flow_graph_filename,variable_names,variable_values))  # backticks execute commands

        c_thread.daemon = True
        c_thread.start()
        
    def attackFlowGraphStop(self, parameter):
        """ Stop the currently running attack flow graph.
        """
        # User Kills Python Scripts Manually
        if parameter == "Python Script":  
            pass        
            #os.system("sudo pkill -f " + '"' + self.attack_script_name +'"')  # Make terminal responsible for killing scripts
            
            #script_pid = subprocess.check_output("pgrep -f '" + self.attack_script_name + "'", shell=True)
            #print(script_pid)
            #os.system("sudo kill " + str(script_pid))
        elif parameter == "Flow Graph - GUI":
            os.system("pkill -f " + '"' + self.attack_script_name +'"')
        else:         
            self.attackflowtoexec.stop()
            self.attackflowtoexec.wait()
            
            # Stop Fuzzer Thread or Future Blocks with Infinite Threads
            if hasattr(self.attackflowtoexec,'fuzzer_fuzzer_0_0'):
                self.attackflowtoexec.fuzzer_fuzzer_0_0.stop_event.set()
                
            del self.attackflowtoexec  # Free up the ports    
            self.attack_flow_graph_loaded = False
            
    def runFlowGraphThread(self, stop_event, flow_graph_filename, variable_names, variable_values):
        """ Runs the attack script in the new thread.
        """
        # Stop Any Running Attack Flow Graphs
        try:
            self.attackFlowGraphStop(None)
        except:
            pass
            
        try:                  
            # Overwrite Variables
            loadedmod, class_name = self.overwriteFlowGraphVariables(flow_graph_filename, variable_names, variable_values)
            
            # Call the "__init__" Function
            self.attackflowtoexec = getattr(loadedmod,class_name)()       

            # Start it
            self.attackflowtoexec.start()  # How do you tell if this fails? 
            if "iq_recorder" in flow_graph_filename:
                self.flowGraphStarted("IQ")
            elif "iq_playback" in flow_graph_filename:                
                self.flowGraphStarted("IQ Playback")
            else:
                self.flowGraphStarted("Attack")  # Signals to other components
            
            # Physical Layer Fuzzing Can Now Commence
            self.attack_flow_graph_loaded = True     
            
            # Let it Run
            self.attackflowtoexec.wait()                 

            # Signal on the PUB that the Attack Flow Graph is Finished
            if "iq_recorder" in flow_graph_filename:
                self.flowGraphFinished("IQ")
            elif "iq_playback" in flow_graph_filename:
                self.flowGraphFinished("IQ Playback")
            else:
                self.flowGraphFinished("Attack")  
            
        # Error Loading Flow Graph              
        except Exception as e:
            if "iq_recorder" in flow_graph_filename:
                self.flowGraphStarted("IQ")
                self.flowGraphFinished("IQ")
            elif "iq_playback" in flow_graph_filename:
                self.flowGraphStarted("IQ Playback")
                self.flowGraphFinished("IQ Playback")
            else:
                self.flowGraphStarted("Attack")
                self.flowGraphFinished("Attack")                  
                self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Error', Parameters = e)  
                self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Multi-Stage Attack Finished', Parameters = "")  
            #~ #raise e   
            
            
    ##############  IQ Recording, IQ Playback Flow Graphs  #############
      
    def iqFlowGraphStart(self, flow_graph_filename, variable_names, variable_values, file_type):
        """ Runs the IQ flow graph with the specified file path.
        """       
        # Make a new Thread
        stop_event = threading.Event()
        if file_type == "Flow Graph":
            c_thread = threading.Thread(target=self.iqFlowGraphThread, args=(stop_event,flow_graph_filename,variable_names,variable_values))
        c_thread.daemon = True
        c_thread.start()
        
    def iqFlowGraphStop(self, parameter):
        """ Stop the currently running IQ flow graph.
        """       
        self.iqflowtoexec.stop()
        self.iqflowtoexec.wait()            
        del self.iqflowtoexec  # Free up the ports    
            
    def iqFlowGraphThread(self, stop_event, flow_graph_filename, variable_names, variable_values):
        """ Runs the IQ script in the new thread.
        """
        # Stop Any Running IQ Flow Graphs
        try:
            self.iqFlowGraphStop(None)
        except:
            pass
            
        try:                  
            # Overwrite Variables
            loadedmod, class_name = self.overwriteFlowGraphVariables(flow_graph_filename, variable_names, variable_values)
            
            # Call the "__init__" Function
            self.iqflowtoexec = getattr(loadedmod,class_name)()       

            # Start it
            self.iqflowtoexec.start()  
            if "iq_recorder" in flow_graph_filename:
                self.flowGraphStarted("IQ")
            elif "iq_playback" in flow_graph_filename:                
                self.flowGraphStarted("IQ Playback")
                        
            # Let it Run
            self.iqflowtoexec.wait()                 

            # Signal on the PUB that the IQ Flow Graph is Finished
            if "iq_recorder" in flow_graph_filename:
                self.flowGraphFinished("IQ")
            elif "iq_playback" in flow_graph_filename:
                self.flowGraphFinished("IQ Playback")  
            
        # Error Loading Flow Graph              
        except Exception as e:
            if "iq_recorder" in flow_graph_filename:
                self.flowGraphStarted("IQ")
                self.flowGraphFinished("IQ")
            elif "iq_playback" in flow_graph_filename:
                self.flowGraphStarted("IQ Playback")
                self.flowGraphFinished("IQ Playback")     
      
            
    ####################  Inspection Flow Graphs  ######################
    def inspectionFlowGraphStart(self, flow_graph_filename, variable_names, variable_values, file_type):
        """ Runs the flow graph with the specified file path.
        """       
        # Make a new Thread
        stop_event = threading.Event()

        # Only Supports Flow Graphs with GUIs
        if file_type == "Flow Graph - GUI":
            c_thread = threading.Thread(target=self.inspectionFlowGraphGUI_Thread, args=(stop_event,flow_graph_filename,variable_names,variable_values))
            c_thread.daemon = True
            c_thread.start()
        
    def inspectionFlowGraphStop(self, parameter):
        """ Stop the currently running inspection flow graph.
        """
        # Only Supports Flow Graphs with GUIs
        if parameter == "Flow Graph - GUI":
            os.system("pkill -f " + '"' + self.inspection_script_name +'"')
            
    def inspectionFlowGraphGUI_Thread(self, stop_event, flow_graph_filename, variable_names, variable_values):
        """ Runs the inspection flow graph in the new thread.
        """
        # Stop Any Running Inspection Flow Graphs
        try:
            self.inspectionFlowGraphStop(None)
        except:
            pass
            
        try:                      
            # Start it
            filepath = flow_graph_filename
            flow_graph_filename = flow_graph_filename.rsplit("/",1)[1]
            arguments = ""
            for n in variable_values:
                arguments = arguments + n + " "
                
            osCommandString = "python3 " + '"' + filepath + '" ' + arguments
            proc = subprocess.Popen(osCommandString + " &", shell=True)
              
            self.flowGraphStarted("Inspection")  # Signals to other components 
            self.inspection_script_name = flow_graph_filename
 
        # Error Loading Flow Graph              
        except Exception as e:
            self.flowGraphStarted("Inspection")
            self.flowGraphFinished("Inspection")     
            # ~ self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Error', Parameters = e)  # Custom error message if necessary
            #~ #raise e
    

    #######################  Protocol Discovery  #######################
    def protocolDiscoveryFG_Start(self, flow_graph_filename, variable_names, variable_values):
        """ Runs the flow graph with the specified file path.
        """
        # Make a new Thread
        class_name = flow_graph_filename.replace(".py","")
        stop_event = threading.Event()
        c_thread = threading.Thread(target=self.protocolDiscoveryFG_ThreadStart, args=(stop_event,class_name,variable_names,variable_values))
        c_thread.start()
            
    def protocolDiscoveryFG_Stop(self, parameter):
        """ Stop the currently running flow graph.
        """
        self.pdflowtoexec.stop()
        self.pdflowtoexec.wait()         
        del self.pdflowtoexec  # Free up the ports
                
    def protocolDiscoveryFG_ThreadStart(self, stop_event, flow_graph_filename, variable_names, variable_values):
        """ Runs the flow graph in the new thread.
        """      
        # Stop Any Running PD Flow Graphs
        try:
            self.stopFlowGraph(None)
        except:
            pass
            
        try:            
            # Overwrite Variables
            loadedmod, class_name = self.overwriteFlowGraphVariables(flow_graph_filename, variable_names, variable_values)
            
            # Call the "__init__" Function
            self.pdflowtoexec = getattr(loadedmod,class_name)()                                          
            
            # Start it
            self.pdflowtoexec.start()      
            self.flowGraphStarted("PD")  # Signals to other components
            self.pdflowtoexec.wait() 
            
            # Signal on the PUB that the PD Flow Graph is Finished
            self.flowGraphFinished("PD") 
        
        # Error Loading Flow Graph              
        except Exception as e:
            self.flowGraphStarted("PD")
            self.flowGraphFinished("PD")     
            self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Error', Parameters = e)
            
    
    ######################  Sniffer Flow Graphs  #######################        
    def snifferFlowGraphStart(self, flow_graph_filename, variable_names, variable_values):
        """ Runs the flow graph with the specified file path.
        """
        # Make a new Thread
        class_name = flow_graph_filename.replace(".py","")
        stop_event = threading.Event()
        c_thread = threading.Thread(target=self.snifferFlowGraphThread, args=(stop_event,class_name,variable_names,variable_values))
        c_thread.start()
            
    def snifferFlowGraphStop(self, parameter):
        """ Stop the currently running flow graph.
        """
        # Stop Sniffer Flow Graph (Wireshark Keeps Going)
        self.snifferflowtoexec.stop()
        self.snifferflowtoexec.wait()                         
        del self.snifferflowtoexec  # Free up the ports

        if parameter[0] == "Stream":
            self.flowGraphFinished("Sniffer - Stream")  
        elif parameter[0] == "TaggedStream":
            self.flowGraphFinished("Sniffer - Tagged Stream")  
        elif parameter[0] == "Message/PDU":
            self.flowGraphFinished("Sniffer - Message/PDU")        
                
    def snifferFlowGraphThread(self, stop_event, flow_graph_filename, variable_names, variable_values):
        """ Runs the flow graph in the new thread.
        """                  
        try:   
            # Overwrite Variables
            loadedmod, class_name = self.overwriteFlowGraphVariables(flow_graph_filename, variable_names, variable_values)
            
            # Call the "__init__" Function
            self.snifferflowtoexec = getattr(loadedmod,class_name)()                                          
            
            # Start it
            self.snifferflowtoexec.start()      
            if "Sniffer_stream" in flow_graph_filename:
                self.flowGraphStarted("Sniffer - Stream")
            elif "Sniffer_tagged_stream" in flow_graph_filename:
                self.flowGraphStarted("Sniffer - Tagged Stream")
            elif "Sniffer_async" in flow_graph_filename:
                self.flowGraphStarted("Sniffer - Message/PDU")
            self.snifferflowtoexec.wait() 
                    
        # Error Loading Flow Graph              
        except Exception as e:
            if "Sniffer_stream.py" in flow_graph_filename:
                self.flowGraphStarted("Sniffer - Stream")
                self.flowGraphFinished("Sniffer - Stream")  
            elif "Sniffer_tagged_stream.py" in flow_graph_filename:
                self.flowGraphStarted("Sniffer - Tagged Stream")
                self.flowGraphFinished("Sniffer - Tagged Stream")  
            elif "Sniffer_async.py" in flow_graph_filename:
                self.flowGraphStarted("Sniffer - Message/PDU")
                self.flowGraphFinished("Sniffer - Message/PDU")              
   
            # self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Error', Parameters = e)
                    


    #######################  Physical Fuzzing  #########################
    def physicalFuzzingStart(self, fuzzing_variables, fuzzing_type, fuzzing_min, fuzzing_max, fuzzing_update_period, fuzzing_seed_step):
        """ Sets variables within a flow graph as specified by the Dashboard.
        """       
        # Make a new Thread
        self.fuzzing_stop_event = threading.Event()
        fuzzing_thread = threading.Thread(target=self.physicalFuzzingThreadStart, args=(self.fuzzing_stop_event,fuzzing_variables,fuzzing_type,fuzzing_min,fuzzing_max,fuzzing_update_period,fuzzing_seed_step))
        fuzzing_thread.daemon = True
        fuzzing_thread.start()  
        
    def physicalFuzzingThreadStart(self, stop_event, fuzzing_variables, fuzzing_type, fuzzing_min, fuzzing_max, fuzzing_update_period, fuzzing_seed_step):
        """ Updates flow graph variables for a running flow graph at a specified rate.
        """ 
        # Wait for Flow Graph to Load
        while True:
            if self.attack_flow_graph_loaded == True:
                break
            time.sleep(0.1)
        
        # Get the Update Period
        try:
            update_period = float(fuzzing_update_period)
        except:
            update_period = 1   
            
        # Initialize Values
        for n in range(0,len(fuzzing_variables)):
            variable = str(fuzzing_variables[n])

            if fuzzing_type[n] == "Sequential":
                # Check if it is a Float
                if self.isFloat((fuzzing_min[n])):
                    generic_value = float(fuzzing_min[n])
                # What Happens for a String?    
                else:
                    generic_value = str(fuzzing_min[n])
            elif fuzzing_type[n] == "Random":
                # Check if it is a Float
                if self.isFloat((fuzzing_min[n])):
                    generic_rg = random.Random(float(fuzzing_seed_step[n]))
                    generic_value = generic_rg.randrange(float(fuzzing_min[n]),float(fuzzing_max[n]),1)     
                # What Happens for a String?    
                else:
                    generic_value = str(fuzzing_min[n])                 
        
        # Set Variable Loop     
        while(not stop_event.is_set()):
            
            # Update Each Checked Variable
            for n in range(0,len(fuzzing_variables)):
                
                variable = str(fuzzing_variables[n])
                            
                # Call the Set Function of the Flow Graph
                self.setVariable("Attack",variable, generic_value)
                print("Set " + variable + " to: {}" .format(generic_value))
                
                # Generate New Value
                if fuzzing_type[n] == "Sequential":     
                    # Float 
                    if self.isFloat(fuzzing_min[n]):                 
                        # Increment
                        generic_value = generic_value + float(fuzzing_seed_step[n])
                        
                        # Max is Reached
                        if generic_value > float(fuzzing_max[n]):
                            generic_value = float(fuzzing_min[n])
                            
                    # What Happens for a String?        
                    else:
                        generic_value = str(fuzzing_min[n])     
                        
                elif fuzzing_type[n] == "Random":
                    if self.isFloat(fuzzing_min[n]):                     
                        # New Random Number
                        generic_value = generic_rg.randrange(float(fuzzing_min[n]),float(fuzzing_max[n]),1)     
                    # What Happens for a String?    
                    else:   
                        generic_value = str(fuzzing_min[n])                                                     
            
            # Sleep at "Update Interval"
            time.sleep(update_period)
                
    def physicalFuzzingStop(self):
        """ Stop physical fuzzing on the currently running attack flow graph.
        """
        try:
            # Reset Listener Loop Variable
            self.attack_flow_graph_loaded = False
            
            # Stop the Thread
            self.fuzzing_stop_event.set()
        except:
            pass
        

    #######################  Multi-Stage Attack  #######################
    def multiStageAttackStart(self, filenames, variable_names, variable_values, durations, repeat, file_types):
        """ Starts a new thread for running two flow graphs. A new thread is created to allow the FGE Executor to still perform normal functionality while waiting for an attack to finish.
        """        
        # Make a New Thread
        self.multi_stage_stop_event = threading.Event()
        multi_stage_thread = threading.Thread(target=self.multiStageAttackThreadStart, args=(filenames, variable_names, variable_values, durations, repeat, file_types))
        
        multi_stage_thread.start()  
        
    def multiStageAttackThreadStart(self, filenames, variable_names, variable_values, durations, repeat, file_types):
        """ Starts consecutive flow graphs with each running for a set duration with a fixed pause in between.
        """     
        while(not self.multi_stage_stop_event.is_set()):
            for n in range(0,len(filenames)):
                
                # Make a new Thread
                stop_event = threading.Event()
                if file_types[n] == "Flow Graph":
                    flow_graph_filename = filenames[n].replace(".py","")
                    c_thread = threading.Thread(target=self.runFlowGraphThread, args=(stop_event,flow_graph_filename,variable_names[n],variable_values[n]))
                elif file_types[n] == "Flow Graph - GUI":
                    flow_graph_filename = filenames[n].replace(".py","")
                    c_thread = threading.Thread(target=self.runFlowGraphThread, args=(stop_event,flow_graph_filename,variable_names[n],variable_values[n]))
                # Python2, Python3
                else:
                    c_thread = threading.Thread(target=self.runPythonScriptThread, args=(stop_event,file_types[n],filenames[n],variable_names[n],variable_values[n]))

                c_thread.daemon = True
                c_thread.start()

                # Wait for the Flow Graph to Start
                if (file_types[n] == "Flow Graph") or (file_types[n] == "Flow Graph - GUI"):
                    while self.attack_flow_graph_loaded == False:
                        pass
                    
                # Start the Timer   
                start_time = time.time()    
                while time.time() - start_time < float(durations[n]): 
                    # Check if Stop was Pressed while Running Flow Graph
                    if self.multi_stage_stop_event.is_set():
                        break
                    time.sleep(.05)
                
                # Stop the Flow Graph
                if (file_types[n] == "Flow Graph") or (file_types[n] == "Flow Graph - GUI"):
                    self.attackFlowGraphStop("")
                    time.sleep(0.5)  # LimeSDR needs time to stop or there will be a busy error
                else:
                    self.attackFlowGraphStop("Python Script")
                
                # Break if Stop was Pressed while Running Flow Graph
                if self.multi_stage_stop_event.is_set():
                    break
            
            # End the thread
            if repeat == False:
                self.multiStageAttackStop("")
        
    def multiStageAttackStop(self, parameter):
        """ Stops a multi-stage attack already in progress
        """
        try:
            # Signal to the Other Components
            self.multiStageAttackFinished()
            
            # Reset Listener Loop Variable
            self.attack_flow_graph_loaded = False
            
            # Stop the Thread
            self.multi_stage_stop_event.set()
        except:
            pass    
            
    def multiStageAttackFinished(self):
        """ Signals to the other components that the multi-stage attack has finished.
        """
        # Send the Message
        self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Multi-Stage Attack Finished', Parameters = "")   
        
        
    #######################  Archive Playlist  #########################
    def archivePlaylistStart(self, flow_graph, filenames, frequencies, sample_rates, formats, channels, gains, durations, repeat, ip_address, serial):
        """ Starts a new thread for running the same replay flow graph multiple times for a specified duration.
        """        
        # Make a New Thread
        self.archive_playlist_stop_event = threading.Event()
        archive_playlist_thread = threading.Thread(target=self.archivePlaylistThreadStart, args=(flow_graph, filenames, frequencies, sample_rates, formats, channels, gains, durations, repeat, ip_address, serial))        
        archive_playlist_thread.start()  
        
    def archivePlaylistThreadStart(self, flow_graph, filenames, frequencies, sample_rates, formats, channels, gains, durations, repeat, ip_address, serial):
        """ Starts consecutive flow graphs with each running for a set duration with a fixed pause in between.
        """     
        # LimeSDR Channel Nomenclature
        for m in range(0,len(channels)):
            if channels[m] == "A":
                channels[m] = "0"
            elif channels[m] == "B":
                channels[m] = "1"
                
        while(not self.archive_playlist_stop_event.is_set()):
            for n in range(0,len(filenames)):
                # Send File Position to Dashboard
                self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Archive Playlist Position', Parameters = str(n))  
                
                # Change Variable Values
                variable_names = ["tx_gain","tx_frequency","tx_channel","sample_rate","ip_address","filepath","ip_address","serial"]
                variable_values = [gains[n],frequencies[n],channels[n],sample_rates[n],"",filenames[n],ip_address, serial]
                
                # Make a new Thread
                stop_event = threading.Event()
                c_thread = threading.Thread(target=self.archiveFlowGraphThread, args=(stop_event,flow_graph,variable_names,variable_values))
                c_thread.daemon = True
                c_thread.start()

                # Wait for the Flow Graph to Start
                while self.archive_flow_graph_loaded == False:
                    pass
                    
                # Start the Timer   
                start_time = time.time()    
                while time.time() - start_time < float(durations[n]): 
                    # Check if Stop was Pressed while Running Flow Graph
                    if self.archive_playlist_stop_event.is_set():
                        break
                    time.sleep(.05)
                
                # Stop the Flow Graph
                self.archiveFlowGraphStop()
                time.sleep(0.5)  # LimeSDR needs time to stop or there will be a busy error
                
                # Break if Stop was Pressed while Running Flow Graph
                if self.archive_playlist_stop_event.is_set():
                    break
            
            # End the thread
            if repeat == False:
                self.archivePlaylistStop("")
        
    def archivePlaylistStop(self, parameter):
        """ Stops a multi-stage attack already in progress
        """
        try:
            # Signal to the Other Components
            self.archivePlaylistFinished()
            
            # Reset Listener Loop Variable
            self.archive_flow_graph_loaded = False
            
            # Stop the Thread
            self.archive_playlist_stop_event.set()
        except:
            pass    
            
    def archiveFlowGraphThread(self, stop_event, flow_graph_filename, variable_names, variable_values):
        """ Runs the attack script in the new thread.
        """
        # Stop Any Running Attack Flow Graphs
        try:
            self.attackFlowGraphStop(None)
        except:
            pass
            
        try:                  
            # Overwrite Variables
            loadedmod, class_name = self.overwriteFlowGraphVariables(flow_graph_filename, variable_names, variable_values)
            
            # Call the "__init__" Function
            self.archiveflowtoexec = getattr(loadedmod,class_name)()       

            # Start it
            self.archiveflowtoexec.start()  
            # if "archive_replay" in flow_graph_filename:                
                # pass
            self.archive_flow_graph_loaded = True     
            
            # Let it Run
            self.archiveflowtoexec.wait()                 

            # Signal on the PUB that the Attack Flow Graph is Finished
            # if "archive_replay" in flow_graph_filename:                
                # pass
            
        # Error Loading Flow Graph              
        except Exception as e:
            if "archive_replay" in flow_graph_filename:
                self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Archive Playlist Finished', Parameters = "") 
            else:
                pass
                #self.flowGraphStarted("Attack")
                #self.flowGraphFinished("Attack")     
                #self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Flow Graph Error', Parameters = e)  
                #self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Multi-Stage Attack Finished', Parameters = "")  
            #~ #raise e   
            
    def archiveFlowGraphStop(self):
        """ Stop the currently running archive flow graph.
        """
        self.archiveflowtoexec.stop()
        self.archiveflowtoexec.wait()            
        del self.archiveflowtoexec  # Free up the ports    
        self.archive_flow_graph_loaded = False
            
    def archivePlaylistFinished(self):
        """ Signals to the other components that the multi-stage attack has finished.
        """
        # Send the Message
        self.fge_pub_server.sendmsg('Status', Identifier = 'FGE', MessageName = 'Archive Playlist Finished', Parameters = "")       
    
    ####################################################################
                        
if __name__=="__main__":
    # Create FGE Executor Object
    fg_executor_object = FGE_Executor()
    

