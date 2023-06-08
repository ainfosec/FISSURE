#!/usr/bin/env python3

import zmq
import yaml
from string import Template
import time 
import logging
import logging.config
import os


"""Zmq server and client classes for FISSURE
# Todo: (Maybe)                 
         Add in example program transitioning between 2 gnuradio flowgraphs using fissure class
                  
         Add in data type validator for all data types, throw error if not valid data type
         Add in try/except blocks for data typing
         add in try/except for callback import (and "function not implemented messages" if necessary)               
         Add in try/except error messages for unimplemented functions, flowgraphs or non-existing commands
Done:
    #    Export Chris' Messages into YAML
    #    Add logging         
    #    Add in specific listener or server prompt string (for logging)
    #    Add in non-blocking listener as option for polling with variable timeout
    #    Add in validation before send
    #    Add ZMQ input
    #    Make ZMQ client for user input
    #    Make class to interpret ZMQ input and load
    #    Make return proc for sending ZMQ data back (starting as PUB/SUB, may switch later)
    #    Load description from YAML
    #    Add in callback for listener to implement
    ##   Add in yaml load for both - Done


 """

class fissure_server(object):
        
    def __init__(self, yamldoc, ip, port, pairtype, logcfg, logsource):
        self.ignore_list = ["HIPRFISR:/Heartbeat", "Dashboard:/Heartbeat", "TSI:/Heartbeat", "FGE:/Heartbeat", "PD:/Heartbeat", "PD:/Full Library", "PD:/Buffer Size"] 
        self.parse_list = ["HIPRFISR:/", "Dashboard:/", "TSI:/", "FGE:/", "PD:/"] 
        self.port = port
        self.mqtype = pairtype
        self.context = zmq.Context()        
        self.socket = self.context.socket(self.mqtype)     
        with open(logcfg, 'rt') as f:
          config = yaml.load(f.read(),yaml.FullLoader)
          # Since only a filename is specified in the config file,
          # Add our current directory to the filename to guarantee it's location
          config["handlers"]["file"]["filename"] = os.path.dirname(os.path.realpath(__file__)) + "/" + config["handlers"]["file"]["filename"]

        # Check if directory of the logging file specified exists, and if it doesn't, create it
        if not os.path.exists(os.path.dirname(config["handlers"]["file"]["filename"])):
            os.makedirs(os.path.dirname(config["handlers"]["file"]["filename"]))
        
        logging.config.dictConfig(config)
        global logger           
        logger = logging.getLogger(logsource)   
        self.initialize_port(ip, port)
        self.initialize_schema(yamldoc)
           
        
    def initialize_port(self, ip, port):
        portinit="tcp://{}:{}".format(ip, port)        
        logger.debug("Port Initialized to %s",portinit)
        return self.socket.bind(portinit)
    
    def send(self,msg):
        self.socket.send_string(msg)
        
    def recvwait(self):
        msg = self.socket.recv()
        return msg
        
    def recv(self):
        try:
           msg = self.socket.recv_string(zmq.NOBLOCK)
        except zmq.ZMQError:
            msg = None        
        return msg
        
    def recvmsg(self):
        msgrcvd = self.recv()
        if msgrcvd == None:
            parsed = None 
        else:   
            if any(x in msgrcvd for x in self.ignore_list):
                pass
            else:
                logger.debug("Received message: %s",msgrcvd.replace('/',' '))    
            parsed = self.parsemsg(msgrcvd)
        return parsed
        
    def sendmsg(self, schemaname, **kwargs):
        schema = self.schemadata['Schema'][schemaname]
        sndmsg = self.generatemsg(schema,**kwargs)
        self.send(sndmsg)       
        if any(x in sndmsg for x in self.ignore_list):
            pass
        else:  
            logger.debug("Sending message: %s",sndmsg.replace('/',' '))
    
    def recvmsgwait(self):
        msgrcvd = self.recvwait()        
        if any(x in msgrcvd for x in self.ignore_list):               
            pass
        else:   
            logger.debug("Received message: %s",msgrcvd.replace('/',' '))
        parsed = self.parsemsg(msgrcvd)
        return parsed   
    
    def initialize_schema(self, yamldoc):
        with open(yamldoc) as infile:
            data = infile.read()
            self.schemadata = yaml.load(data,yaml.FullLoader)
            self.callbacks = [k for k,v in self.schemadata.items() if isinstance(v,dict) if v.get('Type',None)=='callback']        
        logger.debug("Initialized Schema: %s",yamldoc)
    
    def generatemsg(self, schema, **kwargs):
        schemainternal = schema.replace(' ','/')        
        tmplate = Template(schemainternal)      
        return tmplate.safe_substitute(kwargs)                
            
    def parsemsg(self, msgparse):
        """ code to parse incoming messages from schema 
            #Todo: Parse down callback if command
                   Throw error for unimplemented message
                   Throw error if message invalid                                    
        """
        identifier,msg = msgparse.split(':/',1)
        
        #figure out what type the message is by the first part of the string
        msgtypeidx, msgattributes = msg.split('/',1)   
        foundmsgtype = False     
        for k in self.schemadata['Message Types']: #add if more message types                                        
            if msgtypeidx in self.schemadata.get(k,[]):                 
                schema = self.schemadata['Schema'][k].replace(' $','/$')
                foundmsgtype = True             
                break            
        # no message type found!
        #classify it by the msgtypeidx (schema name, first variable and sent type have to be equal) 
        if not foundmsgtype:
            k = msgtypeidx
            schema = self.schemadata['Schema'][k].replace(' $','/$')      
                    
        schemasplit = [strins.strip("$:") for strins in schema.split('/')]
        msgsplit = [strins.strip("$:") for strins in msgparse.split('/',len(schemasplit)-1)] #strip out schema leftovers if there
        parsedata = dict(zip([strins for strins in schemasplit if strins not in msgsplit],[strins for strins in msgsplit if strins not in schemasplit]))   
        parsedata['Type'] = k

        #Oh, we're a command? Let's add in our callback to the parsed....        
        if k=='Commands':                        
            #callback = self.schemadata[parsedata[k]]
            callback = self.schemadata[parsedata["MessageName"]]
            parsedata['callback'] = callback
        return parsedata
        
    def validatedata(self, validmsg, schemas):
        """ put in code to validate data declared in callback function        
        """
        pass
        return validmsg in self.schemadata['Commands']    
       
class fissure_listener(fissure_server):    
        
    def initialize_port(self, ip, port):
        if self.socket.getsockopt(zmq.TYPE)==zmq.SUB:       
            self.socket.setsockopt_string(zmq.SUBSCRIBE, '')
        portinit="tcp://{}:{}".format(ip, port)        
        logger.info("Port Connected to %s",portinit)
        return self.socket.connect(portinit)        
    
    def register_callback(self,callback):
        self.callbacks[callback.__name__]=callback
    
    def runcallback(self, context, parsedcommand):
        """ We've received a callback! Great... Now what? (parameters 
        is a dictionary containing a parsed message that has a callback in it, now 
        we pass in a local context to resolve the method or function and call
        it as appropriate (context can either be a class with the function under consideration, or
        a globals() and/or locals() dictionary """

        try:
            callbacktoexec = getattr(context, parsedcommand["callback"])
        except AttributeError:
            callbacktoexec = context.get(parsedcommand["callback"])
        if callbacktoexec is None:
            raise Exception("method {} not implemented in context {}".format(parsedcommand["callback"],context) )
        logger.debug("Executing Callback: {} with parameters {}".format(parsedcommand["callback"],parsedcommand.get("Parameters")))
    
        # Command Schema must contain a "Parameters" variable for any parameters 
        # if not, the function is called with no parameters passed   

        # Commands with no Parameters
        if "Parameters" not in parsedcommand.keys(): #no parameters 
            return callbacktoexec()   
        else:
            # Commands with Empty Parameters
            if len(parsedcommand["Parameters"]) == 0:
                params=parsedcommand["Parameters"]
                return callbacktoexec(params.split())                  
            else:
                # Parameters in Dictionary Form
                if '{' == parsedcommand["Parameters"][0]: # dict
                    params = yaml.load(parsedcommand["Parameters"],yaml.FullLoader) 
                    return callbacktoexec(**params)        
                    
                # Parameters in List Form
                elif "[" == parsedcommand["Parameters"][0]: # list
                    params = yaml.load(parsedcommand["Parameters"],yaml.FullLoader) 
                    return callbacktoexec(*params)    
                    
                # Parameters in Space Separated String Form
                else:
                    params=parsedcommand["Parameters"]
                    return callbacktoexec(params.split())        
    
# # Callback for Testing
# def do_TSI(*args, **kwargs):    
    # print("Doing TSI!", args, kwargs)
        
# class flowgraph1(object):
    # #callback #2 for testing
    # def do_TSI(self, *args, **kwargs):    
        # print("Doing TSI!", args, kwargs)
    
    
if __name__ == '__main__':    
    port = 5051
    fs = fissure_server('server.yaml','*',port,zmq.PAIR, logcfg = "logging.yaml")
    fl = fissure_listener('listener.yaml','localhost',port,zmq.PAIR, logcfg = "logging.yaml")   
    logger.info("initialized server and listener")     
    waitforsending = 1e-4 #takes ~ 3e-6, below 3e-5 gets error from no receive (none returned)        
    cmd = 'Commands'
    soi = 'SOI'
    #now actually use message passing/parsing        
    fs.sendmsg(cmd,Identifier = 'HIPRFISR', Commands='Set Freq', Parameters = '2.4e7 50e6' )
    time.sleep(waitforsending) #non-instantaneous time for non-blocking receive    
    parsed = fl.recvmsg()      
    print("parsed message = ", parsed) 
    print("Callback to execute=", parsed['callback'], "Parameters = ", parsed['Parameters'])
    
    fs.sendmsg(cmd,Identifier = 'HIPRFISR', Commands='Run', Parameters = 'DECT 2.4e7 50e6' )
    time.sleep(waitforsending) #non-instantaneous time for non-blocking receive    
    parsed = fl.recvmsg()       
    print(parsed)
    print("Callback to execute=", parsed['callback'], "Parameters = ", parsed['Parameters'])
    
    #now execute a callback!
    fs.sendmsg(cmd,Identifier = 'HIPRFISR', Commands='Run TSI', Parameters = 'DECT 2.4e7 50e6' )
    time.sleep(waitforsending) #non-instantaneous time for non-blocking receive    
    parsed = fl.recvmsg()      
    print(parsed)
    print("Callback to execute=", parsed['callback'], "Parameters = ", parsed['Parameters'])
    logger.info("Executing Callback, Run TSI")
    globalslocalcontext=globals().copy() #if the callback is a function...   
    globalslocalcontext.update(locals())  #if it was a class member, you'd just pass the class in here
    print('\n fdgfdgdgfdgfdghd {} \n' .format(globalslocalcontext))
    print('hjgjhgk: {} \n' .format(parsed))
    
    fl.runcallback(globalslocalcontext,parsed)
    
    ##execute callback with list
    #fs.sendmsg(cmd,Identifier = 'HIPRFISR', Commands='Run TSI', Parameters = '[DECT, 2.4e7, 50e6]' )
    #time.sleep(waitforsending) #non-instantaneous time for non-blocking receive    
    #parsed = fl.recvmsg()      
    #print(parsed)
    #print "Callback to execute=", parsed['callback'], "Parameters = ", parsed['Parameters']
    #logger.info("Executing Callback, Run TSI")
    #globalslocalcontext=globals().copy() #if the callback is a function... 
    #globalslocalcontext.update(locals())  #if it was a class member, you'd just pass the class in here
    #fl.runcallback(globalslocalcontext,parsed)
    
    ##execute callback with dictionary
    #fs.sendmsg(cmd,Identifier = 'HIPRFISR', Commands='Run TSI', Parameters = '{Modtype=DECT, freq=2.4e7, bw=50e6}' )
    #time.sleep(waitforsending) #non-instantaneous time for non-blocking receive    
    #parsed = fl.recvmsg()      
    #print(parsed)
    #print "Callback to execute=", parsed['callback'], "Parameters = ", parsed['Parameters']
    #logger.info("Executing Callback, Run TSI")
    #globalslocalcontext=globals().copy() #if the callback is a function... 
    #globalslocalcontext.update(locals())  #if it was a class member, you'd just pass the class in here
    #fl.runcallback(globalslocalcontext,parsed)
    
    ##execute callback inside flowgraph
    #fs.sendmsg(cmd,Identifier = 'HIPRFISR', Commands='Run TSI', Parameters = '{Modtype=DECT, freq=2.4e7, bw=50e6}' )
    #time.sleep(waitforsending) #non-instantaneous time for non-blocking receive    
    #parsed = fl.recvmsg()      
    #print(parsed)
    #print "Callback to execute=", parsed['callback'], "Parameters = ", parsed['Parameters']
    #logger.info("Executing Callback inside flowgraph, Run TSI")
    #flowgraph = flowgraph1()
    #fl.runcallback(flowgraph,parsed)
    
    
    #fl.sendmsg(soi,Identifier = 'TSI', ModulationType='FSK', Frequency = '2.4e7', Bandwidth='50e6' )
    #time.sleep(waitforsending) #non-instantaneous time for non-blocking receive    
    #parsed = fs.recvmsg()      
    #print("parsed message = ", parsed)

    #fl.sendmsg('Status',Identifier = 'TSI', Status = 'Wideband', Pieces='50e6 3db {}'.format(time.time()) )
    #time.sleep(waitforsending) #non-instantaneous time for non-blocking receive    
    #parsed = fs.recvmsg()      
    #print("parsed message = ", parsed)
    
    #pc_id='TSI'
    #sdr_count = 2
    #sdr1 = 1
    #sdr2 = 2
    #sdr3 = 3 
    #fl.sendmsg('Status',Identifier = 'TSI', Status = 'Heartbeat', Pieces='{}, {}, {}, {}, {}' .format(pc_id, sdr_count, sdr1, sdr2, sdr3) )
    #time.sleep(waitforsending) #non-instantaneous time for non-blocking receive    
    #parsed = fs.recvmsg()      
    #print("parsed message = ", parsed)
    
    #fs.sendmsg(cmd,Commands='Change Bandwidth', Identifier = 'HIPRFISR', Parameters = '30db' )
    #time.sleep(waitforsending) #non-instantaneous time for non-blocking receive    
    #parsed = fl.recvmsg()      
    #print("parsed message = ", parsed)
    #print(fl.callbacks)
    
    
    
    
