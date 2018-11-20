#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, division
import sys
import os
import io
import re
from . import IxTclHalError
#from IxTclHalError import IxTclHalError


class IxTclHal:

    class ReturnCodes:
        __TCL_OK = '0'
        __TCL_ERROR = '1'
        SUCCESS = __TCL_OK
        FAILURE = __TCL_ERROR
        TRUE = '1'
        FALSE = '0'

    class __Debug:
        def __init__(self):
            self.__enabled = False

        @property
        def IsEnabled(self):
            return self.__enabled

        def Enable(self):
            self.__enabled = True
 
        def Disable(self):
            self.__enabled = False

    def __init__(self, TclServerAddress,  *args):
        """ Initialize the IXIA IxTclHal robot library
            Args:
                TclServerAddress = The address of the IxOS Tcl Server machine
                libPath          = path to the IxOS IxTclHal TCL lib
                optionalLibPath  = path to other libs to be loaded by Tcl interpretter
        """
        self.__tcl_server_connected = False
        self.__chassis_connected_list = []
        self.__init_completed = False
        self.__versions = dict(Tcl=None,IxTclHal=None,PythonPlugin='0.1.0.1')
        self.Debug  = self.__Debug()
        self.__tcl_server_address = TclServerAddress
        self.__init_tcl_interp(args)
     
    def __tcl_print(self, message, nonewline="0", out_stderr="0"):
        if out_stderr == "1":
            print(message, file=sys.stderr)
        else:
            if nonewline == "1":
                print(message, end=' ')
            else:
                print(message)
    
    def __quote_tcl_invalid(self, tcl_string):
        '''
        For user input string quote any tcl list separators
        in order to get good quoting using Tcl_merge. Otherwise, the
        function will quote individual characters instead of the whole string.
        '''
        if not isinstance(tcl_string, str):
            raise ValueError('input not a string')

        invalid_chars = ['{', '}', '\\']

        # state 0 - none
        # state 1 - escaping
        state = 0
        ret = ''
        for c in tcl_string:
            if state == self.ReturnCodes.SUCCESS:
                if c == '\\':
                    state = 1
                elif c in invalid_chars:
                    ret += '\\'
            elif state == 1:
                state = 0
            ret += c
        if state == 1:
            ret += '\\'
        return ret

    def __tcl_flatten(self, obj, key_prefix='', first_call=True):
        '''
        Flatten a python data structure involving dicts, lists and basic data types
        to a tcl list. For the outermost dictionary do not return as a quoted tcl list
        because the quoting is done at evaluation (first_call=True means dont quote)
        '''
        if isinstance(obj, list):
            retlist = [self.__interp.merge(self.__tcl_flatten(x, key_prefix, False)) for x in obj]
            tcl_string = ' '.join(retlist)
        elif isinstance(obj, dict):
            retlist = []
            for (k, v) in obj.items():
                if not first_call:
                    vflat = self.__tcl_flatten(v, '', False)
                    rettext = k + ' ' + self.__interp.merge(vflat)
                    retlist.append(self.__interp.merge(rettext))
                else:
                    retlist.append(key_prefix + k)
                    vflat = self.__tcl_flatten(v, '', False)
                    retlist.append(self.__interp.merge(vflat))

            tcl_string = ' '.join(retlist)
        elif isinstance(obj, str):
            tcl_string = self.__quote_tcl_invalid(obj)
        else:
            tcl_string = str(obj)

        return tcl_string

 
    def __convert_tcl_list(self, tcl_string):
        ''' Returns a python list representing the input tcl list '''
        return list(self.__interp.splitlist(tcl_string))

    def __connect_to_tcl_server(self):
        try:
            connected = self.__eval("ixConnectToTclServer %s"%self.__tcl_server_address) == self.ReturnCodes.SUCCESS
            self.__tcl_server_connected = connected
            if not connected:
                raise IxTclHalError(IxTclHalError.CANNOT_CONNECT_TO_TCLSERVER, 'Please check that IxOS Tcl Server is started on %s'%self.TclServerAddress)
        except:
            e = sys.exc_info()[1]
            raise IxTclHalError(IxTclHalError.CANNOT_CONNECT_TO_TCLSERVER, e.message)
        
    def __disconnect_tcl_server(self):
        try:
            self.__eval("ixDisconnectTclServer %s"%self.TclServerAddress) 
            self.__tcl_server_connected = False
        except:
            pass

    def __init_tcl_interp(self, tcl_autopath_list):
            try:
                try:
                    import Tkinter as tkinter
                except ImportError:
                    import tkinter
            except:
                e = sys.exc_info()[1]
                raise IxTclHalError(IxTclHalError.TKINTER_ERROR, e.message)
            self.__interp = tkinter.Tcl()
            self.__interp.createcommand('__py_puts', self.__tcl_print)
            self.__interp.eval("""
                if { [catch { puts -nonewline {} }] } {
                    #stdout is close. Python's IDLE does not have stdout.
                    __py_puts "Redirecting Tcl's stdout to Python console output."
                    rename puts __tcl_puts
                    proc puts {args} {
                        set processed_args $args
                        set keep_current_line 0
                        set write_to_stderr   0
                        set args_size [llength $args]
                        #check if -nonewline is present
                        set no_new_line_index [lsearch -nocase $processed_args -nonewline]
                        if {$no_new_line_index > -1} {
                            lreplace $processed_args $no_new_line_index $no_new_line_index
                            set keep_current_line 1
                            incr args_size -1
                        }
                        #check if stederr is present
                        set stderr_index [lsearch -nocase $processed_args stderr]
                        if {$stderr_index > -1} {
                            lreplace $processed_args $stderr_index $stderr_index
                            set write_to_stderr 1
                            incr args_size -1
                        }
                        if { $args_size < 2} {
                            # a message for stdout or stderr. Sent to python's print method
                            __py_puts [lindex $processed_args [expr [llength $processed_args] - 1]] $keep_current_line $write_to_stderr
                        } else {
                            # probably a socket. use native tcl puts
                            set cmd "__tcl_puts $args"
                            eval $cmd
                        }
                    }
                }
                """)
            tclHalDllRequired =  (sys.platform == 'win32')
            tclHalDllLocation = None
            for tcl_autopath in tcl_autopath_list:
                self.__interp.eval("lappend ::auto_path {%s}" % tcl_autopath)                 
                for path, dirs, files in os.walk(tcl_autopath):
                    if 'pkgIndex.tcl' in files:
                        self.__interp.eval("lappend ::auto_path {%s}" % path)
                        if 'ixTclHal.tcl' in files:
                            try:
                                file = open(os.path.join(path,'pkgIndex.tcl'), 'r')
                                self.__versions["IxTclHal"] = re.findall("package ifneeded IxTclHal (\d+\.\d+)",''.join(file.readlines()))[0]
                                file.close()
                                if tclHalDllRequired and tclHalDllLocation is None:
                                    expectedTclHalDllLocation = os.path.normpath(os.path.join(path,'..'+os.path.sep+'..'+os.path.sep+'..'+os.path.sep+'IxTCLHAL.dll'))
                                    if os.path.isfile(expectedTclHalDllLocation):
                                        tclHalDllLocation = expectedTclHalDllLocation
                            except:
                                 e = sys.exc_info()[1]
                                 raise IxTclHalError(IxTclHalError.IXTCLHAL_VERSION_NOT_FOUND, e.message)
       
            if not self.__versions["IxTclHal"]:
                tclPath = self.__eval("join $::auto_path").replace("\\","/")
                raise IxTclHalError(IxTclHalError.IXTCLHAL_VERSION_NOT_FOUND, "Please check lib path: %s" % tclPath)

            self.__eval("set env(IXIA_VERSION) %s" % self.__versions["IxTclHal"])
            self.__versions["Tcl"] = self.__eval('info patchlevel')
            print('Tcl version: %s' % self.__versions["Tcl"])
            
            if tclHalDllRequired:
                if  tclHalDllLocation is not None:
                    try:
                        self.__eval(r"load {"+ tclHalDllLocation+"}")
                    except:
                        e = sys.exc_info()[1]
                        raise IxTclHalError(IxTclHalError.CANNOT_LOAD_TCLHAL_DLL, e.message)
                else:
                    raise IxTclHalError(IxTclHalError.CANNOT_FIND_TCLHAL_DLL)    

            self.__versions["IxTclHal"] = self.__eval("package require IxTclHal")
            print('IxTclHal version: %s' % self.__versions["IxTclHal"])

    def __eval(self, code):
        ''' Eval given code in tcl interp '''

        if self.Debug.IsEnabled:
            print('TCL OUT >>> ' + code)
        try:
            ret = self.__interp.eval(code)
        except:
            e = sys.exc_info()[1]
            raise IxTclHalError(IxTclHalError.TCL_COMMAND_FAIL,"%s"% e.message)

        if self.Debug.IsEnabled:
            print('TCL IN <<< ' + ret)
        return ret

   
    @property
    def TclServerAddress(self):
        return self.__tcl_server_address
    @property
    def IsTclServerConnected(self):
        return self.__tcl_server_connected

    @property
    def lastTclError(self):
        ''' Return tcl interp ::errorInfo '''
        return self.__interp.eval('set ::errorInfo')

    def convertToTclList(self, object):
        return self.__tcl_flatten(object)

    @property
    def IsConnectedToChassis(self):
        return self.__chassis_connected_list.count>0

    def disconnectFromTclServer(self):
        if self.__tcl_server_connected:
            self.__disconnect_tcl_server()

    def connectToTclServer(self, TclServerAddress):
        if self.__tcl_server_connected:
            self.__disconnect_tcl_server()
        self.__tcl_server_address = TclServerAddress
        self.__connect_to_tcl_server()

    def connectToChassis(self, chassis):
        if not self.__tcl_server_connected:
            self.__connect_to_tcl_server()

        if chassis in self.__chassis_connected_list:
            
            try: 
                chassisId = self.getChassisId(chassis)
                print ("Chassis %s is already connected. Disconnect first"% chassis)
                return self.getChassisId(chassis)
            except:
                print ("Chassis %s is already connected. Trying to reconnect..."% chassis)
                self.disconnectFromChassis(chassis)
                
        
        try:
            connected = self.__eval("ixConnectToChassis %s"%chassis) == self.ReturnCodes.SUCCESS
            if not connected:
                raise IxTclHalError(IxTclHalError.CANNOT_CONNECT_TO_CHASSIS, 'Please check chasis address (%s) and that IxServer is running'%self.TclServerAddress)
            self.__chassis_connected_list.append(chassis)
            return self.getChasissInfo(chassis)
        except:
            e = sys.exc_info()[1]
            raise IxTclHalError(IxTclHalError.CANNOT_CONNECT_TO_CHASSIS, e.message)
    
    def getChasissInfo(self,chassis):
        chassisInfo = dict()
        chassisInfo[id]  = self.getChassisId(chassis)
        self.__eval("chassis get %s"%chassisInfo[id])
        for prop in ["name","serialNumber","cableLength","sequence","master","maxCardCount","typeName","ixServerVersion"]:
            chassisInfo[prop] = self.__eval("chassis  cget -%s "%prop)
        return chassisInfo


    def getChassisId(self, chassis):
        return self.__eval("ixGetChassisID %s" %chassis)

    def disconnectFromChassis(self, chassis):
        print("Disconnecting from Chassis: %s"%chassis)
        if chassis in self.__chassis_connected_list:
            try:
                self.__eval("ixDisconnectFromChassis %s"%chassis) == self.ReturnCodes.SUCCESS
                self.__chassis_connected_list.remove(chassis)
            except:
                pass
        else:
            print ("Not connected to %s"%s)
        if self.__tcl_server_connected and self.__chassis_connected_list.count == self.ReturnCodes.SUCCESS:
            print ("No chassis connection left. Disconnecting from Tcl Server")
            self.__disconnect_tcl_server()


    def resetHardwareChassis(self, chassis):
        print("Resetting %s chassis hardware..."% chassis)
        chassisId = self.getChassisId(chassis)
        return self.__eval("chassis resetHardware %s"% chassis)
        
    def resetHardwareCard(self, chassis, card):
        print("Resetting card %s from chassis %s..."%( card, chassis))
        chassisId = self.getChassisId(chassis)
        return self.__eval("card resetHardware %s %s"%(chassisId,card))

    def forceHotswapCard(self, chassis, card):
        print("Force hotswap card %s from chassis %s..."%( card, chassis))
        return self.__eval("chassis forceHotswap %s %s"%(chassis,card))
    
    def setPortFactoryDefaults(self, portId):
        print("Setting factory defaults on %s port..."% portId)
        return self.__eval("port setFactoryDefaults %s"%portId)
    
    def rebootPortCpu(self, portId):
        print("Resetting %s port CPU..."% portId)
        return self.__eval("portCpu reset %s"%portId)

    def resetPort(self, portId):
        print("Resetting %s port..."% portId)
        return self.__eval("port reset %s"%portId)

    def getPortId(self, chassis, card, port):
        chassisId = self.getChassisId(chassis)
        return "%s %s %s"%(chassisId,card, port)

    def getPortListFromChassis(self,chassis):
        chassisId =self.getChassisId(chassis)
        portTclList = self.__eval("ixCreatePortListWildCard { { %s * *} }" % chassisId)
        return re.findall("{(%s \d+ \d+)}" % chassisId,portTclList)

    def checkLinkStateForPortsList(self, portList):
        return self.execute("ixCheckLinkState", "[list %s]"%self.convertToTclList(portList))

    def getStatsForPort(self,port):
        return self.execute("statList get", port) == self.ReturnCodes.SUCCESS
    
    def getStatValueForPort(self,port, stat):
        if not stat.startswith('-'): 
            stat = '-%s'%stat
        return self.execute("statList cget", stat)

    def portHasLocalCPU(self,port):
        return self.execute("port isValidFeature", port, "portFeatureLocalCPU") == self.ReturnCodes.TRUE

    def getEntireTopology(self, chassis):
        id = int(self.getChassisId(chassis))
        ports = self.getPortListFromChassis(chassis)
        cards = {x.split()[1]:"" for x in ports}.keys()
        topology = {}
        topology["chassis"] = {}
        topology["chassis"][id]= { "id": "%s"%id, "cards":  {int(x) : { "ports": {} } for x in cards} }
        for prop in ["name","typeName","ixServerVersion","maxCardCount","serialNumber"]:
            topology["chassis"][id][prop] = self.execute("chassis","cget","-%s"%prop)
        for card in cards:
            self.execute("card","get %s"%id, card)
            topology["chassis"][id]["cards"][int(card)]["id"] = "%s"%card
            for prop in ["activeCapturePortList", "activePortList", "speedModeList", "fpgaVersion", "hwVersion", "portCount", "typeName", "serialNumber", "appsId",  "operationMode"]:
                topology["chassis"][id]["cards"][int(card)][prop]= self.execute("card","cget","-%s"%prop)
        for port in ports:
            cardId = int(port.split()[1])
            portId = int(port.split()[2])
            self.execute("port","get", port)
            topology["chassis"][id]["cards"][cardId]["ports"][portId] = { "id": "%s"%portId}
            for prop in ["speed", "owner", "typeName", "linkState",  "portState"]:
                topology["chassis"][id]["cards"][cardId]["ports"][portId][prop]= self.execute("port","cget","-%s"%prop)
        return topology
    
    def login(self, username):
        return self.execute("ixLogin",username) == self.ReturnCodes.SUCCESS

    def logout(self):
        return self.execute("ixLogout") == self.ReturnCodes.SUCCESS

    def clearOwnershipOfPorts(self, portList, forcefully=False):
        takeType = "force" if forcefully else "notForce"
        if not isinstance(portList,list):  
            raise SyntaxError("Expected portList to be a python list of ports")
        tclPortList = "{ %s }"% self.convertToTclList(portList)
        return self.execute("ixClearOwnership", tclPortList, takeType) == self.ReturnCodes.SUCCESS

    def takeOwnershipOfPorts(self, portList, forcefully=False):
        takeType = "force" if forcefully else "notForce"
        if not isinstance(portList,list):  
            raise SyntaxError("Expected portList to be a python list of ports")
        tclPortList = "{ %s }"% self.convertToTclList(portList)
        return self.execute("ixTakeOwnership", tclPortList, takeType) == self.ReturnCodes.SUCCESS

    def execute(self, func_name, *args):
       """ execute a low level ixTclHal command
           Synopsis:
               execute ixConnectToTclServer 127.0.0.1
               execute ixConnectToChassis 127.0.0.1
               execute ixCreatePortListWildCard { { 0 * * } }
           Args:
           Returns:
               the string value returned by the low level API in Tcl
       """
       return self.__eval("%s %s"%(func_name, ' '.join(args)))
     

    
    