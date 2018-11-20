import sys
import re
import time
from pprint import pprint
from IxTclHal.IxTclHal import IxTclHal
from IxTclHal.StatsTranslator import StatsTranslator


chassis = "10.38.162.139"
tclServer = chassis

ixTclHal = IxTclHal(tclServer,r"C:\Program Files (x86)\Ixia\IxOS\8.50-EA\TclScripts\lib")
#ixTclHal.Debug.Enable()
pprint(ixTclHal.connectToChassis(chassis))

#ixTclHal.Debug.Disable()
portList = ixTclHal.getPortListFromChassis(chassis)

ixTclHal.checkLinkStateForPortsList(portList)
topology= ixTclHal.getEntireTopology(chassis)
pprint(topology)
for port in portList:
    if ixTclHal.portHasLocalCPU(port):
        ixTclHal.getStatsForPort(port)
        result = ixTclHal.getStatValueForPort(port,"portCpuStatus")
        if StatsTranslator.portCpuStatus.isError(result):
            print("CPU error (%s) found on port %s"%(StatsTranslator.portCpuStatus.getDescriptionFromId(result) ,port))
            #ixTclHal.rebootPortCpu(port)
            #ixTclHal.resetPort(port)
            #ixTclHal.setPortFactoryDefaults(port)
            #ixTclHal.resetHardwareCard(chassis,2)
            #ixTclHal.forceHotswapCard(chassis, 2)
            time.sleep(1)
            result = ixTclHal.getStatValueForPort(port,"portCpuStatus")
        ixTclHal.execute("portCpu","get", port)
        mem = ixTclHal.execute("portCpu","cget", "-memory")
        print ("Chassis %s Card %s Port %s has %s MB of memory.%s" % (chassis, port.split()[1] , port.split()[2], mem, StatsTranslator.portCpuStatus.getDescriptionFromId(result)))
ixTclHal.disconnectFromChassis(chassis)

        



