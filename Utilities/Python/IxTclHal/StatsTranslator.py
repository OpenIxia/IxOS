class StatsTranslator:
   
    class portCpuStatus:
        __id__ ="id"
        __value__ = "value"
        __description__ = "description"

        __portCpuStatusTranslator__ = {
            "0":  { __id__: "0", __value__: "statCpuNotPresent",         __description__: "No CPU is present on this port." } ,
            "1":  { __id__: "1", __value__: "statCpuNotReady" ,          __description__: "The CPU is not ready." } ,
            "2":  { __id__: "2", __value__: "statCpuReady" ,             __description__: "The CPU is ready." } ,
            "3":  { __id__: "3", __value__: "statCpuErrorOsHalt" ,       __description__: "The CPU has encountered an OS error and has halted." } ,
            "4":  { __id__: "4", __value__: "statCpuErrorMemTestFailed", __description__: "The CPU encountered an error during memory tested and has halted." } ,
            "5":  { __id__: "5", __value__: "statCpuErrorBootFailed" ,   __description__: "The CPU failed to completely boot." } ,
            "6":  { __id__: "6", __value__: "statCpuErrorNotResponding", __description__: "The CPU is not responding." } }

        @classmethod
        def getDescriptionFromId(self,x):
            return self.__portCpuStatusTranslator__[x][self.__description__]
        
        @classmethod
        def getValueFromId(self,x):
            return self.__portCpuStatusTranslator__[x][self.__value__]

        @classmethod
        def isError(self,x):
            return int(x)>2

        @classmethod
        def isReady(self,x):
            return x == "0" or x == "2"


        