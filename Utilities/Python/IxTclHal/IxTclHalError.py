#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, division

class IxTclHalError(RuntimeError):
	TKINTER_ERROR = 0
	TCL_NOT_FOUND = 1
	IXTCLHAL_API_NOT_FOUND = 2
	IXTCLHAL_VERSION_NOT_FOUND = 3
	CANNOT_CONNECT_TO_TCLSERVER=4
	CANNOT_CONNECT_TO_CHASSIS=5
	TCL_COMMAND_FAIL = 6
	CANNOT_FIND_TCLHAL_DLL = 7
	CANNOT_LOAD_TCLHAL_DLL = 8
	

	__error_texts = {
		TKINTER_ERROR: 'Tkinter module could not be loaded',
		TCL_NOT_FOUND: 'No compatible TCL interpretor found',
		IXTCLHAL_API_NOT_FOUND: 'No ixTclHal libraries found',
        IXTCLHAL_VERSION_NOT_FOUND: 'No ixTclHal version found.',
        CANNOT_CONNECT_TO_TCLSERVER: 'Cannot connect to Ixia Tcl Server.',
        CANNOT_CONNECT_TO_CHASSIS: 'Cannot connect to Ixia Chassis.',
		TCL_COMMAND_FAIL: 'Command execution failed.',
		CANNOT_FIND_TCLHAL_DLL : 'Failed to find IxTclHal.dll. Please make sure you have IxOS TCL library installed.',
		CANNOT_LOAD_TCLHAL_DLL : 'Failed to load IxTclHal.dll. IxOS IxTclHal.dll is required for Windows OS. Please make sure you are using same python arhitecture (32/64bit) as the installed Tcl library.',
	}

	def __init__(self, msgid, additional_info=''):
		if msgid not in self.__error_texts.keys():
			raise ValueError('message id is incorrect')

		self.msgid = msgid
		self.message = self.__error_texts[msgid]
		if additional_info:
			self.message += '\nAdditional error info:\n' + additional_info

		super(self.__class__, self).__init__(self.message)
