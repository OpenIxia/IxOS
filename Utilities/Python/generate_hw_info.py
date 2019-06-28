"""

Description
-----------
This file implements code for collecting information of all the Ixia
Load Modules installed in the Ixia Chassis identified by a list of
IP addresses provided by the user. It also fetches information for
licenses installed across all discovered chassis.

Prerequisites
-------------
For successful execution following should apply:
1)	Tcl Server and IxServer must be up and running on all intended chassis
2) 	Make sure following is installed:
    a. python 2.7 / python 3.4

Usage
-----
Edit following parameters in the script:
1) 	IP_LIST -> Should be a list containing at least one valid chassis
    IP or an Subnet IP (in CIDR notation)
    e.g. ['10.216.100.56', '10.216.100.217/27']
2)  COLLECT_LICENSES_INFO -> Should be set to True if licenses for each
    chassis needs to be collected as well

Save this script to a location which has adequate read/write/execute
permission for current user. Open up terminal and change present
working directory to the location where script is saved. Then do,

    python generate_hw_info.py

Expected Result
---------------
As an end result, following files should be created in current directory:
1)	hw_info_<date>.csv -> This file will contain the information for all
	the discovered Chassis/Load Modules/Licenses (And failures if any).
	e.g. hw_info_2016Oct06-203741.csv
2) .ixtemp -> Temporary directory used by the script to store intermediate
	state information. This is deleted by default unless ::cleanupTempDirs
	is set to false

Limitations
-----------
1) 	As of now there's no provision to collect information from slave chassis
	connected in chassis chain configuration.

License
-------
Copyright (c) 2017 Ixia Communications

Author: Vijay Murphy
"""

import os
import datetime
import re
import sys
import telnetlib
import ftplib
import socket
import logging
import subprocess
import multiprocessing


# ---------- PERMITTED CONFIGURATION STARTS HERE ---------- #

IP_LIST = [
    # '10.216.100.56/24',
    # '10.216.100.58',
    # '10.216.100.66',
    # '10.216.100.238',
    # '10.216.100.56',
    '10.39.36.189',
    ]

DEFAULT_TIMEOUT = 60
MAX_PROCESSES = 20
CLEANUP_TEMPDIR = True
LOG_LEVEL = logging.DEBUG

# Assign False against column names that should not appear in csv
INCLUDE_COLUMNS = [
    ('InfoType', True),
    ('ChassisIp', True),
    ('IsChassis', True),
    ('ChassisTypeName', True),
    ('ChassisOs', True),
    ('ChassisSn', True),
    ('IxOSBuild', True),
    ('SlotId', True),
    ('CardTypeName', True),
    ('CardSn', True),
    ('PortCount', True),
    ('LicenseType', True),
    ('LicenseActivationId', True),
    ('LicenseRegId', True),
    ('LicenseProduct', True),
    ('LicenseQuantity', True),
    ('LicensePartNumber', True),
    ('LicenseDescription', True),
    ('LicenseRegNum', True),
    ('LicensePass', True),
    ('LicenseLicId', True),
    ('LicenseMaintenanceEndDate', True),
    ('Failure', True)
]

# ---------- PERMITTED CONFIGURATION ENDS HERE ---------- #


log = None
_log = None


class Resources(object):
    """
    static class for providing/managing resources used by other classes
    """

    CHASSIS_INFO_SCRIPT = """
        set ::columns [list ChassisIp ChassisTypeName ChassisOs ChassisSn IxOSBuild SlotId CardTypeName CardSn PortCount Failure]

        proc isUnix { } {
            # return true if on a unix platform

            if {$::tcl_platform(platform) == "unix"} {
                return 1
            } else {
                return 0
            }
        }

        proc importPackage { } {
            if { [isUnix] } {
                source /opt/ixia/ixos/current/IxiaWish.tcl
            }
            package require IxTclHal
        }

        proc getPass { } {
            set pass NA
            catch {
                package req registry
                set pass [registry get {HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon} DefaultPassword]
            }
            return $pass
        }

        proc getAllActiveCards { chassisId {maxPossibleCards 12} } {
            # return cards which does not return failure during get card operation
            set activeCards [list]

            for {set cardId 1} { $cardId <= $maxPossibleCards } { incr cardId } {
                if { ![card get $chassisId $cardId] } {
                    lappend activeCards [list $chassisId $cardId]
                }
            }
            return $activeCards
        }

        proc listArrayValues { arrayItem keys } {
            # return array values as list
            upvar $arrayItem arrayVar
            set values [list]
            foreach key $keys {
                lappend values $arrayVar($key)
            }
            return $values
        }

        proc printFormattedOutput { rows } {
            set h1 "<data"
            set h2 "start>"
            set pre "$h1$h2"
            set p1 "<data"
            set p2 "end>"
            set post "$p1$p2"
            set rowDelim "**"
            set columnDelim "||"

            set rows2 [list]
            foreach row $rows {
                lappend rows2 [join $row $columnDelim]
            }
            set output [join $rows2 $rowDelim]
            puts "$pre$output$post"
        }

        proc collectInfoFromChassis { {chassisIp localhost} } {
            # try with best efforts to connect to chassis and generate a csv output
            # from collected information

            # create an array and update the existing instance
            # for each row
            array set row {}
            foreach column $::columns {
                set row($column) NA
            }

            set rows [list]
            set row(ChassisIp) $chassisIp

            if { [catch {

                if { [catch { importPackage } result] } {
                    error "error importing IxTclHal"
                }

                # probably too many catches, but keeps us from breaking out
                set chassisConnect 0
                if { [catch { set chassisConnect [ixConnectToChassis $chassisIp] } result] } {
                    if { [regexp "Invalid Method for TCLChassisChain" $result] } {
                    } else {
                        error "Could not connect to IxServer"
                    }
                } else {
                    if { $chassisConnect } {
                        if { $chassisConnect == 2 } {
                            error "IxOS version mismatch"
                        } else {
                            error "Could not connect to IxServer"
                        }
                    }
                }

                if { [catch { set chassisId [ixGetChassisID $chassisIp] } result] } {
                    set chassisId 1
                }
                if { [chassis get $chassisId] } {
                    error "error retreiving chassis $chassisId"
                } else {
                    catch { set row(ChassisTypeName) [chassis cget -typeName] }

                    if { [regexp -nocase "Demo" $row(ChassisTypeName)] } {
                        error "Skipped since it is runnin Demo Server"
                    }
                    if { [regexp -nocase "Optixia XV" $row(ChassisTypeName)] } {
                        error "Skipped since it is a VM Chassis"
                    }
                    catch { set row(ChassisSn) [chassis cget -serialNumber] }
                    catch {
                        if { [lsearch -nocase [list NA unknown] "$row(ChassisSn)"] >= 0  } {
                            set row(ChassisSn) "pw: [getPass]"
                        }
                    }
                    catch { set row(IxOSBuild) [chassis cget -ixServerVersion] }
                    catch { set os [chassis cget -operatingSystem] }
                    switch -- $os { 5 { set row(ChassisOs) Linux } 4 { set row(ChassisOs) WindowsXP } 7 { set row(ChassisOs) Windows7 } default { set row(ChassisOs) NA } }
                }
                if { [catch { set maxCards [chassis cget -maxCardCount] } result] } {
                    set maxCards 16
                }
                set activeCards [getAllActiveCards $chassisId $maxCards]
                foreach activeCard $activeCards {
                    set row(SlotId) [lindex $activeCard 1]
                    set row(Failure) NA
                    if { [card get {*}$activeCard] } {
                        set row(Failure) "error retreiving card $chassisId"
                        lappend rows [listArrayValues row $::columns]
                    } else {
                        catch { set row(CardTypeName) [card cget -typeName] }
                        catch { set row(CardSn) [lindex [card cget -serialNumber] 3] }
                        catch { set row(PortCount) [card cget -portCount] }
                        lappend rows [listArrayValues row $::columns]
                    }
                }

            } result] } {
                set row(Failure) $result
            }
            catch { ixDisconnectFromChassis $chassisIp }

            if { [llength $rows] == 0 } {
                lappend rows [listArrayValues row $::columns]
            }
            printFormattedOutput $rows
        }


        collectInfoFromChassis %s

    """

    LIC_COPY_SCRIPT = """
        set src /opt/ixia/LicenseServerPlus/licenses;
        set dest /ftp/virtual/ixia/.ixlic;

        catch { file delete -force -- $dest }
        catch { file mkdir $dest}

        set licenses [glob -nocomplain $src/*.lic]
        foreach license $licenses {
            file copy -force $license $dest
        }
        set firstHalf "<lic"
        set secondHalf "copied>"
        puts "$firstHalf$secondHalf"
    """

    SSH_KEY = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEArg1XaU0bSxtReZX+94/SNa+RHtmnpspW/acA7wi6FjSddYjF
        3soPUagZYCbwuFe7dlM8MN3Fy6uclIkJ1/MCki6Uv0d4wEzP6DJSn7hWb0GaiNMu
        YbDKv4imB6jHovV7iYxNgNzZTOkUaiW+JbXzM6/bQ+3cqn1bOdyBJzcJKbA3+Bz1
        oLvIKPYHzrGL4ELh4gYQH2YffqCifoKnUhZwvCDIBJ0QP39yZVdr6dLivl8I4vUq
        hBWQSZ02/7qLc168+Lf6+1aIB/2yhvvO6m8i/8Vk405jSuVuDFeF245BYGnU8H7+
        ZR/3HwwqUoNJz3lDIZs4/CElGPnKjg8D0TtAqwIDAQABAoIBAFVTNQbqRfcL7WUt
        o1C5sNOgvgPhr86UYxD2Tf7gyFkachasdlRBukDNp6L7dAbq+3uGUnuiPNUbzCcF
        B05WU2xWaZVb9FZRUZsDEH48YCMqhheNb690e/BpjPs0Qqogre9AWL5ThjOuD9P5
        rL3P9OnhzBwA/6yUx6QV9TrEQDmu2misAvnn9EzcGZacARief7DH3UnFbmHjFRsx
        eZ9ZZ3FI4smp0EzQyO+DMuom7Ry7Uz/ihXY9v95Q0YEzEg7PMDWHASr7hbBGNoAg
        VUsN4cLYdRUeBqkHP7LINnHMeNiVp5N58ao2PL9s4sJNxsB/bQE7kqB3mMWKjmVM
        Eagi7AECgYEA4FIs5NNPg6swPKlz+NKOLaEBxT7ee8rGGAEjJaW70Sf8wJq/w864
        mOcbOxuOlIoorRyXLXdmLmfvCCVhU7/novZj5TK9gUzOmxSNzZm1nlIRi67Rp0+T
        g4467ucS53cDn2VwCnwUvrezb8xgqj9gHuuohx7vmVyH7fYVyF0i7hcCgYEAxqHO
        kge57Ft5gMwUlrbCyg99jQgHs7U+kJ986xnYBPm/aCh9OB3mSzY76pRvd3tI2D5K
        DrNqndVO8wtEqm1V9kY5IZ/TyzoRtwOWHw6o16sy5JIq61oPzn4Mc9DC6nHz+g9h
        hn2iXjkeUh23daHlyGmkAK83NZNd0Hu3Am6Tko0CgYEAzuN7fGBYCbwtdQVkbKzl
        bLf+hgkB8XKHWURTQjmlC7axqoIPM2zJXFxqBQ3ZZq417dNcqxZgK5S4JO804KUx
        4l8UqyMtHL/WHbnLP0Dw/N/8RrQpsQH3r3HScNy11r0xniVUPJdMGsoauJXq4Zop
        8NqwSE8D9JIe3B4G4RDlUmkCgYBNjZeNxJ5+/igudYAEaE8dfXbTvbLkI3vOE7c+
        Q9Tn/GsTS9u4MVRdQUubh2EOEYCbjZZ0rvCNt18f3eJteEr74OcljbWvv3hzMF9I
        uPyLWDiCrd88DOnnAafzACtaRiuwEplNXXgrublw7lFXCGMjILv72G2B6YvTfrox
        pOLRcQKBgQCcT9p4KgNxWU/LCj4/0J/N/czFCE2ovnVgIbLtp5vczouYuFYugbSp
        iLrTJ8+P7Ddn2IPL4u8Ddcusmd9mD/PrPP55yHlqyBjOzEMrLvRDufZy3kKP1JXP
        dm8rTnH8ypSxuhl51KLJptzmzq4VCs36NT2JAh+0BAsgBDfvVDqsQg==
        -----END RSA PRIVATE KEY-----
    """

    @staticmethod
    def get_clean_info_dict():
        """
        create dict from INCLUDE_COLUMNS; init all fields to NA
        """
        try:
            info_dict = {}
            for column in INCLUDE_COLUMNS:
                info_dict[column[0]] = 'NA'
            return info_dict
        except:
            log.warning('Exception occured in get_clean_info_dict')
            return info_dict

    @staticmethod
    def get_minified_script(ip):
        """
        convert a multi-line tcl code into one-liner
        DISCLAIMER: works only for tcl code available in this file
        """
        try:
            script = Resources.CHASSIS_INFO_SCRIPT % ip
            # remove comments
            script = re.sub(r'#.*', '', script)
            # append semicolon; leave out lines ending with '{'
            script = re.sub(r'([^{])\n', r'\1;', script)
            # remove newlines
            script = re.sub(r'\n', '', script)
            return script
        except:
            raise

    @staticmethod
    def create_sshkey(log_dir):
        """
        create ssh key
        """
        try:
            key_parts = Resources.SSH_KEY.strip().splitlines()
            sshkey = os.path.join(log_dir, 'ixtclkey')
            with open(sshkey, "w+") as handle:
                for part in key_parts:
                    handle.write(part.strip() + '\n')
            os.chmod(sshkey, 0o600)
        except:
            raise

    @staticmethod
    def create_log_dir():
        """
        creates a log dir inside .ixtmp dir
        """
        try:
            ixtmp = '.ixtmp'
            if not os.path.exists(ixtmp):
                os.makedirs(ixtmp)
            log_dir = os.path.join(ixtmp,
                                   datetime.datetime.now().strftime('hw-info-%Y%b%d-%H%M%S'))
            os.makedirs(log_dir)
            return log_dir
        except:
            raise

    @staticmethod
    def cleanup_temp_dir():
        """
        remove .ixtmp recursively
        """
        try:
            import shutil
            shutil.rmtree('.ixtmp', ignore_errors=True)
        except:
            raise

    @staticmethod
    def get_included_columns():
        """
        get columns to be printed in order
        """
        try:
            columns = []
            for item in INCLUDE_COLUMNS:
                if item[1]:
                    columns.append(item[0])
            return columns
        except:
            raise

    @staticmethod
    def get_ips_from_cidr(cidr):
        """
        extract list of ip addresses from a CIDR entry
        """
        try:
            ip_list = []
            parts = re.split(r'\.|/', cidr)
            parts = [int(x) for x in parts]

            # validate IP octets, ignore subnet mask for now
            for part in parts:
                if part > 255 or part < 0:
                    _log.error('%s is not a valid cidr entry', cidr)
                    return []

            if len(parts) == 4:
                return [cidr]
            elif len(parts) == 5:
                # validate subnet mask
                if parts[4] > 32 or parts[4] < 1:
                    _log.error('%s is not a valid cidr entry', cidr)
                    return []
            else:
                _log.error('%s is not a valid cidr entry', cidr)
                return []

            # change ip to a decimal number
            ipnum = (parts[0] * pow(2, 24)) + \
                    (parts[1] * pow(2, 16)) + \
                    (parts[2] * pow(2, 8)) + \
                     parts[3]

            # find network address
            ipstart = int(ipnum / pow(2, 32 - parts[4])) * pow(2, 32 - parts[4])
            # find broadcast address
            ipend_plus1 = ipstart + pow(2, 32 - parts[4])

            # change list of decimal IPs to decimal dotted notation
            for decimal_ip in range(ipstart, ipend_plus1):
                oct4 = decimal_ip
                oct1 = int(oct4 / pow(2, 24))
                oct4 %= pow(2, 24)
                oct2 = int(oct4 / pow(2, 16))
                oct4 %= pow(2, 16)
                oct3 = int(oct4 / pow(2, 8))
                oct4 %= pow(2, 8)

                ip_list.append('%d.%d.%d.%d' % (oct1, oct2, oct3, oct4))

            return ip_list
        except Exception as error:
            _log.error('Something went wrong while parsing CIDR %s : %s', cidr, str(error))
            return []

    @staticmethod
    def get_list_of_ips():
        """
        get list of IP addresses from IP_LIST
        """
        try:
            list_of_ips = []
            for item in IP_LIST:
                list_of_ips += Resources.get_ips_from_cidr(item)
            return list_of_ips
        except:
            return list_of_ips

    @staticmethod
    def setup_logger(logger_name, log_dir):
        """
        setup main and multiprocess level logger
        """
        global log
        global _log

        _log = logging.getLogger('main')
        _log.propagate = False
        if len(_log.handlers) < 1:
            # log to file
            _log.setLevel(LOG_LEVEL)
            logfile = os.path.join(log_dir, 'main.log')
            handler = logging.FileHandler(logfile)
            handler.setFormatter(logging.Formatter('[%(asctime)s]%(levelname)8s:\t\t%(message)s'))
            _log.addHandler(handler)
        if 0 < len(_log.handlers) < 2:
            # log limited info to console
            _log.setLevel(LOG_LEVEL)
            stream_handler = logging.StreamHandler(sys.stdout)
            stream_handler.setFormatter(logging.Formatter('%(message)s'))
            _log.addHandler(stream_handler)

        if logger_name == 'main':
            log = _log
        else:
            log = logging.getLogger(logger_name)
            log.propagate = False
            log.setLevel(LOG_LEVEL)
            logfile = os.path.join(log_dir, '%s.log' % logger_name)
            handler = logging.FileHandler(logfile)
            handler.setFormatter(logging.Formatter('[%(asctime)s]%(levelname)8s\t\t%(message)s'))
            log.addHandler(handler)
    
    @staticmethod
    def close_logger(logger_name):
        try:
            for handler in logger_name.handlers:
                handler.close()
                logger_name.removeHandler(handler)
        except:
            pass


class IxConnection(object):
    """
    class for managing telnet/ssh/ftp connections with chassis
    """
    def __init__(self, ip, log_dir, is_chassis=True):
        self.ip = ip
        self.timeout = DEFAULT_TIMEOUT
        self.console = None
        self.ssh = None
        self.ftp = None
        self.log_dir = log_dir
        self.info_dict = Resources.get_clean_info_dict()
        self.info_dict['ChassisIp'] = self.ip
        self.info_dict['IsChassis'] = str(is_chassis)

    def can_connect_ixproxy(self, ixproxy_port=1080):
        """
        try to create socksv4 connection with ixproxy
        and return true if successful
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60)
            sock.connect((self.ip, ixproxy_port))
            request = bytearray()
            request.append(0x80)
            request.append(0x01)
            sock.send(request)
            expected_bytearray = bytearray()
            expected_bytearray.append(0x80)
            expected_bytearray.append(0xa1)
            expected_bytearray.append(0x00)
            received_bytearray = sock.recv(2048)
            if expected_bytearray == received_bytearray:
                return True
            else:
                return False
        except Exception:
            return False
        finally:
            sock.close()

    def windows_telnet_connect(self):
        """
        initiate telnet connection with chassis
        """
        try:
            log.debug('Initiating telnet connection with %s', self.ip)
            self.console = telnetlib.Telnet(self.ip)
            log.debug('Successfully created telnet connection with %s', self.ip)
            return True
        except:
            log.warning('failed creating telnet connection')
            return False

    def get_script_output_from_telnet(self, script, wait_for=''):
        """
        write one-line script to telnet connection and return the output
        """
        try:
            self.console.write(script.encode('ascii') + b'\r')
            output = self.console.read_until(wait_for.encode('ascii'), self.timeout)
            if wait_for in str(output):
                return str(output)
            else:
                raise Exception()
        except:
            self.info_dict['Failure'] = 'could not retreive info from windows chassis'
            log.error(self.info_dict['Failure'])
            return None

    def ftp_connect(self, user='anonymous', password='anonymous'):
        """
        initiate ftp connection with chassis
        """
        try:
            log.debug('Creating ftp connection with %s', self.ip)
            self.ftp = ftplib.FTP(self.ip, user=user, passwd=password)
            self.ftp.connect()
            self.ftp.login(user, password)
            log.debug('Succesfully created ftp connection with %s', self.ip)
            return True
        except:
            log.warning('failed creating ftp connection')
            return False

    def native_ixos_ssh_connect(self):
        """
        initiate ssh connection with chassis
        """
        try:
            log.debug('Initiating ssh connection with %s', self.ip)
            sshkey = os.path.join(self.log_dir, 'ixtclkey')
            port = 8022
            user = "ixtcl"
            command = [
                b"ssh",
                b"-o", b"UserKnownHostsFile=/dev/null",
                b"-o", b"StrictHostKeyChecking=no",
                b"-p", b"%d" % port,
                b"-i", b"%s" % sshkey,
                b"-tt",
                b"%s@%s" % (user, self.ip)
            ]

            # linux specific
            self.ssh = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE,
                                        stdin=subprocess.PIPE, stderr=subprocess.STDOUT)

            # stdout.read() is blocking;
            # os level hack needed to make this particular stdout for
            # ssh connection non-blocking
            # linux specific
            from fcntl import fcntl, F_GETFL, F_SETFL
            flags = fcntl(self.ssh.stdout, F_GETFL)
            fcntl(self.ssh.stdout, F_SETFL, flags | os.O_NONBLOCK)

            import time
            time.sleep(2)
            ssh_failed = False
            try:
                login_stdout = str(self.ssh.stdout.read())
                log.debug('login stdout: %s', login_stdout)
                if 'Connection refused' in login_stdout:
                    ssh_failed = True
            except:
                pass
            if ssh_failed:
                raise Exception()
            log.debug('Successfully created ssh connection with %s', self.ip)
            return True
        except:
            log.warning('failed creating ssh connection')
            return False

    def get_script_output_from_ssh(self, script, wait_for=''):
        """
        split command into several lines; send them to ssh connection
        return the output
        """
        try:
            script_parts = script.split(';')
            # need to split the one-line script to several lines
            # as tty on some OS can only accept max 1024 chars;
            # ixtcl console on native-ixos chassis is capable of multiline
            # commands unlike tcl server console on windows chassis
            for part in script_parts:
                self.ssh.stdin.write((part + ';').encode('ascii') + b'\r')
            output = ''

            # keep reading until timeout occurs or we get intended string
            when_started = datetime.datetime.now()
            while  (when_started + datetime.timedelta(seconds=self.timeout)
                    > datetime.datetime.now()):
                try:
                    output += str(self.ssh.stdout.read())
                    if wait_for in output:
                        break
                except:
                    # read() will behave in non-blocing way since we just
                    # modified some flags in native_ixos_connect method; thus
                    # it raises exception if we don't see anything in stdout
                    pass

            if wait_for in str(output):
                return str(output)
            else:
                raise Exception()
            return output
        except:
            self.info_dict['Failure'] = 'could not retreive info from native-ixos chassis'
            log.error(self.info_dict['Failure'])
            return None

class IxChassisInfo(IxConnection):
    """
    class for managing chassis topology retrieval from windows/native-ixos chassis
    """

    def __init__(self, ip, log_dir, is_chassis=True):
        IxConnection.__init__(self, ip, log_dir, is_chassis)
        self.info_dict['InfoType'] = 'ChassisInfo'

    def __del__(self):
        try:
            self.ssh.terminate()
        except:
            pass

    def run(self):
        """
        connect to chassis and parse the output; return the info_dict
        """
        try:
            info_script = Resources.get_minified_script(self.ip)

            if self.windows_telnet_connect():
                log.debug('%s is most probably a windows chassis', self.ip)
                output = self.get_script_output_from_telnet(info_script, '<dataend>')
                if output is None:
                    return [self.info_dict]
            elif self.native_ixos_ssh_connect():
                log.debug('%s is most probably a native ixos chassis', self.ip)
                output = self.get_script_output_from_ssh(info_script, '<dataend>')
                if output is None:
                    return [self.info_dict]
            else:
                self.info_dict['Failure'] = "could not create connection with %s" % self.ip
                log.error(self.info_dict['Failure'])
                return [self.info_dict]

            log.debug('Successfully retrieved output')

            return self.get_parsed_chassis_info(output)
        except:
            raise

    def get_parsed_chassis_info(self, output):
        """
        parse the output where rows are separated by '**'
        and columns are separated by '||'
        """
        try:
            log.debug('Parsing output ...')
            info_dicts = []
            # this is the order in which info is retrieved from chassis
            keys = ['ChassisIp', 'ChassisTypeName', 'ChassisOs', 'ChassisSn', 'IxOSBuild', 'SlotId',
                    'CardTypeName', 'CardSn', 'PortCount', 'Failure']

            splits = re.split(r'<datastart>', output)
            another_splits = re.split(r'<dataend>', splits[1])
            rows = re.split(r'\*\*', another_splits[0])

            for row in rows:
                columns = re.split(r'\|\|', row)
                # deep copy not needed for now
                new_column = self.info_dict.copy()
                for i in range(0, len(keys)):
                    new_column[keys[i]] = columns[i]
                info_dicts.append(new_column)

            if len(info_dicts) == 0:
                self.info_dict['Failure'] = 'No info retrieved from chassis'
                log.error(self.info_dict['Failure'])
                return [self.info_dict]
            else:
                return info_dicts
        except:
            self.info_dict['Failure'] = 'Error parsing results from chassis'
            log.error(self.info_dict['Failure'])
            return [self.info_dict]


class IxLicenseInfo(IxConnection):
    """
    class for managing lincense retrieval from windows/native-ixos chassis
    """

    def __init__(self, ip, log_dir, is_chassis=True):
        IxConnection.__init__(self, ip, log_dir, is_chassis)
        self.info_dict['InfoType'] = 'LicenseInfo'
        self.lic_dir = os.path.join(log_dir, "%s-lic" % ip)

    def __del__(self):
        try:
            self.ssh.terminate()
        except:
            pass

    def run(self):
        """
        download and parse lic files from chassis; return the info_dict
        """
        try:
            if self.ftp_connect():
                output = self.get_lic_from_windows_chassis()
                if output is None:
                    return [self.info_dict]
            elif self.ftp_connect('admin', 'admin') and self.native_ixos_ssh_connect():
                # doing this so that we can download licenses from ftp location
                # scp doesn't work with ixtcl user as it hangs due to modified bashrc on chassis
                log.debug('Copying lic files from license dir to ftp location')
                console_output = self.get_script_output_from_ssh(Resources.LIC_COPY_SCRIPT,
                                                                 '<liccopied>')
                if console_output is None:
                    return [self.info_dict]
                output = self.get_lic_from_native_ixos_chassis()
                if output is None:
                    return [self.info_dict]
                log.debug('Removing copied licenses from ftp location')
                self.get_script_output_from_ssh(
                    'catch { file delete -force -- /ftp/virtual/ixia/.ixlic }'
                    )
            else:
                self.info_dict['Failure'] = "could not create connection with %s" % self.ip
                log.error(self.info_dict['Failure'])
                return [self.info_dict]

            log.debug('Successfully downloaded licenses')
            return self.get_parsed_licenses(self.info_dict['LicenseType'])

        except:
            raise

    def get_parsed_licenses(self, lic_type):
        """
        parse downloaded license files depending on whether they're IRU/ILU
        """
        try:
            lic_files = os.listdir(self.lic_dir)
            log.debug('Parsing output ...')
            info_dicts = []

            # loop should be one iteration long for ILU
            for lic_file in lic_files:
                # this should happen only once in case of ILU
                new_column = self.info_dict.copy()
                with open(os.path.join(self.lic_dir, lic_file), 'r') as licfd:
                    content_lines = licfd.read().splitlines()
                    for line in content_lines:
                        if line.startswith('#REGID=') and not line.startswith('#REGID=obsolete'):
                            new_column['LicenseRegId'] = line.split('=')[-1].strip()
                        if line.startswith('#LICID='):
                            new_column['LicenseLicId'] = line.split('=')[-1].strip()
                        if line.startswith('#MAINTENANCE_END_DATE='):
                            new_column['LicenseMaintenanceEndDate'] = line.split('=')[-1].strip()
                        if lic_type == 'IRU':
                            if line.startswith('#REGNUM='):
                                new_column['LicenseRegNum'] = line.split('=')[-1].strip()
                            if line.startswith('#PASS='):
                                new_column['LicensePass'] = line.split('=')[-1].strip()
                            if line.startswith('#PRODUCT'):
                                new_column['LicenseProduct'] = line.split('=')[-1].strip()
                            if line.startswith('#FEATURE='):
                                try:
                                    new_feature_column = new_column.copy()
                                    features = line.split('=')[-1].strip().split('|')
                                    new_feature_column['LicensePartNumber'] = features[0]
                                    new_feature_column['LicenseDescription'] = features[1]
                                    new_feature_column['LicenseQuantity'] = features[3]
                                except:
                                    new_feature_column['Failure'] = 'error parsing license features'
                                    log.warning(new_feature_column['Failure'])
                                finally:
                                    info_dicts.append(new_feature_column)

                        else:
                            if line.startswith("#PARTNUMBER="):
                                try:
                                    new_feature_column = new_column.copy()
                                    parts = line.split('=')[-1].strip().split('|')
                                    new_feature_column['LicenseProduct'] = parts[1]
                                    new_feature_column['LicenseMaintenanceEndDate'] = parts[3]
                                    new_feature_column['LicenseActivationId'] = parts[5]
                                    new_feature_column['LicenseQuantity'] = parts[6]
                                    new_feature_column['LicensePartNumber'] = parts[8]
                                    new_feature_column['LicenseDescription'] = parts[9]
                                except:
                                    new_feature_column['Failure'] = 'error parsing license parts'
                                    log.warning(new_feature_column['Failure'])
                                finally:
                                    info_dicts.append(new_feature_column)

            if len(info_dicts) == 0:
                self.info_dict['Failure'] = 'No licenses retrieved from chassis'
                log.error(self.info_dict['Failure'])
                return [self.info_dict]
            else:
                return info_dicts
        except:
            self.info_dict['Failure'] = 'Error parsing licenses from chassis'
            log.error(self.info_dict['Failure'])
            return [self.info_dict]

    def get_lic_from_windows_chassis(self):
        """
        download licenses from windows chassis
        """
        try:
            os.makedirs(self.lic_dir)
            # order is important here
            # it is possible to have both IRU and ILU installed on same chassis;
            # we should check for ILU first
            possible_paths = [
                '/Program Files/Ixia/LicenseServerPlus/licenses',
                '/Program Files (x86)/Ixia/LicenseServerPlus/licenses',
                '/Program Files/Ixia/licensing/licenses',
                '/Program Files (x86)/Ixia/licensing/licenses'
            ]

            actual_lic_dir = None
            for lic_path in possible_paths:
                try:
                    log.debug('changing dir to %s', lic_path)
                    self.ftp.cwd(lic_path)
                    actual_lic_dir = lic_path
                    log.debug('successfully changed dir to %s', lic_path)
                    break
                except:
                    log.warning('changing dir to %s failed', lic_path)

            if actual_lic_dir is None:
                self.info_dict['Failure'] = 'lic dir does not exist on %s' % self.ip
                log.error(self.info_dict['Failure'])
                return None

            if 'licensing' in actual_lic_dir:
                self.info_dict['LicenseType'] = 'IRU'
            else:
                self.info_dict['LicenseType'] = 'ILU'

            log.debug('License type is %s', self.info_dict['LicenseType'])
            lic_pattern = re.compile(r'\d+\.lic')
            dir_contents = self.ftp.nlst()

            for content in dir_contents:
                if lic_pattern.match(content):
                    log.debug('Copying %s to %s', content, self.lic_dir)
                    lic_file = open(os.path.join(self.lic_dir, content), 'wb')
                    self.ftp.retrbinary('RETR %s' % content, lic_file.write)
                    lic_file.close()
                    log.debug('Successfully copied %s to %s', content, self.lic_dir)
            return True
        except:
            self.info_dict['Failure'] = 'Error downloading lic files from %s' % self.ip
            log.error(self.info_dict['Failure'])
            return None

    def get_lic_from_native_ixos_chassis(self):
        """
        download licenses from native-ixos chassis
        """
        try:
            os.makedirs(self.lic_dir)
            actual_lic_dir = '/.ixlic'

            try:
                self.ftp.cwd(actual_lic_dir)
                self.info_dict['LicenseType'] = 'ILU'
            except:
                self.info_dict['Failure'] = 'lic dir does not exist on %s' % self.ip
                log.error(self.info_dict['Failure'])
                return None

            log.debug('License type is %s', self.info_dict['LicenseType'])
            lic_pattern = re.compile(r'\d+\.lic')
            dir_contents = self.ftp.nlst()

            for content in dir_contents:
                if lic_pattern.match(content):
                    log.debug('Copying %s to %s', content, self.lic_dir)
                    lic_file = open(os.path.join(self.lic_dir, content), 'wb')
                    self.ftp.retrbinary('RETR %s' % content, lic_file.write)
                    lic_file.close()
                    log.debug('Successfully copied %s to %s', content, self.lic_dir)
            return True
        except:
            self.info_dict['Failure'] = 'Error downloading lic files from %s' % self.ip
            log.error(self.info_dict['Failure'])
            return None

class IxWorker(object):
    """
    class for compiling chassis/license info and dumping a csv
    """

    def __init__(self, ip, log_dir):
        try:
            self.ip = ip
            self.log_dir = log_dir
            Resources.setup_logger(self.ip, self.log_dir)
            log.debug('Done initializing worker for %s', self.ip)
        except:
            raise

    def __del__(self):
        try:
            log.debug('Deleting Worker for %s', self.ip)
        except:
            raise

    def flatten_dict(self, dict_item, keys):
        """
        return a list of values each surrounded by ' " ' for keys
        """
        try:
            values = []
            for key in keys:
                values.append('"' + dict_item[key] + '"')
            return values
        except:
            raise

    def dump_csv(self, info_dicts):
        """
        generate csv for lic/chassis info
        """
        try:
            log.debug('Creating csv for %s ...', self.ip)
            columns = Resources.get_included_columns()
            with open(os.path.join(self.log_dir, "%s.csv" % self.ip), "w+") as handle:
                for info in info_dicts:
                    handle.write(','.join(self.flatten_dict(info, columns)) + '\n')
        except:
            pass

    def run(self):
        """
        worker execution starts here
        """
        try:
            _log.info('%s\t\t-> Worker Started', self.ip)
            log.debug('Checking if %s is a chassis...', self.ip)
            ixcon = IxConnection(self.ip, self.log_dir)
            if ixcon.can_connect_ixproxy():
                log.info('%s is a chassis...', self.ip)
                log.debug('Getting chassis info ...')
                chassis_infos = IxChassisInfo(self.ip, self.log_dir).run()
                log.debug('Done getting chassis info ...')
                log.debug('Getting chassis licenses ...')
                license_infos = IxLicenseInfo(self.ip, self.log_dir).run()
                log.debug('Done getting chassis licenses ...')
            else:
                log.error('%s is not a chassis...', self.ip)
                ixcon.info_dict['IsChassis'] = str(False)
                ixcon.info_dict['Failure'] = 'ip is down or not a chassis'
                return self.dump_csv([ixcon.info_dict])

            info_dicts = []
            for item in chassis_infos:
                info_dicts.append(item)
            for item in license_infos:
                info_dicts.append(item)
            self.dump_csv(info_dicts)
        except:
            raise
        finally:
            _log.info('%s\t\t-> Worker Closed', self.ip)


def dispatch_worker(arg_tuple):
    """
    worker dispatcher for a given ip address
    """
    try:
        ip, log_dir = arg_tuple
        IxWorker(ip, log_dir).run()
    except:
        raise

def main():
    """
    execution starts here
    """
    try:
        start_tick = datetime.datetime.now()
        log_dir = Resources.create_log_dir()
        Resources.create_sshkey(log_dir)
        Resources.setup_logger('main', log_dir)

        list_of_ips = Resources.get_list_of_ips()
        total_hosts = len(list_of_ips)
        tuple_list = [(ip, log_dir) for ip in list_of_ips]

        pool = multiprocessing.Pool(MAX_PROCESSES)
        jobs = pool.map_async(dispatch_worker, tuple_list, chunksize=1)
        pool.close()

        while True:
            if not jobs.ready():
                _log.info("COVERED: %d out of %d hosts !",
                          total_hosts - jobs._number_left, total_hosts)
                jobs.wait(5)
            else:
                _log.info("COVERED: %d out of %d hosts !",
                          total_hosts - jobs._number_left, total_hosts)
                break

        _log.info('')
        _log.info('Compiling csv results ...')
        csv_file = datetime.datetime.now().strftime('hw-info-%Y%b%d-%H%M%S.csv')
        columns = Resources.get_included_columns()

        with open(csv_file, "w+") as handle:
            handle.write(','.join(columns) + '\n')
            ip_csvs = os.listdir(log_dir)
            for ip_csv in ip_csvs:
                if ip_csv.endswith('.csv'):
                    with open(os.path.join(log_dir, ip_csv), "r") as ip_handle:
                        handle.write(ip_handle.read())
    except:
        raise
    finally:
        delta = datetime.datetime.now() - start_tick
        _log.info('')
        _log.info('Jobs Done: %s hours', str(delta))
        _log.info('')
        _log.info('########## Please check %s for results ##########', csv_file)

        logging.shutdown()
        if CLEANUP_TEMPDIR:
            Resources.cleanup_temp_dir()

if __name__ == '__main__':
    main()
