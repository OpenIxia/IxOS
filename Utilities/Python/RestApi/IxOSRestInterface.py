"""
An interface to IxOS REST APIs that allows you to connect to a IxOS chassis.
This is intended for Linux based chassis including IxVM chassis, but also
works with limited functionality for Windows chassis.
"""

import sys
import os
import json
import time
import requests

# handle urllib3 differences between python versions
if sys.version_info[0] == 2 and ((sys.version_info[1] == 7 and sys.version_info[2] < 9) or sys.version_info[1] < 7):
    import requests.packages.urllib3
else:
    import urllib3

class IxRestException(Exception):
    pass

class IxRestSession(object):
    """
    class for handling HTTP requests/response for IxOS REST APIs
    Constructor arguments:
    chassis_address:    addrress of the chassis
    Optional arguments:
        api_key:        API key or you can use authenticate method \
                        later to get it by providing user/pass.
        verbose:        If True, will print every HTTP request or \
                        response header and body.
        timeout:        Time to wait (in seconds) while polling \
                        for async operation.
        poll_interval:  Polling inteval in seconds.
    """

    def __init__(self, chassis_address, api_key=None,timeout=500, poll_interval=2, verbose=False, insecure_request_warning=False):

        self.chassis_ip = chassis_address
        self.api_key = api_key
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.verbose = verbose
        self._authUri = '/platform/api/v1/auth/session'

        # ignore self sign certificate warning(s) if insecure_request_warning=False
        if not insecure_request_warning:
            try:
                if sys.version_info[0] == 2 and ((sys.version_info[1] == 7 and sys.version_info[2] < 9) or sys.version_info[1] < 7):
                    requests.packages.urllib3.disable_warnings()
                else:
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except AttributeError:
                print('WARING:You are using an old urllib3 version which does not support handling the certificate validation warnings. Please upgrade urllib3 using: pip install urllib3 --upgrade')

    # try to authenticate with default user/password if no api_key was provided
        if not api_key:
            self.authenticate()

    def get_ixos_uri(self):
        return 'https://%s/chassis/api/v2/ixos' % self.chassis_ip

    def get_headers(self):
        # headers should at least contain these two
        return {
            "Content-Type": "application/json",
            'x-api-key': self.api_key
        }

    def authenticate(self, username="admin", password="admin"):
        """
        we need to obtain API key to be able to perform any REST
        calls on IxOS
        """
        print('getting api key ...')
        payload = {
            'username': username,
            'password': password,
            'rememberMe': False
        }
        response = self.http_request(
            'POST',
            'https://{address}{uri}'.format(address=self.chassis_ip,
                                            uri=self._authUri),
            payload=payload
        )
        self.api_key = response.data['apiKey']
        print('api key is %s' % self.api_key)

    def http_request(self, method, uri, payload=None, params=None):
        """
        wrapper over requests.requests to pretty-print debug info
        and invoke async operation polling depending on HTTP status code (e.g. 202)
        """
        try:
            # lines with 'debug_string' can be removed without affecting the code
            if not uri.startswith('http'):
                uri = self.get_ixos_uri() + uri

            debug_string = 'Request => %s %s\n' % (method, uri)

            if payload is not None:
                payload = json.dumps(payload, indent=2, sort_keys=True)

            headers = self.get_headers()

            if self.verbose:
                debug_string += 'Params:\n' + \
                    json.dumps(params, indent=2, sort_keys=True) + '\n'
                debug_string += 'Headers:\n' + \
                    json.dumps(headers, indent=2, sort_keys=True) + '\n'
                debug_string += 'Payload:\n' + str(payload) + '\n'

            print(debug_string)
            response = requests.request(
                method, uri, data=payload, params=params,
                headers=headers, verify=False
            )

            debug_string = 'Response => Status %d\n' % response.status_code
            data = None
            try:
                data = response.content.decode()
                data = json.loads(data) if data else None
            except:
                print('Invalid/Non-JSON payload received: %s' % data)
                data = None

            if str(response.status_code)[0] == '4':
                raise IxRestException("{code} {reason}: {data}.{extraInfo}".format(
                    code=response.status_code,
                    reason=response.reason,
                    data=data,
                    extraInfo="{sep}{msg}".format(
                        sep=os.linesep,
                        msg="Please check that your API key is correct or call IxRestSession.authenticate(username, password) in order to obtain a new API key."
                    ) if str(response.status_code) == '401' and uri[-len(self._authUri):] != self._authUri else ''
                )
                )

            if self.verbose:
                debug_string += 'Headers:\n' + \
                    json.dumps(dict(response.headers),
                               indent=2, sort_keys=True) + '\n'
                if data:
                    debug_string += 'Payload:\n' + \
                        json.dumps(data, indent=2, sort_keys=True) + '\n'

            print(debug_string)

            if response.status_code == 202:
                return self.wait_for_async_operation(data)
            else:
                response.data = data
                return response
        except:
            raise

    def wait_for_async_operation(self, response_body):
        """
        method for handeling intermediate async operation results
        """
        try:
            print('Polling for async operation ...')
            operation_status = response_body['state']
            start_time = int(time.time())
            while operation_status == 'IN_PROGRESS':
                response = self.http_request('GET', response_body['url'])
                response_body = response.data
                operation_status = response_body['state']
                if int(time.time() - start_time) > self.timeout:
                    raise IxRestException(
                        'timeout occured while polling for async operation')

                time.sleep(self.poll_interval)

            if operation_status == 'COMPLETED':
                return response
            else:
                raise IxRestException('async operation failed')
        except:
            raise
        finally:
            print('Completed async operation')

    def get_chassis(self, params=None):
        return self.http_request('GET', self.get_ixos_uri() + '/chassis', params=params)

    def get_cards(self, params=None):
        return self.http_request('GET', self.get_ixos_uri() + '/cards', params=params)

    def get_ports(self, params=None):
        return self.http_request('GET', self.get_ixos_uri() + '/ports', params=params)

    def get_services(self, params=None):
        return self.http_request('GET', self.get_ixos_uri() + '/services', params=params)

    def take_ownership(self, resource_id):
        return self.http_request(
            'POST',
            self.get_ixos_uri() + '/ports/%d/operations/takeownership' % resource_id
        )

    def release_ownership(self, resource_id):
        return self.http_request(
            'POST',
            self.get_ixos_uri() + '/ports/%d/operations/releaseownership' % resource_id
        )

    def reboot_port(self, resource_id):
        return self.http_request(
            'POST',
            self.get_ixos_uri() + '/ports/%d/operations/reboot' % resource_id
        )

    def reset_port(self, resource_id):
        return self.http_request(
            'POST',
            self.get_ixos_uri() + '/ports/%d/operations/resetfactorydefaults' % resource_id
        )

    def hotswap_card(self, resource_id):
        return self.http_request(
            'POST',
            self.get_ixos_uri() + '/cards/%d/operations/hotswap' % resource_id
        )


if __name__ == '__main__':
    print('''
This library is not ment to be executed directly.
Sample usage:
    
    from IxOSRestInterface import IxRestSession
    session = IxRestSession("<chassis_address>", api_key="<you_api_key>")
    
    #If your chassis does not uses the default credentials
    self.authenticate("<username>","<password>")
    
    # Get all chassis/cards/ports
    chassisInfo = session.get_chassis()
    card_list= session.get_cards().data
    port_list = session.get_ports().data

    #Get card/port using card/port number
    card = session.get_cards(params={'cardNumber': 1}).data[0]
    port = session.get_ports(params={'cardNumber': 1, 'portNumber': 1}).data[0]

    #Note: Below are only supported on Linux Chassis

    # Port specific operations  
    session.take_ownership(port['id'])
    session.reboot_port(port['id'])
    session.reset_port(port['id'])
    session.release_ownership(port['id'])

    # Card specific operations
    session.hotswap_card(card['id'])

    # Chassis specific operations
    session.get_services()
''')
