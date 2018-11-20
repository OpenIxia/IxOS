import os
from  RestApi.IxOSRestInterface import IxRestSession

CHASSIS = "10.38.162.139" #replace this with your chassis address/hostname.

session = IxRestSession(CHASSIS, verbose=False)
# Get all chassis/cards/ports
chassisInfo = session.get_chassis()
if  type(chassisInfo.data) != type([]) or 'state' not in chassisInfo.data[0]:
    print("Unexpected chassis response. Please check that you are connection to an IxOS chassis running 8.50 or newer version.")
elif chassisInfo.data[0]['state'].upper() != 'UP':
    #chassis is not ready. need to take action
    print("Chassis {0} is reachable, but IxServer in down! Please check chassis connectivity, license avilability and logs.".format(CHASSIS))
else: 
    card_list= session.get_cards().data
    port_list = session.get_ports().data

    for port in port_list:
        print("Port {card}/{port}{newline}Owner: {owner}{newline}Type: {type}{newline}Link state: {state}".format(
                card=port['cardNumber'], 
                type = port['type'],
                port=port['portNumber'],
                newline= os.linesep+"\t",
                owner= port['owner'],
                state = port['linkState'] if 'linkState' in port else 'Not Supported (Windows Chassis)'))

    # Get card/port using card/port number
    #card = session.get_cards(params={'cardNumber': 1}).data[0]
    #port = session.get_ports(params={'cardNumber': 1, 'portNumber': 1}).data[0]


    #Note: Below are only supported on Linux Chassis

    # Port specific operations  
    #session.take_ownership(port['id'])
    #session.reboot_port(port['id'])
    #session.reset_port(port['id'])
    #session.release_ownership(port['id'])

    # Card specific operations
    #session.hotswap_card(card['id'])

    # Chassis specific operations
    #session.get_services()