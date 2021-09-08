from utils import *
from my_secrets import *
import re
from netmiko import (
    ConnectHandler,
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
)
import logging
from multiprocessing.dummy import Pool as ThreadPool

FILENAME_LOG = 'get_interfaces.log'
format_date = '%d.%m.%Y %H:%M:%S'

logging.basicConfig(filename=FILENAME_LOG,
                    format='%(asctime)s %(levelname)s: %(message)s',
                    # level=logging.INFO,
                    datefmt=format_date)
# было DICT_INT_TYPE
DICT_IFACE_TYPE = {
    'lag': '(Port-channel)',
    'virtual': '(Vlan|Loopback|\.|AppGigabitEthernet)',
    '1000base-t': '(GigabitEthernet.*[^\.])',
    '10gbase-x-sfpp': '(TenGigabitEthernet.*[^\.])',
    '25gbase-x-sfp28': '(TwentyFiveGigE.*[^\.])',
    '40gbase-x-qsfpp': '(FortyGigabitEthernet.*[^\.])',
    'lte': '(Cellular)',
}


class GetIntFromDevice:
    pattern_iface_parts = ''    # было pattern_int_parts
    pattern_switchport_parts = ''
    pattern_description = ''
    pattern_mac = ''
    pattern_status = ''
    pattern_mtu = ''
    pattern_media = ''
    pattern_lag_child = ''
    pattern_ip_address = ''
    pattern_ip_address_sec = ''
    pattern_vrf = ''

    def __init__(self, some_device_from_nb):
        self.nb_device = some_device_from_nb
        self.hostname = self.nb_device.name
        self.device_id = self.nb_device.id
        self.ip_address, *_ = self.nb_device.primary_ip.address.split('/') \
            if self.nb_device.primary_ip else [None, None]
        self.vendor = self.nb_device.device_type.manufacturer.name
        self.tenant_name = self.nb_device.tenant.name
        self.tenant_id = self.nb_device.tenant.id
        self.device_platform = ''
        self.dict_command = {}

    def set_child_class(self):
        if self.vendor == 'Cisco':
            return GetIntFromDeviceCisco(self.nb_device)
        elif self.vendor == 'HPE':
            return GetIntFromDeviceHPE(self.nb_device)
        elif self.vendor == 'Juniper':
            return GetIntFromDeviceJuniper(self.nb_device)
        else:
            return GetIntFromDevice(self.nb_device)

    def _get_data_from_netbox(self):
        dict_device = {
            'device_type': self.device_platform,
            'host': self.ip_address
        }
        list_secret = list(NB.secrets.secrets.filter(role=['terminal', 'enable'], device=self.hostname))
        for secret in list_secret:
            if secret.role.name == 'terminal':
                dict_device['username'] = secret.name
                dict_device['password'] = secret.plaintext
            elif secret.role.name == 'enable':
                dict_device['secret'] = secret.plaintext
        return dict_device

    def _get_show_iface_commands(self):     # было _get_show_int_commands
        some_result = {}
        device = self._get_data_from_netbox()
        try:
            with ConnectHandler(**device) as ssh:
                ssh.enable()
                for command_name, command in self.dict_command.items():
                    output = ssh.send_command(command)
                    some_result[command_name] = output
            return some_result
        except (NetmikoTimeoutException, NetmikoAuthenticationException, Exception) as error:
            logging.error(f"{device['host']}, {self.hostname} some problem with ssh: {error.__str__().split(chr(10))[0]}")
            return

    def _collect_data_for_netbox(self):
        """this method must be define in specific child class"""

        def convert_short_to_long_name(short_iface_name: str, list_long_name: list):    # было short_int_name
            begin_pattern, end_pattern, *_ = list(filter(bool, re.split(r'(^\D+)', short_iface_name)))
            pattern_re = re.compile(f'{begin_pattern}.*{end_pattern}')
            try:
                long_iface_name, *_ = list(filter(pattern_re.match, list_long_name))    # было long_int_name
                return long_iface_name
            except ValueError as error:
                logging.error(f'{self.hostname} {short_iface_name} some problem with convert')
                return

        get_iface_config_result = self._get_show_iface_commands()   # было get_int_config_result
        if not get_iface_config_result: return None
        iface_config_parts = re.split(self.pattern_iface_parts, get_iface_config_result['show_int'].lstrip())   # было int_config_parts
        ip_iface_config_parts = re.split(self.pattern_iface_parts, get_iface_config_result['show_ip_int'].lstrip()) # было ip_int_config_parts
        # int_switchport_config_parts = re.split(self.pattern_switchport_parts, get_iface_config_result['show_int_switch'])
        # int_switchport_config_parts = list(filter(bool, int_switchport_config_parts))
        dict_device_interfaces = {}

        for iface_config in iface_config_parts:     # было int_config
            device_iface_name, *_ = iface_config.split()    # было device_int_name
            dict_device_interfaces[device_iface_name] = {}
            iface_description = re.search(self.pattern_description, iface_config)   # было int_description
            dict_device_interfaces[device_iface_name]['description'] = iface_description.group(1) if iface_description else ''

            iface_mac_address = re.search(self.pattern_mac, iface_config)   # было int_mac_address
            dict_device_interfaces[device_iface_name]['mac'] = iface_mac_address.group(1) if iface_mac_address else None

            iface_status = re.search(self.pattern_status, iface_config)     # было int_status
            dict_device_interfaces[device_iface_name]['status'] = iface_status.group(1).lower() if iface_status else None

            iface_mtu = re.search(self.pattern_mtu, iface_config)   # было int_mtu
            dict_device_interfaces[device_iface_name]['mtu'] = iface_mtu.group(1) if iface_mtu else None

            iface_media_type = re.search(self.pattern_media, iface_config)      # было int_media_type
            dict_device_interfaces[device_iface_name]['media_type'] = iface_media_type.group(1) if iface_media_type else None

            iface_child = re.search(self.pattern_lag_child, iface_config)       # было int_child
            dict_device_interfaces[device_iface_name]['child'] = iface_child.group(1).split() if iface_child else []

        for ip_iface_config in ip_iface_config_parts:       # было ip_int_config
            device_iface_name, *_ = ip_iface_config.split()     # было device_int_name
            iface_ip = re.search(self.pattern_ip_address, ip_iface_config)  # было int_ip
            dict_device_interfaces[device_iface_name]['ip_addresses'] = [iface_ip.group(1)] if iface_ip else None

            iface_ip = re.findall(self.pattern_ip_address_sec, ip_iface_config)
            if iface_ip: dict_device_interfaces[device_iface_name]['ip_addresses'] += iface_ip

            iface_vrf = re.search(self.pattern_vrf, ip_iface_config)    # было int_vrf
            dict_device_interfaces[device_iface_name]['vrf'] = iface_vrf.group(1) if iface_vrf else ''

        list_of_iface_long_name = list(dict_device_interfaces.keys())   # было list_of_int_long_name

        for iface_data in dict_device_interfaces.values():  # было int_data
            if iface_data['child']:
                iface_data['child'] = [convert_short_to_long_name(iface_name_short, list_of_iface_long_name) for
                                     iface_name_short in iface_data['child']]

        # for int_switchport_config in int_switchport_config_parts:
        #     device_int_name_short, *_ = int_switchport_config.split()
        #     device_iface_name = convert_short_to_long_name(device_int_name_short, list_of_iface_long_name)
        #
        #     int_member_of_lag_short = re.search('.*member of bundle (.*)\)\n', int_switchport_config)
        #     int_member_of_lag = convert_short_to_long_name(int_member_of_lag_short.group(1),
        #                                                    list_of_iface_long_name) if int_member_of_lag_short else ''
        #     if device_iface_name:
        #         dict_device_interfaces[device_iface_name]['parent_lag'] = int_member_of_lag

        return dict_device_interfaces

    def fill_data_in_netbox(self):

        def nb_ip_create():
            NB.ipam.ip_addresses.create(
                address=ip_address, status='active',
                tenant=self.tenant_id, assigned_object_type='dcim.interface',
                assigned_object_id=current_interface.id,
                description='',
            )

        dict_device_interfaces = self._collect_data_for_netbox()
        if not dict_device_interfaces: return False

        dict_existed_ints_device_nb = {key.name: key for key in list(NB.dcim.interfaces.filter(device=self.nb_device))}

        # delete excess interfaces form netbox, which are not created on the device:
        [iface_nb_data.delete() for iface_nb_name, iface_nb_data in dict_existed_ints_device_nb.items() if
         iface_nb_name not in dict_device_interfaces]

        for iface_name, iface_data in dict_device_interfaces.items():   # было int_name, int_data
            for nb_type, type_pattern in DICT_IFACE_TYPE.items():
                temp_re_search = re.search(type_pattern, iface_name)
                if temp_re_search:
                    device_type = nb_type
                    break
                else:
                    device_type = 'virtual'
            # print(device_type)

            if iface_name in dict_existed_ints_device_nb.keys():
                dict_existed_ints_device_nb[iface_name].update(
                    dict(description=iface_data['description'],
                         mtu=iface_data['mtu'],
                         mac_address=iface_data['mac'],
                         enabled=iface_data['status'] == 'up',
                         )
                )

            else:
                NB.dcim.interfaces.create(
                    device=self.device_id,
                    name=iface_name,
                    description=iface_data['description'],
                    mtu=iface_data['mtu'],
                    enabled=iface_data['status'] == 'up',
                    type=device_type,
                    mac_address=iface_data['mac'],
                )
            current_interface = NB.dcim.interfaces.get(device=self.hostname, name=iface_name)

            if iface_data['child']:
                [NB.dcim.interfaces.get(device=self.hostname, name=some_iface_name).update(dict(lag=current_interface.id))
                 for some_iface_name in iface_data['child']]

            iface_data.setdefault('ip_addresses', None)
            if iface_data['ip_addresses']:
                for ip_address in iface_data['ip_addresses']:
                    try_get_ip_address = NB.ipam.ip_addresses.get(address=ip_address)
                    if try_get_ip_address:
                        if try_get_ip_address.assigned_object.device.name == self.hostname and \
                                try_get_ip_address.assigned_object.name == iface_name:
                            pass
                        elif try_get_ip_address.assigned_object.device.name == self.hostname and \
                                try_get_ip_address.assigned_object.name != iface_name:
                            try_get_ip_address.update(dict(assigned_object_id=current_interface.id))
                        else:
                            nb_ip_create()
                            logging.info(
                                f"IP {ip_address}, is already busy in {try_get_ip_address.assigned_object.device.name} "
                                f"{try_get_ip_address.assigned_object.device.tenant}")
                    else:
                        nb_ip_create()
        return True


class GetIntFromDeviceCisco(GetIntFromDevice):
    pattern_iface_parts = re.compile(r'\n(?=\S)')
    pattern_switchport_parts = re.compile(r'Name: ')
    pattern_description = re.compile(r' Description: (.*)\n')
    pattern_mac = re.compile(r' Hardware is.*address is (\w{4}.\w{4}.\w{4}).*\n')
    pattern_status = re.compile(r' line protocol is (up|down).*\n')
    pattern_mtu = re.compile(r' MTU (\d{,4}) bytes.*\n')
    pattern_media = re.compile(r'.* media type is (.*)\n')
    pattern_lag_child = re.compile(r'Members in this channel: (.*)\n')
    pattern_ip_address = re.compile(r' Internet address is (.*)\n')
    pattern_ip_address_sec = re.compile(r' Secondary address (.*)\n')
    pattern_vrf = re.compile(r'VPN Routing/Forwarding (.*)\n')

    def __init__(self, some_device_from_nb):
        super().__init__(some_device_from_nb)
        self.device_platform = 'cisco_ios'
        self.dict_command = {
            'show_int': 'show interfaces',
            'show_ip_int': 'show ip interface',
            # 'show_int_switch': 'show interfaces switchport',
        }


class GetIntFromDeviceHPE(GetIntFromDevice):
    pattern_iface_parts = re.compile(r'\n\n')
    # pattern_switchport_parts = re.compile(r'Name: ')
    pattern_description = re.compile(r'Description: (?!.*Interface)(.*)\n')
    pattern_mac = re.compile(r'IP .* Hardware Address: (\w{4}.\w{4}.\w{4}).*\n')
    pattern_status = re.compile(r'Current state: (UP|DOWN).*\n')
    pattern_mtu = re.compile(r'Maximum Transmit Unit: (\d{,4})\n')
    pattern_media = re.compile(r'Media type: (.*?),.*\n')
    pattern_lag_child = re.compile(r'Members in this channel: (.*)\n')  # TODO
    pattern_ip_address = re.compile(r'Internet Address is (.*) Primary\n')
    pattern_ip_address_sec = re.compile(r'Internet Address is (.*) Sub\n')
    pattern_vrf = re.compile(r'VPN Routing/Forwarding (.*)\n')  # TODO

    def __init__(self, some_device_from_nb):
        super().__init__(some_device_from_nb)
        self.device_platform = 'hp_comware'
        self.dict_command = {
            'show_int': 'display interface',
            'show_ip_int': 'display ip interface',
            # 'show_int_switch': 'show interfaces switchport',
        }


class GetIntFromDeviceJuniper(GetIntFromDevice):
    def __init__(self, some_device_from_nb):
        super().__init__(some_device_from_nb)
        self.device_platform = 'juniper_junos'
        self.list_command = ['show interfaces']


@time_track
def main():
    test_device_from_nb = NB.dcim.devices.get(name='bas-gw-ufa_oktyabrskoy_revolyucii-MSR3012')
    # test_device_from_nb = NB.dcim.devices.get(name='kur-gw-lipovchik-C1111')
    test = GetIntFromDevice(test_device_from_nb).set_child_class()
    test_some_device = test._collect_data_for_netbox()
    print(test_some_device)
    # test.fill_data_in_netbox()
    # list_active_cisco_device = list(NB.dcim.devices.filter(status='active', manufacturer='cisco'))
    # list_class_cisco_device = [GetIntFromDevice(device_from_nb).set_child_class() for device_from_nb in
    #                            list_active_cisco_device]
    # # [item.fill_data_in_netbox() for item in list_class_cisco_device]
    # with ThreadPool(10) as pool:
    #     pool.map(GetIntFromDevice.fill_data_in_netbox, list_class_cisco_device)


if __name__ == '__main__':
    main()
