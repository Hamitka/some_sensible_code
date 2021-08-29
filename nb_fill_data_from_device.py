from utils import *
import pynetbox
from pathlib import Path
import re
from netmiko import (
    ConnectHandler,
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
)
import logging
import time


def time_track(func):
    def surrogate(*args, **kwargs):
        started_at = time.monotonic()   # 7.4

        result = func(*args, **kwargs)

        ended_at = time.monotonic()     # 7.4
        elapsed = round(ended_at - started_at, 4)
        print(f'Функция работала {int(elapsed // 3600)} час,'
              f'{elapsed / 60 % 60} минут,'
              f'{elapsed % 60} секунд')
        return result

    return surrogate


FILENAME_LOG = 'get_interfaces.log'
format_date = '%d.%m.%Y %H:%M:%S'

logging.basicConfig(filename=FILENAME_LOG,
                    format='%(asctime)s %(levelname)s: %(message)s',
                    # level=logging.INFO,
                    datefmt=format_date)

FILE_KEY_PEM = Path('C:\Install\private-key.pem')

NB = pynetbox.api(
    private_key_file=FILE_KEY_PEM,

)

DICT_INT_TYPE = {
    'lag': '(Port-channel)',
    'virtual': '(Vlan|Loopback|\.|AppGigabitEthernet)',
    '1000base-t': '(GigabitEthernet.*[^\.])',
    '10gbase-x-sfpp': '(TenGigabitEthernet.*[^\.])',
    '25gbase-x-sfp28': '(TwentyFiveGigE.*[^\.])',
    'lte': '(Cellular)',
}


class GetIntFromDevice:

    def __init__(self, some_device_from_nb):
        self.nb_device = some_device_from_nb
        self.hostname = self.nb_device.name
        self.device_id = self.nb_device.id
        self.ip_address, *_ = self.nb_device.primary_ip.address.split('/')
        self.vendor = self.nb_device.device_type.manufacturer.name
        self.tenant_name = self.nb_device.tenant.name
        self.tenant_id = self.nb_device.tenant.id
        self.device_platform = ''
        self.list_command = []

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
        for secret in list_secret:  # 7.3 уже наглядно
            if secret.role.name == 'terminal':
                dict_device['username'] = secret.name
                dict_device['password'] = secret.plaintext
            elif secret.role.name == 'enable':
                dict_device['secret'] = secret.plaintext
        return dict_device

    def _get_show_int_commands(self):
        some_result = {}
        device = self._get_data_from_netbox()
        try:
            with ConnectHandler(**device) as ssh:
                ssh.enable()
                for command in self.list_command:
                    output = ssh.send_command(command)
                    some_result[command] = output
            return some_result
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as error:
            logging.error(f'{device["host"]}, {self.hostname} some problem with ssh')
            return

    def _collect_data_for_netbox(self):
        """this method must be define in specific child class"""
        return

    def fill_data_in_netbox(self):  # 7.1 7.2 Единственный пример во всем коде, который возвращает bool

        def nb_ip_create():
            NB.ipam.ip_addresses.create(
                address=ip_address, status='active',
                tenant=self.tenant_id, assigned_object_type='dcim.interface',
                assigned_object_id=current_interface.id,
                description='',
            )

        dict_device_interfaces = self._collect_data_for_netbox()
        if not dict_device_interfaces: return False

        for int_name, int_data in dict_device_interfaces.items():   # 7.3 уже наглядно
            for nb_type, type_pattern in DICT_INT_TYPE.items():
                match_type_int = re.search(type_pattern, int_name)  # 7.5 ранее была переменная temp_re_search
                if match_type_int:
                    device_type = nb_type
                    break
                else:
                    device_type = 'virtual'
            # print(device_type)

            try_get_int_device = NB.dcim.interfaces.get(device=self.hostname, name=int_name)
            if try_get_int_device:
                try_get_int_device.update(
                    dict(description=int_data['description'],
                         mtu=int_data['mtu'],
                         mac_address=int_data['mac'],
                         enabled=int_data['status'] == 'up',
                         ))
            else:
                NB.dcim.interfaces.create(
                    device=self.device_id,
                    name=int_name,
                    description=int_data['description'],
                    mtu=int_data['mtu'],
                    enabled=int_data['status'] == 'up',
                    type=device_type,
                    mac_address=int_data['mac'],
                )
            current_interface = NB.dcim.interfaces.get(device=self.hostname, name=int_name)

            if int_data['child']:
                [NB.dcim.interfaces.get(device=self.hostname, name=some_int_name).update(dict(lag=current_interface.id))
                 for some_int_name in int_data['child']]

            if int_data['ip_addresses']:
                for ip_address in int_data['ip_addresses']:
                    try_get_ip_address = NB.ipam.ip_addresses.get(address=ip_address)
                    if try_get_ip_address:
                        if try_get_ip_address.assigned_object.device.name == self.hostname and \
                                try_get_ip_address.assigned_object.name == int_name:
                            pass
                        elif try_get_ip_address.assigned_object.device.name == self.hostname and \
                                try_get_ip_address.assigned_object.name != int_name:
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
    def __init__(self, some_device_from_nb):
        super().__init__(some_device_from_nb)
        self.device_platform = 'cisco_ios'
        self.list_command = ['show interfaces', 'show ip interface', 'show interfaces switchport', ]

    def _collect_data_for_netbox(self):
        super()._collect_data_for_netbox()
        get_int_config_result = self._get_show_int_commands()
        if not get_int_config_result: return None
        int_config_parts = re.split(r'\n(?=\S)', get_int_config_result['show interfaces'].lstrip())
        ip_int_config_parts = re.split(r'\n(?=\S)', get_int_config_result['show ip interface'].lstrip())
        int_switchport_config_parts = re.split(r'Name: ', get_int_config_result['show interfaces switchport'])
        int_switchport_config_parts = list(filter(bool, int_switchport_config_parts))
        dict_device_interfaces = {}

        def convert_short_to_long_name(short_int_name: str, list_long_name: list):
            begin_pattern, end_pattern, *_ = list(filter(bool, re.split(r'(^\D+)', short_int_name)))    # 7.4
            pattern_re = re.compile(f'{begin_pattern}.*{end_pattern}')
            try:
                long_int_name, *_ = list(filter(pattern_re.match, list_long_name))
                return long_int_name
            except ValueError as error:
                logging.error(f'{self.hostname} {short_int_name} some problem with convert')
                return

        for int_config in int_config_parts: # 7.3 уже наглядно
            device_int_name, *_ = int_config.split()
            dict_device_interfaces[device_int_name] = {}
            int_description = re.search(' Description: (.*)\n', int_config)
            dict_device_interfaces[device_int_name]['description'] = int_description.group(1) if int_description else ''

            int_mac_address = re.search(' Hardware is.*address is (\w{4}.\w{4}.\w{4}).*\n', int_config)
            dict_device_interfaces[device_int_name]['mac'] = int_mac_address.group(1) if int_mac_address else None

            int_status = re.search(' line protocol is (up|down).*\n', int_config)
            dict_device_interfaces[device_int_name]['status'] = int_status.group(1) if int_status else None

            int_mtu = re.search(' MTU (\d{,4}) bytes.*\n', int_config)
            dict_device_interfaces[device_int_name]['mtu'] = int_mtu.group(1) if int_mtu else None

            int_media_type = re.search('.* media type is (.*)\n', int_config)
            dict_device_interfaces[device_int_name]['media_type'] = int_media_type.group(1) if int_media_type else None

            int_child = re.search('Members in this channel: (.*)\n', int_config)
            dict_device_interfaces[device_int_name]['child'] = int_child.group(1).split() if int_child else []

        for ip_int_config in ip_int_config_parts:   # 7.3 уже наглядно
            device_int_name, *_ = ip_int_config.split()
            int_ip = re.search(' Internet address is (.*)\n', ip_int_config)
            dict_device_interfaces[device_int_name]['ip_addresses'] = [int_ip.group(1)] if int_ip else None

            int_ip = re.search(' Secondary address (.*)\n', ip_int_config)
            if int_ip: dict_device_interfaces[device_int_name]['ip_addresses'] += [int_ip.group(1)]

            int_vrf = re.search('VPN Routing/Forwarding (.*)\n', ip_int_config)
            dict_device_interfaces[device_int_name]['vrf'] = int_vrf.group(1) if int_vrf else ''

        list_of_int_long_name = list(dict_device_interfaces.keys())

        for int_data in dict_device_interfaces.values():    # 7.3 уже наглядно
            if int_data['child']:
                int_data['child'] = [convert_short_to_long_name(int_name_short, list_of_int_long_name) for
                                     int_name_short in int_data['child']]

        # for int_switchport_config in int_switchport_config_parts:
        #     device_int_name_short, *_ = int_switchport_config.split()
        #     device_int_name = convert_short_to_long_name(device_int_name_short, list_of_int_long_name)
        #
        #     int_member_of_lag_short = re.search('.*member of bundle (.*)\)\n', int_switchport_config)
        #     int_member_of_lag = convert_short_to_long_name(int_member_of_lag_short.group(1),
        #                                                    list_of_int_long_name) if int_member_of_lag_short else ''
        #     if device_int_name:
        #         dict_device_interfaces[device_int_name]['parent_lag'] = int_member_of_lag

        return dict_device_interfaces


class GetIntFromDeviceHPE(GetIntFromDevice):
    def __init__(self, some_device_from_nb):
        super().__init__(some_device_from_nb)
        self.device_platform = 'hp_comware'
        self.list_command = ['display interface']


class GetIntFromDeviceJuniper(GetIntFromDevice):
    def __init__(self, some_device_from_nb):
        super().__init__(some_device_from_nb)
        self.device_platform = 'juniper_junos'
        self.list_command = ['show interfaces']


@time_track
def main():
    test_device_from_nb = NB.dcim.devices.get(name='vlg-core-vologda_moskovskoe-C9300')
    test = GetIntFromDevice(test_device_from_nb).set_child_class()
    test.fill_data_in_netbox()


if __name__ == '__main__':
    main()
