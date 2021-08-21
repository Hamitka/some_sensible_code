import pynetbox
from netmiko import (
    ConnectHandler,
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
)
from multiprocessing.dummy import Pool as ThreadPool
import time
import logging
from pathlib import Path
from git import Repo
from collections import defaultdict
import ipaddress


FILENAME_LOG = 'backup_error.log'
FOLDER_BACKUP = 'backup_config_v2'
FILE_KEY_PEM = Path('C:\Install\private-key.pem')
# FILE_KEY_PEM = Path('/mnt/c/Install/private-key.pem')
format_date = '%d.%m.%Y %H:%M:%S'
logging.basicConfig(filename=FILENAME_LOG,
                    format='%(asctime)s %(levelname)s: %(message)s',
                    # level=logging.INFO,
                    datefmt=format_date)
DICT_VENDOR = {
    'Cisco': 'cisco_ios',
    'HPE': 'hp_comware',
    'Juniper': 'juniper_junos',
}


def get_devices_from_netbox():
    """ function to get data from netbox
    filtered by exists data of secrets """
    try:
        nb = pynetbox.api(
            'https://netbox.rtrn.ru/',
            private_key_file=FILE_KEY_PEM,
            token='255875da0b8ef55381950e2b4968b138daa2828b'
            # token='1b97638e45b2b16f77c2bc7a797b33a2cf490d98'
        )
    except Exception as error:
        logging.critical(f'no response from NETBOX {error.__class__.__name__}')
        return
    # dict_vendor = {
    #     'Cisco': DeviceCisco,
    #     'HP': DeviceHPE,
    # }
    # list_devices = list(nb.dcim.devices.all())
    list_secrets = list(nb.secrets.secrets.filter(role=['terminal', 'enable']))
    # dict_tenants = {key.name: key.group for key in list(nb.tenancy.tenants.all())}
    dict_devices = defaultdict(defaultdict)
    logging.warning('finished collecting data from netbox')
    for item in list_secrets:
        dev_hostname = item.assigned_object.name
        if item.role.name == 'enable':
            dict_devices[dev_hostname]['secret'] = item.plaintext
        elif item.role.name == 'terminal':
            dev_vendor = item.assigned_object.device_type.manufacturer.name
            if dev_vendor in DICT_VENDOR.keys():
                dict_devices[dev_hostname]['device_type'] = DICT_VENDOR[dev_vendor]

            dict_devices[dev_hostname]['username'] = item.name
            dict_devices[dev_hostname]['password'] = item.plaintext
            try:
                dev_ip = ipaddress.ip_interface(item.assigned_object.primary_ip.address).ip
                dict_devices[dev_hostname]['host'] = str(dev_ip)
            except Exception as error:
                logging.critical(
                    f'cannot get ip from netbox for {item.name, dev_hostname},  {error.__class__.__name__}')
    logging.warning('finished collecting data from secrets')
    return dict_devices


def send_show_command(hostname: str, device: dict):
    """function for sending some list of command to device """
    try:
        if device['device_type'] == 'cisco_ios':
            list_command = ['show version | exclude uptime|Uptime|restarted', 'show inventory', 'show configuration', ]
        elif device['device_type'] == 'hp_comware':
            list_command = ['display  version | exclude uptime', 'display device manuinfo', 'display current']
        elif device['device_type'] == 'juniper_junos':
            list_command = ['show version', 'show configuration | display set']
        else:
            logging.error(f'unknown type of device {hostname}, {device["host"]}')
            return
    except Exception as error:
        logging.error(f'some problem with {hostname}, {error.__class__.__name__}')
        return
    some_result = {}
    try:
        with ConnectHandler(**device) as ssh:
            ssh.enable()
            for command in list_command:
                output = ssh.send_command(command)
                some_result[command] = output
        return some_result
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as error:
        # some strange way to extract useful args from exception:
        # error_msg_exp, *_ = list(filter(lambda x: 'Device settings' in x, error.args[0].split('\n')))
        logging.error(f'{device["host"]}, {hostname} some problem with ssh')
        return


def write_config_to_file(filename: str, some_data, ):
    if not some_data:
        return
    path = Path(FOLDER_BACKUP)
    path.mkdir(exist_ok=True)
    with open(Path(path, filename), encoding='utf-8', mode='w+') as file:
        for value in some_data.values():
            file.write(value)


def get_config_and_write(tup_hostname_device: tuple):
    hostname, device = tup_hostname_device
    # print(f'try to get data from {hostname}')
    result = send_show_command(hostname, device)
    if result:
        write_config_to_file(hostname, result)


def git_push():
    path_repo = Path.cwd()
    commit_msg = f'new commit of backup done at {time.strftime(format_date, time.localtime())}'
    repo = Repo(path_repo)
    repo.index.add([FOLDER_BACKUP, FILENAME_LOG])
    repo.index.commit(commit_msg)
    origin = repo.remote(name='origin')
    repo_url, *_ = [i for i in origin.urls]
    origin.push(force=True)
    print(f'all files was pushed into repo {repo_url}')


if __name__ == "__main__":
    logging.warning('starts main program')
    time_start_all = time.monotonic()
    dict_device = get_devices_from_netbox()

    with ThreadPool(30) as pool:
        pool.map(get_config_and_write, dict_device.items())

    time_execute_all = time.monotonic() - time_start_all

    print(f'data of all available hosts successfully written to files in {round(time_execute_all, 2)} seconds, '
          f'exceptions in file {FILENAME_LOG}')
    git_push()
