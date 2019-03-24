#! /usr/bin/env python


from pyVim import connect, task
from pyVmomi import vim
from tools import cli
from tools import tasks
from pprint import pprint


import atexit
import time
import requests
import urllib3
import ssl
import configparser
import os
import subprocess
import argparse
import sys
import re
import logging
import traceback


class logger:
    loggingEnabled = False
    initialised = False
    logger = None

    def __init__(self):
        if Logger.initialised == False:
            logger.setup()

    @staticmethod
    def setup():
        logger.initialised = True
        logger.logger = logging.getLogger()
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logger.logger.addHandler(console_handler)

        logger.logger.setLevel(logging.INFO)

    @staticmethod
    def set_enabled(status):
        logger.loggingEnabled = status

    @staticmethod
    def debug(str):
        if logger.loggingEnabled:
            logger.logger.debug(str)

    @staticmethod
    def info(str):
        if logger.loggingEnabled:
            logger.logger.info(str)

"""
Consolidates "tasks" returned by calls to pymomi, then allows wait() for the tasks to be completed...
"""
class ESXiTaskManager:
    def __init__(self):
        self.tasks = []

    def add_task(self, task):
        self.tasks.append(task)

    def add_task_list(self, group):
        self.tasks = self.tasks + group

    def check(self):
        if len(self.tasks):
            for task in self.tasks:
                logger.info(task.info)
        else:
            logger.info("No tasks..")

    def _progress_output(self, task, progress):
        if progress is None:
            return
        try:
            progess = str(progress)

            if "error" in progress:
                return  ## Just return at this point.. the exception handler in waitX() will deal with this

            if progress.isdigit():
                progress = progress + "%"

            logger.info("{} on {}, progress is {}".format(task.info.descriptionId, task.info.entityName, progress))
        except (TypeError) as e:
            pass

    def clear(self):
        self.tasks = list()

    def wait(self, show_progress=False):
        if len(self.tasks) > 0:
            try:
                if show_progress:
                    progress_call = self._progress_output
                else:
                    progress_call = None

                task.WaitForTasks(tasks=self.tasks, onProgressUpdate=progress_call)
            except (Exception) as e:
                logger.info("Houston, we have a problem: " + e.msg)


"""
Manages the connection to ESXi/vCenter hosts, including the accessing the server-instance and data contents
"""
class ESXiConnectionManager:
    def __init__(self, svr, usr, pss, prt):
        self.server_instance = None

        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.server_instance = connect.SmartConnectNoSSL(host=svr, user=usr, pwd=pss, port=prt)
            atexit.register(connect.Disconnect, self.server_instance)

        except IOError as ex:
            raise SystemExit("unable to connect to vCenter / ESXi host..")

    def get_server_instance(self):
        return self.server_instance

    def get_content(self):
        return self.server_instance.RetrieveContent()


"""
Incapsulate functions for identifying and managing the ESXi hosts
"""
class ESXiHostManager:
    def __init__(self):
        self.hosts = dict()

    def get_hosts(self, content, hostnames=[]):
        self.hosts = dict()
        host_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)

        ## Here we keep a class-local reference to the hosts, filtering for specific hosts if defined in "hostnames"
        for host in host_view.view:
            if len(hostnames) == 0:
                self.hosts[host.name] = host
            else:
                for hostname in hostnames:
                    if (host.name == hostname):
                        self.hosts[host.name] = host

        return self.hosts

    def shutdown_hosts(self, forced_shutdown=False):
        tasks = list()
        for key, host in self.hosts.items():
            logger.info("Host {} is now being shutdown".format(key))
            task = host.ShutdownHost_Task(forced_shutdown)
            tasks.append(task)

        return tasks


"""
Incapsulate functions for identifying and managing the VMs on ESXi hosts
"""
class ESXiVMManager:
    def __init__(self):
        self.vms = dict()

    def get_vms(self, hosts):
        self.vms = dict()
        for key, host in hosts.items():
            for vm in host.vm:
                self.vms[vm.name] = vm

        return self.vms

    def set_note(self, vm, message):
        spec = vim.vm.ConfigSpec()
        spec.annotation = message
        task = vm.ReconfigVM_Task(spec)
        return task

    def suspend_vms(self):
        task_list = list()
        for key, vm in self.vms.items():
            logger.info("VM {} is currently {}".format(key, vm.runtime.powerState))
            if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                logger.info("VM {} is being suspended".format(key))
                note_task = self.set_note(vm, "SCHEDULED_SUSPEND")
                task.WaitForTask(note_task)
                vm_task = vm.SuspendVM_Task()
                task_list.append(vm_task)

        return task_list

    def unsuspend_vms(self):
        task_list = list()
        for key, vm in self.vms.items():
            logger.info("VM {} is currently {}".format(key, vm.runtime.powerState))
            if vm.runtime.powerState == vim.VirtualMachinePowerState.suspended:
                logger.info("VM {} is being unsuspended".format(key))
                note_task = self.set_note(vm, "SCHEDULED_UNSUSPEND")
                task.WaitForTask(note_task)
                vm_task = vm.PowerOnVM_Task()
                task_list.append(vm_task)

        return task_list

"""
IPMI access by making subsystem calls the ipmitools executable 
"""
class IPMIManager:
    POWER_OFF = "Off"
    POWER_ON = "On"
    POWER_UP = "Up/On"

    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password

    def check_powered_on_result(self, result):
        result = str(result)
        if result == self.POWER_ON.lower():
            return True
        elif result == self.POWER_UP.lower():
            return True
        else:
            return False

    def is_powered_on(self):
        result = self.get_power_status()
        return self.check_powered_on_result(result)

    def power_response_to_str(self, result):
        result = str(result)

        if result.lower() == self.POWER_UP.lower():
            return "Powering UP"
        elif result.lower() == self.POWER_ON.lower():
            return "Power is ON"
        elif result.lower() == self.POWER_OFF.lower():
            return "Power is OFF"
        else:
            return "Power is UNKNOWN"

    def get_power_status(self):
        try:
            cmd = "ipmitool -I lanplus -H {} -U {} -P {} chassis power status".format(self.host, self.username, self.password)
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)

            pattern = "Chassis Power is (?P<status>.*)\\\\n'"
            result = re.search(pattern, str(result.stdout))

            return result.group("status")
        except subprocess.CalledProcessError as e:
            raise Exception("Unable to cleanup old audit logs, the following error occured: " + e.output)

    def power_on(self):
        try:
            cmd = "ipmitool -I lanplus -H {} -U {} -P {} chassis power on".format(self.host, self.username, self.password)
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)

            pattern = ": (?P<status>.*)\\\\n'"
            result = re.search(pattern, str(result.stdout))
            status = result.group("status")

            return self.check_powered_on_result(status)
        except subprocess.CalledProcessError as e:
            raise Exception("Error unable to power on, the following error occured: " + e.output)



"""
A utility for loading the config file, extracting the user-defined settings, and ensuring that mandatory values are present
"""
class ConfigManager:
    def __init__(self, path):
        """
        Initiate the class, reset all values to default..
        """
        self.config_path = path
        self.hosts = dict()

    def read(self):
        mandatory_fields = ["enabled", "esxi_host", "esxi_username", "esxi_password", "esxi_webport", "ipmi_enabled"]

        if os.path.exists(self.config_path):
            config_parser = configparser.ConfigParser()
            config_parser.read(self.config_path)
            host_no = 1;
            section_name = "HOST"
            while config_parser.has_section(section_name + str(host_no)):
                host = dict(config_parser.items(section_name + str(host_no)))
                for field in mandatory_fields:
                    if field not in host:
                        raise Exception("Mandatory config field %s not found in section [HOST%s]" % (field, host_no))
                    if len(host[field]) == 0:
                        raise Exception("Mandatory config field %s has no VALUE in section [HOST%s]" % (field, host_no))

                if host["enabled"] == "True":
                    host["enabled"] = True
                elif host["enabled"] == "False":
                    host["enabled"] = False
                else:
                    raise Exception("[HOST%s] setting 'enabled' is invalid, must be True or False (case sensitive)" % (host_no))

                if host["ipmi_enabled"] == "True":
                    host["ipmi_enabled"] = True
                elif host["ipmi_enabled"] == "False":
                    host["ipmi_enabled"] = False
                else:
                    raise Exception("[HOST%s] setting 'ipmi_enabled' is invalid, must be True or False (case sensitive)" % (host_no))
                esxi_host = host["esxi_host"]
                self.hosts[esxi_host] = host
                host_no += 1

        else:
            raise Exception("Config file does not exist, cannot find " + self.config_path)



class WebManager:
    def __init__(self, fqdn):
        self.fqdn = fqdn

    def test_web_server(self, delay, attempts):
        url = "https://{}/ui/#/login".format(self.fqdn)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        result = None
        for count in range(attempts):
            try:
                result = requests.head(url, verify=False, timeout=5)

                ## If we get a valid response... great
                if result.status_code == 200:
                    logger.info("{} is NOW accessible, on attempt {}, total delay was {} seconds".format(url, count+1, count*delay))
                    logger.info("Allowing WebUI time to complete initialisation, delaying {} more seconds".format(delay))
                    time.sleep(delay)
                    return True

            ## An exception is going to happen everytime a request fails, such as timeout or rejected connection
            except requests.ConnectionError as e:
                logger.info("{} is not responding, please wait - attempt {} of {}, delaying {} seconds".format(url, count + 1, attempts, delay))
            finally:
                time.sleep(delay)

                ## If we're post exception, there will be no response, so nothing to do... else only log message if
                ## we didn't see a 200... this stop the message showing on function exit
                if result is not None:
                    if result.status_code != 200:
                        logger.info("{} is responding with HTTP {} - attempt {} of {}, delaying {} seconds".format(url, result.status_code, count + 1, attempts, delay))

                        result.close()

        return False




def do_power_on_vms(host_config):
    connection_mgr = ESXiConnectionManager(host_config["esxi_host"], host_config["esxi_username"],
                                           host_config["esxi_password"], host_config["esxi_webport"])
    host_mgr = ESXiHostManager()
    vm_mgr = ESXiVMManager()
    task_mgr = ESXiTaskManager()

    hosts = host_mgr.get_hosts(connection_mgr.get_content())

    ## Process and pause VMs
    vms = vm_mgr.get_vms(hosts)
    task_list = vm_mgr.unsuspend_vms()
    task_mgr.add_task_list(task_list)
    task_mgr.wait(True)
    task_mgr.clear()


def get_config_for_host(esxi_host):
    config = ConfigManager("conf/esxi-hosts.conf")
    config.read()

    if esxi_host not in config.hosts:
        raise Exception("Host '{}' not found in the esxi-hosts.conf".format(host))

    host_config = config.hosts[esxi_host]
    if host_config["enabled"] == False:
        raise Exception("Unable to perform action, host '{}' is DISABLED in the esxi-hosts.conf".format(esxi_host))

    return host_config

def get_power_status(esxi_host):
    logger.info("Loading config")
    host_config = get_config_for_host(esxi_host)

    if host_config["ipmi_enabled"] == True:
        ipmi = IPMIManager(host_config["ipmi_host"], host_config["ipmi_username"], host_config["ipmi_password"])
        result = ipmi.get_power_status()
        logger.info("Current power status is: " + ipmi.power_response_to_str(result))
        return ipmi.check_powered_on_result(result)


def do_shutdown(esxi_host):
    logger.info("Loading config")
    host_config = get_config_for_host(esxi_host)

    connection_mgr = ESXiConnectionManager(host_config["esxi_host"], host_config["esxi_username"], host_config["esxi_password"], host_config["esxi_webport"])
    host_mgr = ESXiHostManager()
    vm_mgr = ESXiVMManager()
    task_mgr = ESXiTaskManager()

    hosts = host_mgr.get_hosts(connection_mgr.get_content())
    vms = vm_mgr.get_vms(hosts)
    task_list = vm_mgr.suspend_vms()
    task_mgr.add_task_list(task_list)
    task_mgr.wait(True)
    task_mgr.clear()

    ## Process Host...
    task_list = host_mgr.shutdown_hosts(True)
    task_mgr.add_task_list(task_list)
    task_mgr.wait(True)


def do_poweron(esxi_host):
    logger.info("Loading config")
    host_config = get_config_for_host(esxi_host)

    ## IPMI Power On Blick
    if host_config["ipmi_enabled"] == True:
        logger.info("Sending IPMI power on to " + host_config["esxi_host"])
        ipmi = IPMIManager(host_config["ipmi_host"], host_config["ipmi_username"], host_config["ipmi_password"])
        result = ipmi.power_on()
        logger.info("IPMI result was " + ipmi.power_response_to_str(result))

        logger.info("Beginning checks for WebUI on " + host_config["esxi_host"])
        web_check = WebManager(host_config["esxi_host"])
        result = web_check.test_web_server(5, 100)

        if result == False:
            raise Exception("Unable to boot VMs, the WebUI on host '{}' did not respond in time!".format(esxi_host))
    ## End IPMI

    ## VM Power On Block
    do_power_on_vms(host_config)
    ## End VM



def main():
    parser = argparse.ArgumentParser("ESXi/BMC Power Manager")
    parser.add_argument("host", help="Name of the ESXi to perform operation on (must match esxi_host in the esxi-host.conf)", action="store")
    parser.add_argument("operation", choices=["up", "down", "status"], help="type of power operation to perform")
    parser.add_argument("-verbose", "--verbose", help="Output info and debug information, very useful for finding config problems", action='store_true')

    args = parser.parse_args()

    if args.verbose == True:
        logger.set_enabled(True)

    host = args.host
    operation = args.operation

    try:
        if operation == "up":
            logger.info("Received POWER UP for {}".format(host))
            do_poweron(host)
        elif operation == "down":
            logger.info("Received POWER DOWN for {}".format(host))
            do_shutdown(host)
        elif operation == "status":
            logger.info("Received POWER STATUS for {}".format(host))
            result = get_power_status(host)
            print(result)
    except Exception as e:
         logger.info("Exception: " + str(e))
         logger.info("Exception Trace: " + traceback.format_exc())
         print("Error: " + str(e))


if __name__ == "__main__":
    logger.setup()
    main()