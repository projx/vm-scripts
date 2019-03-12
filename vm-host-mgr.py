from pyvim import connect, task
from pyVmomi import vim
from tools import cli
from tools import tasks
from pprint import pprint
from numbers import Number

import atexit
import time
import requests
import ssl
import configparser
import os
import subprocess
import argparse

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
                pprint(task.info)
        else:
            print("No tasks..")

    def _progress_output(self, task, progress):
        if progress is None:
            return
        try:
            progess = str(progress)

            if "error" in progress:
                return  ## Just return at this point.. the exception handler in waitX() will deal with this

            if progress.isdigit():
                progress = progress + "%"

            print("{} on {}, progress is {}".format(task.info.descriptionId, task.info.entityName, progress))
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
                print("Houston, we have a problem: " + e.msg)

"""
Manages the connection to ESXi/vCenter hosts, including the accessing the server-instance and data contents
"""
class ESXiConnectionManager:
    def __init__(self, svr, usr, pss, prt, ssl_verify=False):
        self.server_instance = None

        ## pyvMomi library expects a trusted cert from the ESXi/vCenter server.. need to allow self-generated certs
        if ssl_verify == False:
            self._disable_ssl_verify()

        try:
            self.server_instance = connect.SmartConnect(host=svr, user=usr, pwd=pss, port=prt)
            atexit.register(connect.Disconnect, self.server_instance)

        except IOError as ex:
            raise SystemExit("unable to connect to vCenter / ESXi host..")

    def _disable_ssl_verify(self):
        requests.packages.urllib3.disable_warnings()
        try:
            _create_unverified_https_context = ssl._create_unverified_context
        except AttributeError:
            print("Error disabling SSL Verification")
            pass
        else:
            ssl._create_default_https_context = _create_unverified_https_context

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

        ## Here we keep a class-local reference to the hosts, filtering for specific hosts if defined
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
            print(key)
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
                print(vm.name)
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
            if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                note_task = self.set_note(vm, "SCHEDULED_SUSPEND")
                task.WaitForTask(note_task)
                vm_task = vm.SuspendVM_Task()
                task_list.append(vm_task)
                # tasks.append(note_task)

        return task_list

    def unsuspend_vms(self):
        task_list = list()
        for key, vm in self.vms.items():
            print(key + " is " + vm.runtime.powerState)
            if vm.runtime.powerState == vim.VirtualMachinePowerState.suspended:
                note_task = self.set_note(vm, "SCHEDULED_UNSUSPEND")
                task.WaitForTask(note_task)
                vm_task = vm.PowerOnVM_Task()
                task_list.append(vm_task)

        return task_list

"""
IPMI access by making subsystem calls the ipmitools executable 
"""
class IPMIManager:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password

    def power_on(self):
        try:
            cmd = "ipmitool -I lanplus -H {} -U {} -P {} chassis power on".format(self.host, self.username,
                                                                                  self.password)
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            raise Exception("Unable to cleanup old audit logs, the following error occured: " + e.output)

"""
A utility for loading the config file, extracting the user-defined settings, and ensuring that mandatory values are present

"""
class ConfigManager:
    def __init__(self, path):
        """
        Initiate the class, reset all values to default..
        """
        self.config_path = path
        self.hosts = []

    def read(self):
        mandatory_fields = ["enabled", "esxi_host", "esxi_username", "esxi_password", "ipmi_enabled"]

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
                    raise Exception(
                        "[HOST%s] setting 'enabled' is invalid, must be True or False (case sensitive)" % (host_no))

                if host["ipmi_enabled"] == "True":
                    host["ipmi_enabled"] = True
                elif host["ipmi_enabled"] == "False":
                    host["ipmi_enabled"] = False
                else:
                    raise Exception(
                        "[HOST%s] setting 'ipmi_enabled' is invalid, must be True or False (case sensitive)" % (
                            host_no))

                self.hosts.append(host)
                host_no += 1

        else:
            raise Exception("Config file does not exist, cannot find " + self.config_path)


def get_config_for_hosts():
    config = ConfigManager("conf/esxi-hosts.conf")
    config.read()
    return config.hosts


def do_shutdown(hosts):
    ## Setup connection and get our content provider...
    for host in hosts:
        if host["enabled"] == True:
            connection_mgr = ESXiConnectionManager(host["esxi_host"], host["esxi_username"], host["esxi_password"], 443)
            host_mgr = ESXiHostManager()
            vm_mgr = ESXiVMManager()
            task_mgr = ESXiTaskManager()

            hosts = host_mgr.get_hosts(connection_mgr.get_content())

            ## Process and pause VMs
            vms = vm_mgr.get_vms(hosts)
            task_list = vm_mgr.suspend_vms()
            task_mgr.add_task_list(task_list)
            task_mgr.wait(True)
            task_mgr.clear()

            ## Process Host...
            task_list = host_mgr.shutdown_hosts(True)
            task_mgr.add_task_list(task_list)
            task_mgr.wait(True)

def do_poweron(hosts):

    boot_delay = 0

    ## Boot hosts via IPMI
    for host in hosts:
        if host["enabled"] == True:
            if host["ipmi_enabled"] == True:
                print("powering on " + host["esxi_host"])
                ipmi = IPMIManager(host["ipmi_host"], host["ipmi_username"], host["ipmi_password"])
                ipmi.power_on()

                ## Figure which host had the biggest boot delay.. then clone it
                if int(host["ipmi_vm_poweron_delay"]) > boot_delay:
                    boot_delay = int(host["ipmi_vm_poweron_delay"])

    ## if IPMI was used, then we use the boot delay...
    # @todo: replace this with a check for HTTPS connection..
    print("Allowing {} seconds to boot hosts, before starting VMs".format(boot_delay))
    time.sleep(boot_delay)

    ## Boot VMs
    for host in hosts:
        if host["enabled"] == True:

            connection_mgr = ESXiConnectionManager(host["esxi_host"], host["esxi_username"], host["esxi_password"], 443)
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--up", help="Power up the ESXi Hosts and their VMs", action="store_true")
    parser.add_argument("-d", "--down", help="Suspend VMs and power down the Hosts", action="store_true")
    args = parser.parse_args()
    if args.up:
        hosts = get_config_for_hosts()
        do_poweron(hosts)
    elif args.down:
        hosts = get_config_for_hosts()
        do_shutdown(hosts)
    else:
        print("No valid arguments, use -h for help!")

if __name__ == "__main__":
    main()