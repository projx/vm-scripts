# VM Scripts

This repository contain the python script(s) I use for managing my homelab and IOT bits. 

The main focus I have is power saving, whilst I love gadgets, I hate huge electric bills. 

##Scripts
###vm-power-mgr.py

Is a shell script for powering up and down Dell PowerEdge servers running ESXi (must have a iDRAC Enterprise), it 
uses the VMWare vSphere API to pause VMs and shutdown the host, it can power the server on using IPMI to connect to the 
host iDRAC (this should also with iLO and other BMC's)


####Usage:

vm-power-mgr.py \<HOST\> \<UP/DOWN/STATUS> \<optional flags\>

Optional Flags:
* `-v` gives verbose information about  progress (very useful for checking details) 

**Note** `HOST` **must match** the IP/FQDN specified in the esxi_host field of the config (see below)

###### Examples
* Suspend VM's and shutdown the host - `vm-power-mgr.py 192.168.11.21 down`
* Power up the host and resume suspended VMs - `vm-power-mgr.py 192.168.11.21 up`
* Get current status - `vm-power-mgr.py 192.168.11.21 status`
* For detailed output use -v - `vm-power-mgr.py 192.168.11.21 up -v` 

#####Requirements:

* Python 3.x (I developed this using 3.7, it should with with 3.5, 3.6 etc but its not tested)
* ipmitools (Usually available as with standard distro installer, i.e. apt install ipmitool)

Though not essential, I recommend you install this in a python virtualenv for testing.

#####Installation:
This script uses the ipmitools to connect to the hosts iDRAC/iLO/BMC to control power, 
and the python pyVMomi library for connecting
* `apt install ipmitool`
* `pip3 install pyvmomi`

Clone the example config file

* `cp conf/esxi-host.conf.example conf/esxi-host.conf`

Now edit `conf/esxi-hosts.conf` file, read the comments at the top for detailed info, but as a quick 
summary, you create a seperate section for each host, i.e. [HOST1] and [HOST2]. If you intend to use
the script, then I'd recommend creating dedicated ESXi and iDRAC users, but for testing, just use the ones you 
log into the ESXi and iDRAC Web UIs:


```
[HOST1]
enabled=True
esxi_host=192.168.1.5
esxi_webport=443
esxi_username=root
esxi_password=<user password>
ipmi_enabled=True
ipmi_vm_poweron_delay=330
ipmi_host=192.168.1.6 (iDRAC IP/FQDN)
ipmi_username=root
ipmi_password=calvin

[HOST2]
enabled=True
esxi_host=192.168.1.7
esxi_webport=443
esxi_username=root
esxi_password=<user password>
ipmi_enabled=True
ipmi_vm_poweron_delay=330
ipmi_host=192.168.1.8 (iDRAC IP/FQDN)
ipmi_username=root
ipmi_password=calvin
```



