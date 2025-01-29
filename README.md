---
meta:
    author(s): Mickaël DUBARD (www.opours.net) - AI assisted
    topic: CustomRBLIntegrator - Ipfire
---

# CustomRBLIntegrator - Ipfire

## Overview

CustomRBLIntegrator is a script developed by Mickaël DUBARD (www.opours.net) and adapted for Ipfire Firewall (www.ipfire.org).
The aim is to add the possibility of including Iptables rules for custom  real-time blackhole lists (RBLs) stored locally or imported via API, http or https. 
This script automate the process of downloading, updating, and enforcing network security policies based on RBLs and other IP blacklist sources. 
Its primary function is to ensure that firewall rules are continually updated to reflect the latest security intelligence, thereby protecting the network from potential threats identified by various blacklist providers.

## Features

- **Automated RBL Updates**: Download and process IP addresses and subnets from various RBL sources, including standard URLs, API URLs, and local files.

- **IPSET Management**: Integrate the updated blacklists into IPSET and ensure that the firewall rules are always up to date.

- **Duplicate IP Detection**: Detect and log duplicate IP addresses and subnets across different RBLs.

- **Error Handling**: Log errors and send email notifications if issues occur during execution.

- **IPTABLES Integration**: Ensure that IPTABLES rules are correctly set up to use the updated IPSET lists.

- **Concurrency Control**: Prevent multiple instances of the script from running simultaneously by using a PID file.

- **Detailed Logging**: Maintain a comprehensive log of all actions performed by the script.

## Prerequisites

- Bash (version 4.0 or higher)
- `ipset` tool
- `iptables` tool
- `Sendmail` tool

## Installation

**1.** Clone the repository:

__Example:__
Use Git command line
```bash
git clone https://github.com/opours/CustomRBLIntegrator__fw-Ipfire.git
```
or Wget and Unzip command line
``` bash
wget https://github.com/opours/CustomRBLIntegrator__fw-Ipfire/archive/refs/heads/main.zip && unzip main.zip
```

**2.** Navigate to the script directory:
```bash
mv CustomRBLIntegrator__fw-Ipfire-main /usr/local/bin/CustomRBLIntegrator
```

**3.** Ensure the script is executable:
```bash
chmod +x /usr/local/bin/CustomRBLIntegrator/CustomRBLIntegrator.sh
```

**4.** **Edit file CustomRBLIntegrator.conf** to enter the path(s) to your RBLs. See the file configuration section below


## Configuration
The script uses a configuration file (CustomRBLIntegrator.conf) to manage the various parameters. This file must be located in the same directory as the script. 
One or more slots must be configured.

  * STANDARD_URLS: http or https URLs type for RBL files path

or/and

  * API_URLS: Path to APIs for RBL files

or/and

  * LOCAL_RBL_FILES: Local path to RBL files



  * ADMIN_MAIL: leave this variable blank if if you do not wish to be notified of updates to the iptables rules (-i option only) and thus receive the log file by e-mail.

  * IPBLOCKLIST_CTRL:  Enable/disable Ipfire Ipblocklist files verification (0 or 1...1 by default)

  * FILL_GLOBAL_INFO_FILE: Enable/disable creation of global RBL information file (0 or 1...1 by default)

 
The script's other variables can be left as they are, or customized to suit your needs.

<u> **For IPFIRE environment**: 

**1)** So that the ipset list and iptables rules don't disappear when the firewall is modified by a third-party service, **you need to add the script with the "-c" option as below to /etc/sysconfig/firewall.local**.
Here's an example of a configured firewall.local file
</u>
``` bash
#!/bin/sh
#
# Log file path
LOG_FILE="/var/log/firewall_local.log"
USER=$(whoami)
#
# Log the user information
: > "${LOG_FILE}"
echo "+++++ firewall.local executed by user: $USER (UID: $UID) +++++" >> "$LOG_FILE"
date >> "$LOG_FILE"
echo ""

# See how we were called.
case "$1" in
  start)
        ## add your 'start' rules here
	# Starting the CustomRBLIntegrator script
	echo "   > Starting the CustomRBLIntegrator script. It may take a few minutes to complete..."
	echo "   > Starting the CustomRBLIntegrator script. It may take a few minutes to complete..." >> "$LOG_FILE"
	/bin/bash /usr/local/bin/CustomRBLIntegrator/CustomRBLIntegrator.sh -c >>"${LOG_FILE}" 2>&1
	;;
  stop)
        ## add your 'stop' rules here
        ;;
  reload)
        $0 stop
        $0 start
        ## add your 'reload' rules here
        ;;
  *)
        echo "Usage: $0 {start|stop|reload}"
        ;;
esac
```
**2)**
If you wish to receive an e-mail, **the /var/ipfire/dma/auth.conf file must be set to 644**, otherwise the script executed from /etc/sysconfig/firewall.local will have a problem sending mail via Sendmail.
``` bash
chmod 644 /var/ipfire/dma/auth.conf
```
## Usage
**5.** Run the script with the following options:

-c : Check for the presence of the customized ipset list. If the list does not exist, the -i option will be automatically applied.

-u : Update the RBLs list only.

-i : Implement IPs and subnetworks according to the existing referent list

-h : Display the help message.

<u>Example of a command line just to update the RBL list :</u>
```bash
    ./CustomRBLIntegrator.sh -u
```
<u> If you want to use Cron to set up an automatic check and update at a specific time, here's an example: </u>
    
    # Check custom RBLs, update reference file (-u) and update custom ipset list (-i) 
    30 20 * * *	/usr/local/bin/CustomRBLIntegrator/CustomRBLIntegrator.sh -ui >/dev/null 2>&1

### After execution
After execution, you can view the contents of Iptables to check that the rules have been added.
here are the rules that should be present into Iptables:

``` bash
iptables -L -n --line-numbers > /tmp/newiptables.save && cat /tmp/newiptables.save

...
...
...
Chain BLOCKLISTIN (2 references)
num  target     prot opt source               destination         
1    RETURN     0    --  10.0.0.0/8           0.0.0.0/0           
2    RETURN     0    --  172.16.0.0/12        0.0.0.0/0           
3    RETURN     0    --  192.168.0.0/16       0.0.0.0/0           
4    RETURN     0    --  100.64.0.0/10        0.0.0.0/0           
5    RETURN     0    --  224.0.0.0/4          0.0.0.0/0           
...
17   CUSTOMRBLIN  0    --  0.0.0.0/0            0.0.0.0/0            match-set CustomRBLIntegrator_V4 src

Chain BLOCKLISTOUT (2 references)
num  target     prot opt source               destination         
1    RETURN     0    --  0.0.0.0/0            10.0.0.0/8          
2    RETURN     0    --  0.0.0.0/0            172.16.0.0/12       
3    RETURN     0    --  0.0.0.0/0            192.168.0.0/16      
4    RETURN     0    --  0.0.0.0/0            100.64.0.0/10       
5    RETURN     0    --  0.0.0.0/0            224.0.0.0/4         
...
17   CUSTOMRBLOUT  0    --  0.0.0.0/0            0.0.0.0/0            match-set CustomRBLIntegrator_V4 dst
...
...
...
Chain CUSTOMRBLIN (1 references)
num  target     prot opt source               destination         
1    LOG        0    --  0.0.0.0/0            0.0.0.0/0            limit: avg 10/sec burst 5 LOG flags 0 level 4 prefix "CUSTRBLINTEGR_BLOCK: "
2    DROP       0    --  0.0.0.0/0            0.0.0.0/0           

Chain CUSTOMRBLOUT (1 references)
num  target     prot opt source               destination         
1    LOG        0    --  0.0.0.0/0            0.0.0.0/0            limit: avg 10/sec burst 5 LOG flags 0 level 4 prefix "CUSTRBLINTEGR_BLOCK: "
2    DROP       0    --  0.0.0.0/0            0.0.0.0/0           


```

and check also into Ipset:

``` bash
ipset list CustomRBLIntegrator_V4 > /tmp/customipsetlist.view
cat /tmp/customipsetlist.view | more

Name: CustomRBLIntegrator_V4
Type: hash:net
Revision: 7
Header: family inet hashsize 32768 maxelem 65536 bucketsize 12 initval 0xe25f8c5e
Size in memory: 1767504
References: 2
Number of entries: 57904
Members:
...
...
...
```
When a packet is intercepted by the custom RBL, it will appear in the firewall logs (/var/log/messages) as **"CUSTRBLINTEGR_BLOCK:"**.

## Main functions

`log_action`

    Logs an action message with a timestamp to the specified log file.

`log_error`

    Logs errors with a timestamp to the specified log file and sets an error flag.

`cleanup`

    Removes the PID file.

`send_mail`

    Sends an email notification if errors occurred during execution.

`count_ips_and_subnets`

    Counts the number of IP addresses and subnets in a given file.

`is_valid_ipv4`
    
    Checks if a given string is a valid IPv4 address.

`is_valid_ipv4_subnet`

    Checks if a given string is a valid IPv4 subnet.

`is_valid_ipv6`
    
    Checks if a given string is a valid IPv6 address.

`is_valid_ipv6_subnet`

    Checks if a given string is a valid IPv6 subnet.

`filter_erroneous_ips_subnets`
    
    Filters and saves erroneous IP addresses and subnets, logging errors and merging valid entries.

`update_rbl_list`

    Downloads and processes RBL data, updating the reference file and logging actions.

`add_iptables_child_rule`

    Ensures the existence of IPTABLES child chains and adds rules to them.

`add_iptables_parent_rule`

    Ensures the existence of IPTABLES parent chains and adds rules to them.

`check_update_iptables_rules`

    Checks and updates IPTABLES rules for inbound and outbound traffic.

`update_ipset`

    Updates the IPSET rules based on the reference file.

`implement_ips_from_file`

    Implements IPs from the reference file into the IPSET.

## Logging
All actions and errors are logged to the specified log file. You can configure the path to the log file in the configuration file (default in "/var/log/CustomRBLIntegrator_update.log")

## Concurrency Control
The script uses a PID file to prevent multiple instances from running simultaneously. If the PID file is older than 4 hours (configurable), it is deleted, and a new one is created.

## License
This script is provided under the GPL v3 license WITHOUT ANY WARRANTY. It is free to use, modify, and redistribute as long as you mention the original author and adhere to the terms of the GPL v3 license. For more details, visit: GPL v3 License.

## Author
Mickaël DUBARD (www.opours.net)

For any questions or support, please contact the author.
    
