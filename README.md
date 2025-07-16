
# Fail2ban-Mikrotik Actionscript

This is a simple script which allows to use any Linux server with Fail2ban + Rsyslog installed on it. Rsyslog needs to grab logs from Mikrotik devices and store to regular text log file. Fail2ban also needs to parse these logs and do some actions.  

## Rsyslog simple setup(old way. sure thing now rsyslog is being removed from modern Debian and Ubuntu distros. But who cares...)

In this example, every log entry contains router's name 'router.lan', so we are catching records from this device using its description and store to its own log file  
Create a file with any name and ".conf" extension in /etc/rsyslog.d/. Let it be /etc/rsyslog.d/router.lan.conf:
```
if $fromhost contains 'router.lan' then {
  *.* action(type="omfile" file="/var/log/mikrotik/router.lan.log")
  &stop
}
```
Restart Rsyslog service and now all log records from the router gonna be captured and saved to the log file.  

## Mikrotik setup(you know it,right?):

Just add remote logging settings to your Mikrotik device(replace remote= with your own ip or FQDN of your server):
```
/system logging action add name=remote-server remote=10.254.254.1 target=remote
/system logging
add action=remote-server prefix=router.lan topics=info
add action=remote-server prefix=router.lan topics=critical
add action=remote-server prefix=router.lan topics=warning
add action=remote-server prefix=router.lan topics=error
```

## Fail2ban setup(the most interesting,beleive me):

Here we gonna use one example for IPSEC + L2TP VPN, but you can change your config files in that way to create another services for fail2ban.  
  
### Step 1:  
Create a record of jail in /etc/fail2ban/jail.local(feel free to change these simple variables to your own values):
```
[mikrotik-ipsec-l2tp]
enabled = true
logpath = /var/log/mikrotik/router.lan.log
action_  = mikrotik-ipsec-l2tp
findtime  = 1m
maxretry = 5
```
Also, you need to generate an SSH key on your server to use it for SSH access to your Mikrotik device:  
```
ssh-keygen -t ed25519
```
chose any name and path to save you want, futher this name and path should be set in script config. file.  
Than, create a user on your Mikrotik device and add a public key for it:
```
/user/group add name=fail2ban policy=ssh,read,write,!local,!telnet,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!api,!romon,!rest-api
/user/add name=fail2ban group=fail2ban
```
After that, you need to upload a public key you have just generated (id_ed25519.pub for example) to the Mikrotik, then import it as a user's public key:  
```
/user/ssh-keys/import public-key-file=id_ed25519.pub user=fail2ban
```
And do not forget to create some ban rule in Mikrotik's Firewall which will use an address list with the name you need to set in Mikrotik and then in script's config. file.  
  
### Step 2:  
Create a record of filter rule in /etc/fail2ban/filter.d/mikrotik-ipsec-l2tp.conf.These 3x lines catch connection attempts of proto UDP and prots 1701,4500,500 - they are exactly "VPN ports".
```
[Definition]
failregex = ^(.*)connection-state:new(.*)proto UDP, <HOST>:(.*)->(.*):1701(.*)$
            ^(.*)connection-state:new(.*)proto UDP, <HOST>:(.*)->(.*):4500(.*)$
            ^(.*)connection-state:new(.*)proto UDP, <HOST>:(.*)->(.*):500(.*)$
```
  
### Step 3:  
Create a record of action rule in /etc/fail2ban/action.d/mikrotik-ipsec-l2tp.conf.  
Syntax of "actionban" is "script_name" "action" "mikrotik_device_ip_or_fqdn" "ip" "service_name" where:  
"script_name" - full path to the script  
"action" - can be "banip" or "unbanip"  
"mikrotik_device_ip_or_fqdn" - IP address or FQDN name of Mikrotik device, where an attacker IP shoud be banned  
"ip" - don't change it, it is a variable from fail2ban, where an IP of attacker is set  
"service_name" - just a readable name of a service, to understand why an IP was blocked. Used in comment for Mikrotik's address list.  
```
[Definition]
actionban   = /etc/fail2ban/Fail2ban-Mikrotik/fail2ban_mikrotik_actionscript.py banip router.lan <ip> VPN
actionunban = /etc/fail2ban/Fail2ban-Mikrotik/fail2ban_mikrotik_actionscript.py unbanip router.lan <ip>
actioncheck =
actionstart =
actionstop =
```
Here I assume that my actionscript located directly inside /etc/fail2ban/ folder(the folder Fail2ban-Mikrotik). If in any other place - just fix script path in config above.  

## Main action script pre-setup:

At first launch of my script, it will generate simple JSON config inside its directory. You need to check these few settings in there:  
"telegramToken" - Telegram token to access to bot. Can be empty  
"telegramChat"  - Telegram chat to access to bot. Can be empty  
"logFile" - log file name and absolute path. Default inside working directory of the script.  
"sshKey" - ssh key name and path. Needs to be generated and added to your Mikrotik device to use SSH connection.  
"sshKeyType" - type of your key. Can be "ED25519" or "RSA". "ED25519" is better for sure.  
"sshKeyPass" - set key's password if the key is password protected, or "-" when there is no password.  
"sshPort" - set SSH port of your Mikrotk device. Default is 22.  
"sshUserName" - username for SSH connection.  
"FirewallAddressListv4" - name of address list for attackers ban for ipv4 firewall in your Mikrotik device.  
"FirewallAddressListv6" - name of address list for attackers ban for ipv6 firewall in your Mikrotik device.  

## The final:

Now everything should work:

1. Mikrotik sends all copies of log records to your server.
2. Rsyslog gathers logs and stores them to a file(s).
3. Fail2ban parses the logs using jail configs from /etc/fail2ban/jail.local
4. A jail from /etc/fail2ban/jail.local setup parsing rules via /etc/fail2ban/filter.d/_jail-name_.conf
5. The jail does actions for the parsed lines using action from /etc/fail2ban/action.d/_action-name_.conf
6. The action uses my script to do actions - ban or unban of IPs.
7. My script uses its config file to get information how to get into some device via SSH and sends commands to add or removed IPs to/from address lists.
