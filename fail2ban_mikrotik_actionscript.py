#!/usr/local/bin/python3

import os,sys,paramiko,logging,httpx,json,asyncio,ipaddress
from datetime import datetime
from pathlib import Path

SCRIPT_NAME = os.path.splitext(os.path.basename(__file__))[0]
SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_FILE = os.path.join(SCRIPT_DIR,SCRIPT_NAME+".config")
TELEGRAM_TOKEN = TELEGRAM_CHATID = LOG_FILE = SSHKEY = SSHKEYTYPE = SSHPORT = SSHKEYPASS = SSHUSERNAME = FIREWALLADDRLISTv4 = FIREWALLADDRLISTv6 = ""
SSHPORT = 0

os.chdir(SCRIPT_DIR)

def generate_default_config():
    config =  {
        "telegramToken": "",
        "telegramChat": "",
        "logFile": f"{SCRIPT_NAME}.log",
        "sshKey": "fail2ban.key",
        "sshKeyType": "ED25519",
        "sshKeyPass": "-",
        "sshPort": 22,
        "sshUserName": "fail2ban",
        "FirewallAddressListv4": "ban-list",
        "FirewallAddressListv6": "ban-list"
    }
    with open(CONFIG_FILE, 'w',encoding='utf8') as file:
        json.dump(config, file, indent=4)
    os.chmod(CONFIG_FILE, 0o600)
    print(f"First launch. New config file {CONFIG_FILE} generated and needs to be configured.")
    quit()

def load_config():
    success = 0
    global TELEGRAM_TOKEN, TELEGRAM_CHATID, LOG_FILE, SSHKEY, SSHKEYTYPE, SSHKEYPASS, SSHPORT, SSHUSERNAME, FIREWALLADDRLISTv4, FIREWALLADDRLISTv6
    """
    Check if config file exists. If not - generate the new one.
    """
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r',encoding='utf8') as file:
            config = json.load(file)
        for id,key in enumerate(config.keys()):
            if (key in ["logFile", "sshKey", "sshPort", "sshUserName", "FirewallAddressList"]):
                if config.get(key) in [None, "", "None"]:
                    print(f"Important parameter of {key} is not defined! Can't proceed")
                    exit(1)
                else:
                    success += 1               
        if success != 5:
            print(f"Some variables are not set in config file. Please fix it then run the program again.")
            exit(1)
        TELEGRAM_TOKEN = config.get('telegramToken').strip()
        TELEGRAM_CHATID = config.get('telegramChat').strip()
        LOG_FILE = config.get('logFile').strip()
        SSHKEY = config.get('sshKey').strip()
        SSHKEYTYPE = config.get('sshKeyType').strip()
        SSHKEYPASS = config.get('sshKeyPass').strip()
        SSHPORT = config.get('sshPort')
        SSHUSERNAME = config.get('sshUserName').strip()
        FIREWALLADDRLISTv4 = config.get('FirewallAddressListv4').strip()
        FIREWALLADDRLISTv6 = config.get('FirewallAddressListv6').strip()
        logging.basicConfig(filename=LOG_FILE,level=logging.INFO,format='%(asctime)s - Fail2ban-Mikrotik - %(levelname)s - %(message)s',datefmt='%d-%m-%Y %H:%M:%S')
    else:
        generate_default_config()

async def send_to_telegram(message: str, subject: str = f"{SCRIPT_NAME}:", ) -> None:
    """
    Sends messages via Telegram if TELEGRAM_CHATID and TELEGRAM_TOKEN are both set. Requires "message" parameters and can accept "subject"
    """
    global TELEGRAM_CHATID, TELEGRAM_TOKEN
    if TELEGRAM_CHATID and TELEGRAM_TOKEN:
        headers = {
            'Content-Type': 'application/json',
        }
        data = {
            "chat_id": f"{TELEGRAM_CHATID}",
            "text": f"{subject}\n{message}",
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                    headers=headers,
                    json=data
                )
            print(response.status_code)
            if response.status_code != 200:
                logging.error("error", f"Telegram bot error! Status: {response.status_code} Body: {response.text}")
        except Exception as err:
            logging.error(f"Error while sending message to Telegram: {err}")
    else:
        logging.error("Send-To-Telegram function was called, but TELEGRAM_CHATID or TELEGRAM_TOKEN is not set!")

def ip_version(addr: str) -> str | None:
    """
    Returns a type of an IP address - V4 or V6, or None
    """
    try:
        ip = ipaddress.ip_address(addr)
        return "IPv4" if ip.version == 4 else "IPv6"
    except ValueError:
        return None

def banip(deviceIp: str, banIp: str, service: str)->None:
    """
    Ban function - bans given IP using SSH connection to Mikrotik device
    """
    logging.info("-----------------------------Starting BanIP------------------------------------------")
    global FIREWALLADDRLISTv4, FIREWALLADDRLISTv6, SSHKEYPASS, SSHKEYTYPE, SSHPORT, SSHUSERNAME
    try:
        if (SSHKEYTYPE == "ED25519"):
            if (SSHKEYPASS != "-"):
                KEY = paramiko.Ed25519Key.from_private_key_file(SSHKEY,password=SSHKEYPASS)
            else:
                KEY = paramiko.Ed25519Key.from_private_key_file(SSHKEY)
        elif (SSHKEYTYPE == "RSA"):
            if (SSHKEYPASS != "-"):
                KEY = paramiko.RSAKey.from_private_key_file(SSHKEY,password=SSHKEYPASS)
            else:
                KEY = paramiko.RSAKey.from_private_key_file(SSHKEY)
        logging.info(f"Preparing connection: Device={deviceIp} Port={SSHPORT} Username={SSHUSERNAME} KeyPath={SSHKEY} KeyType={SSHKEYTYPE}")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        """Check of banIP address correct syntax and its type"""
        if ip_version(banIp) == "IPv4":
            COMMAND=f"/ip/firewall/address-list/add list={FIREWALLADDRLISTv4} address={banIp} comment=\"Fail2ban: {service} {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\""
            logging.info("banIP has a type of IPv4")
        elif ip_version(banIp) == "IPv6":
            COMMAND=f"/ipv6/firewall/address-list/add list={FIREWALLADDRLISTv6} address={banIp} comment=\"Fail2ban: {service} {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\""
            logging.info("banIP has a type of IPv6")
        elif ip_version(banIp) == None:
            logging.error(f"Base check error! banIP(value:{banIp}) has wrong syntax or type, or any other error.")
            asyncio.run(send_to_telegram(f"Base check error! banIP(value:{banIp}) has wrong syntax or type, or any other error.","🚨Pre-check error :"))
            exit(1)
        """Check of deviceIP address correct syntax"""
        if ip_version(deviceIp) == None:
            logging.error(f"Base check error! deviceIP(value:{deviceIp}) has wrong syntax or type, or any other error.")
            asyncio.run(send_to_telegram(f"Base check error! deviceIP(value:{deviceIp}) has wrong syntax or type, or any other error.","🚨Pre-check error :"))
            exit(1)
        ssh.connect(hostname=deviceIp, port=int(SSHPORT), username=SSHUSERNAME, pkey=KEY, timeout=5)
        stdin, stdout, stderr = ssh.exec_command(COMMAND)
        output = stdout.read().decode()
        error  = stderr.read().decode()
        if error:
            logging.error(f"STDERR: {error}")
            asyncio.run(send_to_telegram(f"Device={deviceIp}. AddressList={FIREWALLADDRLISTv4} or {FIREWALLADDRLISTv6}. BanIP={banIp}.\n{output.strip()}!","⚠Error while adding to ban list:"))
            logging.info("-----------------------------Finished BanIP with error------------------------------------------")
            exit()
        if (len(output) > 0):
            logging.info(f"STDOUT: {output}")
            asyncio.run(send_to_telegram(f"Device={deviceIp}. AddressList={FIREWALLADDRLISTv4} or {FIREWALLADDRLISTv6}. BanIP={banIp}.\n{output.strip()}!","⚠Possible error while adding to ban list:"))
            logging.info("-----------------------------Finished BanIP with error------------------------------------------")
            exit()
        asyncio.run(send_to_telegram(f"Device={deviceIp}. AddressList={FIREWALLADDRLISTv4} or {FIREWALLADDRLISTv6}.\nAttackerIP={banIp} Service={service}!","🎣Attacker has been banned:"))
        logging.info(f"Done: {COMMAND} Service={service}")
    finally:
        ssh.close()
        logging.info("-----------------------------Finished BanIP------------------------------------------")

def unbanip(deviceIp: str, unbanIp: str)->None:
    """
    UnBan function - unbans given IP using SSH connection to Mikrotik device
    """
    logging.info("-----------------------------Starting UnbanIP------------------------------------------")
    global FIREWALLADDRLISTv4, FIREWALLADDRLISTv6, SSHKEYPASS, SSHKEYTYPE, SSHPORT, SSHUSERNAME
    try:
        if (SSHKEYTYPE == "ED25519"):
            if (SSHKEYPASS != "-"):
                KEY = paramiko.Ed25519Key.from_private_key_file(SSHKEY,password=SSHKEYPASS)
            else:
                KEY = paramiko.Ed25519Key.from_private_key_file(SSHKEY)
        elif (SSHKEYTYPE == "RSA"):
            if (SSHKEYPASS != "-"):
                KEY = paramiko.RSAKey.from_private_key_file(SSHKEY,password=SSHKEYPASS)
            else:
                KEY = paramiko.RSAKey.from_private_key_file(SSHKEY)
        logging.info(f"Preparing connection: Device={deviceIp} Port={SSHPORT} Username={SSHUSERNAME} KeyPath={SSHKEY} KeyType={SSHKEYTYPE}")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        """Check of unbanIP address correct syntax and its type"""
        if ip_version(unbanIp) == "IPv4":
            COMMAND=f"/ip/firewall/address-list/remove [find address={unbanIp} and list={FIREWALLADDRLISTv4}]"
            logging.info("unbanIP has a type of IPv4")
        elif ip_version(unbanIp) == "IPv6":
            COMMAND=f"/ipv6/firewall/address-list/remove [find address={unbanIp} and list={FIREWALLADDRLISTv6}]"
            logging.info("unbanIP has a type of IPv6")
        elif ip_version(unbanIp) == None:
            logging.error(f"Base check error! unbanIP(value:{unbanIp}) has wrong syntax or type, or any other error.")
            asyncio.run(send_to_telegram(f"Base check error! unbanIP(value:{unbanIp}) has wrong syntax or type, or any other error.","🚨Pre-check error :"))
            exit(1)
        """Check of deviceIP address correct syntax"""
        if ip_version(deviceIp) == None:
            logging.error(f"Base check error! deviceIP(value:{deviceIp}) has wrong syntax or type, or any other error.")
            asyncio.run(send_to_telegram(f"Base check error! deviceIP(value:{deviceIp}) has wrong syntax or type, or any other error.","🚨Pre-check error :"))
            exit(1)
        ssh.connect(hostname=deviceIp, port=int(SSHPORT), username=SSHUSERNAME, pkey=KEY, timeout=5)
        stdin, stdout, stderr = ssh.exec_command(COMMAND)
        output = stdout.read().decode()
        error  = stderr.read().decode()
        if error:
            logging.error(f"STDERR: {error}")
            asyncio.run(send_to_telegram(f"Device={deviceIp}. AddressList={FIREWALLADDRLISTv4} or {FIREWALLADDRLISTv6}. UnbanIP={unbanIp}.\n{output.strip()}!","⚠Error while removing from ban list:"))
            logging.info("-----------------------------Finished BanIP with error------------------------------------------")
            exit()
        if (len(output) > 0):
            logging.info(f"STDOUT: {output}")
            asyncio.run(send_to_telegram(f"Device={deviceIp}. AddressList={FIREWALLADDRLISTv4} or {FIREWALLADDRLISTv6}. UnbanIP={unbanIp}.\n{output.strip()}!","⚠Possible error while removing from ban list:"))
            logging.info("-----------------------------Finished BanIP with error------------------------------------------")
            exit()
        asyncio.run(send_to_telegram(f"Device={deviceIp}. AddressList={FIREWALLADDRLISTv4} or {FIREWALLADDRLISTv6}.\nUnbanIP={unbanIp}!","☮Attacker IP has been unbanned:"))
        logging.info(f"Done: {COMMAND}")
    finally:
        ssh.close()
        logging.info("-----------------------------Finished BanIP------------------------------------------")

if __name__ == "__main__":
    load_config()
    if len(sys.argv) >= 3:
        if sys.argv[1] == "banip":
            if (sys.argv[2] and sys.argv[3] and sys.argv[4]):
                """<device_ip> <ban_ip> <service>"""
                banip(sys.argv[2], sys.argv[3], sys.argv[4])
            else:
                print("BanIP error: no IP provided!")
        elif sys.argv[1] == "unbanip":
            if (sys.argv[2] and sys.argv[3]):
                """<device_ip> <unban_ip>"""
                unbanip(sys.argv[2], sys.argv[3])
            else:
                print("UnbanIP error: no IP provided!")
    else:
        """exit with error code when insufficient parameters given"""
        print("Insufficient parameters given...")
        exit(1)
#script.py <action> <mikrotik-device-ip> <ban-ip> <service>
#script.py banip 192.168.20.1 214.132.12.189 vpn
