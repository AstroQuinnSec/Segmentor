from fabric import Connection
from invoke import Responder
import argparse
from multiprocessing import Process, current_process
from multiprocessing import log_to_stderr, get_logger
import logging
from getpass import getpass

def run_test(host, password):

	c = Connection(host, connect_kwargs = {"password": password})

	c.run('ip addr')

def run_scan(host, scope):

	password = input(f'please enter the password for {host}: ')

	run_connect(host, password,scope)


def run_connect(host, password, scope):

	c = Connection(host, connect_kwargs = {"password": password})

	process_name = current_process().name

	print(f'{host} connected on {process_name}\n')

	name = host.split("@")[0]

	sudopass= Responder(pattern = r'\[sudo\] password for ' + name + ': ', response = f'{password}\n',) #automatically use sudo with passsword when prompted

	c.put(scope, remote = f"/tmp/{scope}") #place scope file on remote server

	cmd = c.run('ip route | grep dev | grep -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}"', warn = True, hide = True) #get subnet from remote

	subnet = cmd.stdout.rstrip()

	grepnet = subnet.split("/")[0]

	c.run(f'sed -i "/{grepnet}/d" /tmp/{scope}') #remove it from the scope

	subnet = subnet.replace(".","_") #Formatting for nmap output

	subnet = subnet.replace("/","_") #same as last cmd

	print(f'Scope added for {host} running nmap scan....\n')

	c.run(f'sudo nmap -iL /tmp/{scope} --privileged -n -PE PS21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 -PU53,67-69,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,5353,49152 -sS -sU -p T:1-65535,U:53,67,123,137,161,407,500,523,623,1434,1604,1900,2302,2362,3478,3671,4800,5353,5683,6481,17185,31337,44818,47808  -T4 --open --stats-every 10s -g 88 -oN /tmp/{subnet}',watchers=[sudopass], pty=True, hide=True)

	c.get(f'/tmp/{subnet}') #obtaing the nmap scan results

	print(f'scan for {host} complete\n')


def get_scan_results(host,password):

	c = Connection(host, connect_kwargs = {"password": password})

	process_name = current_process().name

	print(f'{host} connected on {process_name}\n')

	name = host.split("@")[0]

	sudopass= Responder(pattern = r'\[sudo\] password for ' + name + ': ', response = f'{password}\n',) #automatically use sudo with passsword when prompted

	cmd = c.run ('sudo tmux ls', watchers=[sudopass], pty = True, warn = True, hide = True)

	t_sesh = cmd.stdout.rstrip()

	session = "session1"

	if t_sesh.find(session) != -1:

		print(f"Nmap scan not complete for {host}\n")

	else:

		cmd = c.run('ip route | grep dev | grep -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}"', warn = True, hide = True)

		subnet = cmd.stdout.rstrip()

		subnet = subnet.replace(".","_")

		subnet = subnet.replace("/","_")	

		c.get(f'/tmp/{subnet}')

		print(f'Obtained scan results for {host}\n')

def run_background(host, password, scope):

	c = Connection(host, connect_kwargs = {"password": password})

	process_name = current_process().name

	print(f'{host} connected on {process_name}\n')

	name = host.split("@")[0]

	sudopass= Responder(pattern = r'\[sudo\] password for ' + name + ': ', response = f'{password}\n',) #automatically use sudo with passsword when prompted

	c.put(scope, remote = f"/tmp/{scope}") #place scope file on remote server

	cmd = c.run('ip route | grep dev | grep -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}"', warn = True, hide = True) #get subnet from remote

	subnet = cmd.stdout.rstrip()

	grepnet = subnet.split("/")[0]

	c.run(f'sed -i "/{grepnet}/d" /tmp/{scope}') #remove it from the scope

	subnet = subnet.replace(".","_") #Formatting for nmap output

	subnet = subnet.replace("/","_") #same as last cmd

	print(f'Scope added for {host} running nmap scan....\n')

	c.run(f'sudo tmux new -d -s session1 "sudo nmap -iL /tmp/{scope} --privileged -n -PE PS21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 -PU53,67-69,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,5353,49152 -sS -sU -p T:1-65535,U:53,67,123,137,161,407,500,523,623,1434,1604,1900,2302,2362,3478,3671,4800,5353,5683,6481,17185,31337,44818,47808  -T4 --open --stats-every 10s -g 88 -oN /tmp/{subnet} "', pty=True, watchers=[sudopass], hide=True)

	#c.get(f'/tmp/{subnet}') #obtaing the nmap scan results

	print(f'nmap running in backround for {host}\n')

def group_scan(H_file, scope):
	processes = []
	passwords = []
	count = 0
	with open(H_file) as f:
		hosts = f.read().splitlines()

	length = len(hosts)

	for x in range(length):
		password = getpass(f'please enter the password for {hosts[x]}: ')
		passwords.append(password)

	log_to_stderr()
	logger = get_logger()
	logger.setLevel(logging.INFO)

	for x in range(length):
		process = Process(target=run_connect, args=(hosts[x],passwords[x],scope))
		processes.append(process)

		process.start()
def group_get_results(H_file):
	processes = []
	passwords = []
	count = 0
	with open(H_file) as f:
		hosts = f.read().splitlines()

	length = len(hosts)

	for x in range(length):
		password = getpass(f'please enter the password for {hosts[x]}: ')
		passwords.append(password)

	log_to_stderr()
	logger = get_logger()
	logger.setLevel(logging.INFO)

	for x in range(length):
		process = Process(target=get_scan_results, args=(hosts[x],passwords[x]))
		processes.append(process)

		process.start()

def group_background(H_file, scope):
	processes = []
	passwords = []
	count = 0
	with open(H_file) as f:
		hosts = f.read().splitlines()

	length = len(hosts)

	for x in range(length):
		password = getpass(f'please enter the password for {hosts[x]}: ')
		passwords.append(password)

	log_to_stderr()
	logger = get_logger()
	logger.setLevel(logging.INFO)

	for x in range(length):
		process = Process(target=run_background, args=(hosts[x],passwords[x],scope))
		processes.append(process)

		process.start()

def group_test(H_file):
	processes= []
	passwords = []
	count = 0
	with open(H_file) as f:
		hosts = f.read().splitlines()

	length = len(hosts)

	for x in range(length):
		password = getpass(f'please enter the password for {hosts[x]}: ')
		passwords.append(password)

	log_to_stderr()
	logger = get_logger()
	logger.setLevel(logging.INFO)

	for x in range(length):
		process = Process(target=run_test, args=(hosts[x],passwords[x]))
		processes.append(process)

		process.start()


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='automate segmentation tests on a list of hosts or a single host')
	group1 = parser.add_mutually_exclusive_group()
	group1.add_argument('-l', dest='host_list' ,type=str, help='.txt file with a list of hosts to execute on')
	group1.add_argument('-i',dest='host', type=str, help='enter a single host to execute commands on(e.g. admin@127.0.01)')
	parser.add_argument('-s',dest='scope', type=str, help='scope file with list of hosts to scan')
	
	group = parser.add_mutually_exclusive_group()
	group.add_argument('-t', '--test', action='store_true',dest ='test',help ='test to just run whoami. Include host list e.g. -l hosts.txt -t')
	group.add_argument('-g', '--get', dest='get', action='store_true', help='Grabs the scan results from the lists of hosts if the tmux session is complete. include hosts list e.g. -hosts.txt --get')
	group.add_argument('-b', '--background', dest='background', action='store_true', help='runs the scan in a tmux session, usefull for if you are running from a host system. Include hosts list and scope list. e.g. -l hosts.txt -s scope --background')
	group.add_argument('-c', '--connect', dest='connect',action='store_true', help='connects to the listed ips and runs nmap then grabs the result file after scan is complete. WARNING: Nmap scan will cancel if connectivity is lost. Include hosts list and scope list. e.g. -l hosts.txt -s scope --background')

	args = parser.parse_args()

	if args.host_list and args.scope and args.connect == True:
		group_scan(args.host_list, args.scope)
	
	elif args.host and args.scope and args.connect == True:
		run_scan(args.host, args.scope)

	elif args.host_list and args.test == True:
		group_test(args.host_list)

	elif args.host_list and args.scope and args.background == True:
		group_background(args.host_list, args.scope)

	elif args.host_list and args.get == True:
		group_get_results(args.host_list)

	else:
		print("please enter options or enter them correctly, use -h for help")