#!/usr/bin/env python
#
# Gathers information about the running kvm machines

import glob, os, os.path

# Returns the list of kvm process ids

def get_kvm_pids():

	pids = []

	for dirpath in glob.glob('/proc/*'):
		dirname = os.path.basename(dirpath)
		if dirname.isdigit():
			f = open(dirpath + '/status', 'r')
			cmd_name = f.readline().split()[1]
			f.close()

			if cmd_name == 'qemu-system-x86':
				pids.append(dirname)
	return pids

# Returns the name of a KVM virtual machine

def get_kvm_machine_name(pid):

	f = open('/proc/' + pid + '/cmdline')
	cmdline = f.readline()
	f.close()

	cmdline_words = cmdline.split('\0')

        try:
                name = cmdline_words[cmdline_words.index('-name') + 1]

        except ValueError:
                name = "Not found"
	
	return name

# Get process information

def get_process_info(pid, key):

	f = os.popen('/bin/ps -p ' + pid + ' -o ' + key)
	l = f.readline()
	l = f.readline().rstrip()
	f.close()
	return l

# Get process CPU time

def get_process_cputime(pid):
	return get_process_info (pid, 'time')

# Get process CPU percentage: total and current

def get_process_cpu_percent_total(pid):
	return get_process_info (pid, '%cpu')

# Get process start time

def get_process_starttime(pid):
	return get_process_info (pid, 'bsdstart')

# Get process resident size

def get_process_rss(pid):
	size_kb = int(get_process_info (pid, 'rss'))
	size_mb = size_kb / 1024
	return str(size_mb) + ' MB'

# Get machine info
# from the specified shell variable,
# defined in /etc/kvm-manager/guests/<machine>

def get_machine_info(machine, var):
	f = os.popen(os.environ['KVM_MANAGER_ROOT'] + '/bin/kvm-manager ' + machine + ' info '+ var)
	return f.readline().rstrip()

# Get interface tx/rx info

def get_interface_info(interface):
	f = os.popen('/sbin/ifconfig ' + interface)
	txrx_line = f.readlines()[7]
	f.close
	return txrx_line

# Get interface rx info

def get_interface_rx_info(interface):
	return get_interface_info(interface).partition('(')[2].partition(')')[0]

# Get interface tx info

def get_interface_tx_info(interface):
	return get_interface_info(interface).partition('(')[2].partition('(')[2].partition(')')[0]

# Get guest maintenance status (safe or unsafe in maintenance mode)

def machine_is_safe(machine):
	if os.path.exists('/var/run/kvm-manager/' + machine + '_in_maintenance_mode'):
		return 'no'
	else:
		return 'yes'

# Main program

machine_pid = dict()
total_ram = 0

for pid in get_kvm_pids():
	machine_pid[get_kvm_machine_name(pid)] = pid

print '%-9s %-8s %-5s %-8s %-12s %-6s %-6s %-10s %-9s %-8s %-4s' % ('Machine', 'RAM', 'PID', 'RSS', 'CPU', 'CPU%', 'Since', 'IP', 'RX', 'TX', 'Safe')

for path in glob.glob('/etc/kvm-manager/guests/*'):
	
	machine = os.path.basename(path)

	ram = get_machine_info(machine, 'GUEST_RAM')
	total_ram += int(ram)
	ram += ' MB'

	if machine_pid.has_key(machine):
		pid = machine_pid[machine]
	 	rss = get_process_rss(pid)	
		cputime = get_process_cputime(pid)		
		cpu_percent_total = get_process_cpu_percent_total(pid)		
		starttime = get_process_starttime(pid)
		ip = get_machine_info(machine, 'GUEST_IP')
		interface = get_machine_info(machine, 'GUEST_IF')

		# From the host point of view, what's transmitted
		# to the guest is what is received by the guest
		# and vice versa. That's why rx and tx are inverted here.

		rx = get_interface_tx_info(interface)
		tx = get_interface_rx_info(interface)
		safe = machine_is_safe(machine)

		if safe == 'no':
			safe = '\033[31;1mno\033[0m'
	else:
		pid = '-----'
		rss = '--------'
		cputime = '--------'
		cpu_percent_total = '------'
		starttime = '------'
		ip = '----------'
		rx = '--------'
		tx = '--------'
		safe = '----'
	
	print '%-9s %-8s %-5s %-8s %-12s %-6s %-6s %-10s %-9s %-8s %-4s' % (machine, ram , pid, rss, cputime, cpu_percent_total, starttime, ip, rx, tx, safe)

print 'Total RAM: ' + str(total_ram) + ' MB'
