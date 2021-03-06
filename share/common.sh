# Settings for our KVM machines

# CAUTION: these utilities require the 'bc' command

. /lib/lsb/init-functions
. /etc/default/kvm-manager

GPG=/usr/bin/gpg
SCP=/usr/bin/scp
RM=/bin/rm
RMDIR=/bin/rmdir
CP=/bin/cp
LN=/bin/ln
SED=/bin/sed
BASENAME=/usr/bin/basename
DIRNAME=/usr/bin/dirname
LVREMOVE=/sbin/lvremove
DMSETUP=/sbin/dmsetup
MOUNT=/bin/mount
UMOUNT=/bin/umount
SLEEP=/bin/sleep
MKDIR=/bin/mkdir
SSH=/usr/bin/ssh
RSYNC=/usr/bin/rsync
LVS=/sbin/lvs
LVCREATE=/sbin/lvcreate
LVREMOVE=/sbin/lvremove
GREP=/bin/grep
AWK=/usr/bin/awk
DD=/bin/dd
MKFS=/sbin/mkfs.ext4
MKSWAP=/sbin/mkswap
IFCONFIG=/sbin/ifconfig

GUEST_DEFS=/etc/kvm-manager/guests
KVM_MANAGER=$KVM_MANAGER_ROOT/bin/kvm-manager
LVMLOG=$LOGPATH/lvm.log
MNT=/mnt/snapshots

# Get interface ip address ######################################

get_ip () {
	ip=`$IFCONFIG $1 | $SED -n 's/.*inet *addr:\([0-9\.]*\).*/\1/p'`
	
	if [ "$ip" = "" ]
	then
		log_failure_msg "No IP address for interface $1. Network issue or failing line in /etc/network/interfaces?"
		exit 1
	fi

	echo $ip
}

# Further inits

EXTIP=`get_ip $EXTIF`
GUEST_PUBLIC_IP=`get_ip $GUEST_PUBLIC_IF`

# Create and setup the guest tap interface ######################

create_guest_if () {
	iface=`/usr/sbin/tunctl -b -u kvm-${GUEST_NAME} -t $GUEST_IF`
	/sbin/ifconfig $GUEST_IF $GUEST_GW netmask $GUEST_MASK
}

# Destroy the tap interface #####################################

destroy_guest_if () {

	# 3s pause needed to avoid:
	# TUNSETIFF: Device or resource busy
	$SLEEP 3
	/usr/sbin/tunctl -d $GUEST_IF > /dev/null
}

# Launch kvm ####################################################

launch_kvm () {
	# The kvm-name parameter is a dummy one
	# used to quickly find the corresponding process with "ps"


	# Make sure disk images are not mounted
        check_volume_not_mounted $GUEST_BOOT
        check_volume_not_mounted $GUEST_ROOT
        check_volume_not_mounted $GUEST_DATA

	extradisks=""

	if [ -e "$GUEST_EXTRADISK" ]
	then
        	check_volume_not_mounted $GUEST_EXTRADISK
		extradisks="-drive file=$GUEST_EXTRADISK,cache=none,if=virtio,format=raw"
	fi

	# Sync disks
	# Sometimes needed - Otherwise, may not see a recent change in some disks
 	# Typical case: change in /boot/grub/menu.lst

	/bin/sync

	# Start VM

	nice -$GUEST_PRIO /usr/bin/qemu-start -u kvm-$GUEST_NAME -t $GUEST_NR -m $GUEST_MAC -n virtio -- -cpu host -smp $GUEST_CPUS -drive file=$GUEST_BOOT,cache=none,if=virtio,format=raw -drive file=$GUEST_ROOT,cache=none,if=virtio,format=raw -drive file=$GUEST_DATA,cache=none,if=virtio,format=raw $extradisks -m $GUEST_RAM -monitor tcp::$GUEST_MONITOR_PORT,server,nowait -serial file:$GUEST_CONSOLE -parallel null -display none -vga none -daemonize -name $GUEST_NAME
}

# Shutdown guest ################################################

shutdown_guest () {

	# If the machine answers to ping, shut it down in a clean way

	if /bin/ping -c 1 -W 10 $GUEST_IP > /dev/null
	then
		# Guest answers to ping
		# Send it shutdown keys

		# Command compatible with Ubuntu 14.04 and earlier, ignored in 16.04 and later
		echo "sendkey ctrl-alt-delete" | /bin/nc 127.0.0.1 $GUEST_MONITOR_PORT > /dev/null
		# Command compatible with Ubuntu 16.04 and later (systemd)
		echo "system_powerdown" | /bin/nc 127.0.0.1 $GUEST_MONITOR_PORT > /dev/null
	fi
}

# Destroy guest ################################################

destroy_guest () {
	echo "quit" | /bin/nc 127.0.0.1 $GUEST_MONITOR_PORT > /dev/null
}

# iptables functions

open_guest_port () {
  if [ "$3" = "any" ]
  then
  	$IPT -A FORWARD -p $1 -s $2 --dport $4 -m state --state NEW -j ACCEPT
  else
  	$IPT -A FORWARD -p $1 -s $2 -d $3 --dport $4 -m state --state NEW -j ACCEPT
  fi
}

open_guest_ports () {
  if [ "$3" = "any" ]
  then
  	$IPT -A FORWARD -p $1 -s $2 -m multiport --dport $4 -m state --state NEW -j ACCEPT
  else
  	$IPT -A FORWARD -p $1 -s $2 -d $3 -m multiport --dport $4 -m state --state NEW -j ACCEPT
  fi
}

# Enable / disable DNS requests from the guest ##################

guest_dns () {
	ACTION=$1
	$IPT -$ACTION INPUT -s $GUEST_IP -d $GUEST_GW -p udp --dport 53 -m state --state NEW -j ACCEPT
}

enable_guest_dns () {
        guest_dns A
}

disable_guest_dns () {
        guest_dns D
}

# ENABLES ACCESS TO AN HTTP PROXY ##############################################

__connection_to_proxy () {
	ACTION=$1
	$IPT -$ACTION FORWARD -p tcp -s $HTTP_PROXY_IP -d $GUEST_IP --dport http -j ACCEPT
}

enable_connection_to_proxy () {
	__connection_to_proxy A
}

disable_connection_to_proxy () {
	__connection_to_proxy D
}

# Enable / disable nat and port forwarding from the outside to the inside #######

__outside_port_forwarding () {
	ACTION=$1
	PROTOCOL=$2
	PORTS=$3
	$IPT -t nat -$ACTION PREROUTING -p $PROTOCOL -d $GUEST_PUBLIC_IP -m multiport --dport $PORTS -j DNAT --to-destination $GUEST_IP
	$IPT -$ACTION FORWARD -i $EXTIF -o $GUEST_IF -p $PROTOCOL -d $GUEST_IP -m multiport --dport $PORTS -m state --state NEW -j ACCEPT
}

outside_port_forwarding () {

	ACTION=$1

	if [ "$GUEST_INPUT_TCP_PORTS" != "" ]
	then
		__outside_port_forwarding $ACTION tcp $GUEST_INPUT_TCP_PORTS
	fi

	if [ "$GUEST_INPUT_UDP_PORTS" != "" ]
	then
		__outside_port_forwarding $ACTION udp $GUEST_INPUT_UDP_PORTS
	fi
}

enable_outside_port_forwarding () {
	outside_port_forwarding A
}

disable_outside_port_forwarding () {
	outside_port_forwarding D
}


# Enable ping to guest (from the host only) ####################################

ping_to_guest () {
	ACTION=$1
	$IPT -$ACTION OUTPUT -p icmp -s $GUEST_GW -d $GUEST_IP -j ACCEPT
}

enable_ping_to_guest () {
        ping_to_guest A
}

disable_ping_to_guest () {
        ping_to_guest D
}

# Enable ping from guest  ####################################################

guest_ping () {
	ACTION=$1
        # Forward guest ping requests to the outside
        $IPT -$ACTION FORWARD -p icmp -o $EXTIF -s $GUEST_IP -m state --state NEW -j ACCEPT
}

enable_guest_ping () {
        guest_ping A
}

disable_guest_ping () {
        guest_ping D
}

# Check guest running status ####################################

check_guest_status () {
	STATUS=`/usr/bin/pgrep -fu kvm-$GUEST_NAME "^qemu-system-x86_64 .* \-name $GUEST_NAME$"`
}

# Make sure that the partition is not currently mounted ########

check_volume_not_mounted () {
	device=$1
	volume_name=`$BASENAME $device`
	dm_volume=`echo $volume_name | $SED -n 's/-/--/pg'`
        result=`/bin/mount | /bin/grep $dm_volume`

	if [ "$result" != "" ]
        then
                log_failure_msg "Volume $device is already mounted."
                log_failure_msg "Starting the VM will cause data corruption."
                log_failure_msg "Please unmount it first:"
                log_failure_msg "sudo umount /dev/mapper/dm_volume"
                log_end_msg 1
                exit 1
        fi
}

# RC script: start guest machine ################################

start () {

        log_begin_msg "Starting kvm $GUEST_NAME virtual machine"

        # Check that the virtual machine is not running yet
	check_guest_status
        if [ $STATUS ]
        then
                log_failure_msg "kvm $GUEST_NAME is already running. Please stop it first."
                log_end_msg 1
                exit 1
        fi

        # Setup the tap network interface
        create_guest_if

        # Run KVM in background mode and drop priviledges to the kvm user #####
        launch_kvm

        # Firewall settings
	load_iptables

        # Return correct exit status
        log_end_msg 0
}

# RC script: stop guest machine ################################

stop () {
        log_begin_msg "Shutting down the kvm $GUEST_NAME virtual machine"

        # Check that the virtual machine is actually running
	check_guest_status
        if [ $STATUS ]
        then
                shutdown_guest
        else
                log_failure_msg "No kvm $GUEST_NAME virtual machine was running."
                log_end_msg 1
                exit 1
        fi

	# If kvm is still alive after TIMEOUT
        # (guest OS didn't complete shutdown, or isn't responding to ping),
        # quit the emulator

	count=0
	stopped=0

	if [ -z "$GUEST_TIMEOUT" ]
	then
		GUEST_TIMEOUT=20
	fi

	while [ "$count" -lt $GUEST_TIMEOUT ]
	do
		check_guest_status
        	if [ $STATUS ]
        	then
			count=`expr $count + 1`
			$SLEEP 1
        	else
			stopped=1
			break
		fi
	done

	if [ "$stopped" = "0" ]
	then
        	log_failure_msg "Forced to destroy the $GUEST_NAME virtual machine"
               	destroy_guest
	fi

        # Remove firewall rules and disable the tap network interface ##

	remove_iptables
        destroy_guest_if

        # Return correct exit status
        log_end_msg 0
}

# RC script: querying guest status #############################

status () {
       check_guest_status
       if [ $STATUS ]
       then
	  echo "The kvm $GUEST_NAME virtual machine is running"
       else
	  echo "The kvm $GUEST_NAME virtual machine is NOT running"
       fi
}

# RC script: load guest iptables settings #######################
# Useful in case the host firewall script has been rerun,
# which erases the settings for all the guests

load_iptables () {

        enable_outside_port_forwarding
	enable_ping_to_guest
	enable_guest_dns

	if [ "$GUEST_NEED_PING" = "yes" ]
	then
		enable_guest_ping
	fi

	if [ "$GUEST_BEHIND_HTTP_PROXY" = "yes" ]
	then
		enable_connection_to_proxy
	fi
}

# Script to remove iptables #####################################

remove_iptables () {

        disable_outside_port_forwarding
	disable_ping_to_guest
	disable_guest_dns

	if [ "$GUEST_NEED_PING" = "yes" ]
	then
		disable_guest_ping
	fi

	if [ "$GUEST_BEHIND_HTTP_PROXY" = "yes" ]
	then
		disable_connection_to_proxy
	fi
}

# RC script: get guest information ##############################
# (Value of a specified shell variable)

guest_info () {

	var="$"$1
	eval echo $var
}

# Support for VM disk snapshots #######################################

do_snapshot_remove () {

	snapshot=$1
	mountpoint=$2

	if [ -e "$snapshot" ]
	then
		if /bin/mountpoint -q "$mountpoint"
		then
			$UMOUNT $mountpoint
			$SLEEP 10
		fi

		$LVREMOVE -f $snapshot > /dev/null

		if [ "$?" != "0" ]
		then
			echo `date` "lvremove $snapshot failed" >> $LVMLOG
		fi
	fi


	vg_name=$($BASENAME $(dirname $snapshot))
	snapshot_name=$($BASENAME $snapshot)
	snapshot_cow=`echo $snapshot_name | $SED 's/-/--/g'`-cow
	snapshot_cow_file=/dev/mapper/${vg_name}-${snapshot_cow}

	if [ -e "$snapshot_cow_file" ]
	then
		$DMSETUP remove -f $snapshot_cow_file
	fi
}

__snapshot_create () {
	volume=$1
	offset=$2
	snapshot=${volume}-snapshot
	snapshot_name=`$BASENAME $snapshot`
	mountpoint=$MNT/$snapshot_name
	mkdir -p $mountpoint

	# Destroy any snapshot that would still exist
	do_snapshot_remove $snapshot $mountpoint

	# Create a new snapshot

	# Using 2G for snapshot size... It's the maximum size
        # of changes to the original volume during the life of the snapshot
	# 2G should be more than enough

	lvcreate -L2G -s -n $snapshot_name $volume > /dev/null

	if [ "$?" != "0" ]
	then
		echo `date` "lvcreate $snapshot failed" >> $LVMLOG
	else
		if [ "$offset" != "" ]
		then
			# Weird... don't manage to mount with ro and offset directly
			mount -o offset=$offset $snapshot $mountpoint
			mount -o remount,ro $mountpoint
		else
			mount -o ro $snapshot $mountpoint
		fi

		if /bin/mountpoint -q $mountpoint
		then
			mountpoints="$mountpoints $mountpoint"
		else
			echo `date` "mounting $snapshot failed" >> $LVMLOG
		fi
	fi
}

__snapshot_remove () {
	volume=$1
	snapshot=${volume}-snapshot
	snapshot_name=`$BASENAME $snapshot`
	mountpoint=$MNT/$snapshot_name

	do_snapshot_remove $snapshot $mountpoint
}

snapshot_create () {

	mountpoints=""
	__snapshot_create $GUEST_ROOT

        if [ "$GUEST_BACKUP_DATADISK" != "no" ]
	then
		__snapshot_create $GUEST_DATA
	fi

	# Mounting the boot partition

        start=`fdisk -lu $GUEST_BOOT | grep ${GUEST_BOOT}1 | awk '{print $3}'`
        startoffset=$(($start * 512))

        __snapshot_create $GUEST_BOOT $startoffset

        if [ -e "$GUEST_EXTRADISK" -a "$GUEST_BACKUP_EXTRADISK" = "yes" ]
        then
		__snapshot_create $GUEST_EXTRADISK
        fi
}

snapshot_remove () {

	__snapshot_remove $GUEST_BOOT
	__snapshot_remove $GUEST_ROOT

        if [ "$GUEST_BACKUP_DATADISK" != "no" ]
	then
		__snapshot_remove $GUEST_DATA
	fi

        if [ -e "$GUEST_EXTRADISK" -a "$GUEST_BACKUP_EXTRADISK" = "yes" ]
        then
		__snapshot_remove $GUEST_EXTRADISK
        fi
}

# Main code for RC scripts ####################################################

rc_main () {
	case "$2" in
        	start|stop|status)
                	$2
                	;;
		reload-iptables)
			load_iptables
			;;
        	restart)
		 	if [ "$GUEST_RESTARTABLE" != "no" ]	
			then
                		stop
                		start
			else
				log_warning_msg "INFO: NOT restarting the kvm $1 virtual machine (marked as not restartable)"
			fi
                	;;

        	info)
			guest_info $3
			;;
        	*)
                	echo "Usage: /etc/init.d/kvm-www {start|stop|restart|status|reload-iptables|info}"
                	exit 1
                	;;
	esac

	exit 0
}

###########################################################################################
# Backup a remote filesystem
###########################################################################################

remote_filesystem_backup () {
	remotedir=$1
	localdirname=$2

	dir=$backupdir/$localdirname
	$MKDIR -p $dir
	latest=$dir/latest
	new=$dir/`date +%Y-%m-%d-%H:%M:%S`

	if [ -h $latest ]
	then
		previous=`readlink $latest`
		$RM $latest
		$CP -al $previous $new
	fi

	rsync -az --one-file-system --delete -e "ssh -p $port" root@$ip:$remotedir/ $new/
	$LN -s $new $latest
}

###########################################################################################
# Backup an entire host and all its VMs
###########################################################################################

remote_host_backup () {

	ip=$1
	port=$2
	backupdir=$3

	machines=`ssh -p $port root@$ip $DIR/list-vms`

	for machine in $machines
	do
		snapshots=`ssh -p $port root@$ip $DIR/snapshot-create $machine`
		for snapshot in $snapshots
		do
			echo "Processing $snapshot"
			remote_filesystem_backup $snapshot `basename $snapshot`
		done
		ssh -p $port root@$ip $DIR/snapshot-remove $machine
	done

	remote_rootfs_backup $ip $port $backupdir
}

###########################################################################################
# Backup a remote rootfs
###########################################################################################

remote_rootfs_backup () {

	# Variables needed by remote_filesystem_backup
	ip=$1
	port=$2
	backupdir=$3

	remote_filesystem_backup / rootfs
}

###########################################################################################
# Slow port knocking commmand
###########################################################################################

slow_knock () {

	# Standard knock is too fast from the backup server

	ip=$1
	port1=$2
	port2=$3
	port3=$4
	port4=$5

	for port in $2 $3 $4 $5
	do
		/usr/bin/knock $ip $port
		/bin/sleep 1
	done
}
