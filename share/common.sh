# Settings for our KVM machines

# CAUTION: these utilities require the 'bc' command

. /etc/default/kvm-manager

GPG=/usr/bin/gpg
SCP=/usr/bin/scp
RM=/bin/rm
EXTIP=`/sbin/ifconfig $EXTIF | sed -n 's/.*inet *addr:\([0-9\.]*\).*/\1/p'`
GUEST_PUBLIC_IP=`/sbin/ifconfig $GUEST_PUBLIC_IF | sed -n 's/.*inet *addr:\([0-9\.]*\).*/\1/p'`
VARRUN=/var/run/kvm-manager

# Settings deduced from guest settings ##########################

GUEST_MAINTENANCE_FLAG=$VARRUN/${GUEST_NAME}_in_maintenance_mode

# Create and setup the guest tap interface ######################

create_guest_if () {
	iface=`/usr/sbin/tunctl -b -u kvm -t $GUEST_IF`
	/sbin/ifconfig $GUEST_IF $GUEST_GW netmask $GUEST_MASK
}

# Destroy the tap interface #####################################

destroy_guest_if () {
	
	# 3s pause needed to avoid:
	# TUNSETIFF: Device or resource busy
	sleep 3
	/usr/sbin/tunctl -d $GUEST_IF > /dev/null
}

# Launch kvm ####################################################

launch_kvm () {
	# The kvm-name parameter is a dummy one
	# used to quickly find the corresponding process with "ps"

	
	# Make sure disk images are not mounted
        check_disk_image_not_mounted $GUEST_BOOT
        check_disk_image_not_mounted $GUEST_ROOT
        check_disk_image_not_mounted $GUEST_DATA

	if [ -f "$GUEST_EXTRADISK" ]
	then
        	check_disk_image_not_mounted $GUEST_EXTRADISK
		extradisks="-drive file=$GUEST_EXTRADISK,if=virtio"	
	fi

	# Sync disks
	# Sometimes needed - Otherwise, may not see a recent change in some disks
 	# Typical case: change in /boot/grub/menu.lst

	/bin/sync

	# Test Ubuntu release
        # boot=on mandatory in boot drive definitions on 10.04

        . /etc/lsb-release

        if [ "$DISTRIB_RELEASE" = "10.04" ]
        then
                bootorder=",boot=on"
        else
                bootorder=""
        fi

	# Start VM

	nice -$GUEST_PRIO /usr/bin/qemu-start -t $GUEST_NR -m $GUEST_MAC -n virtio -- -cpu host -smp $GUEST_CPUS -nographic -drive file=$GUEST_BOOT,if=virtio$bootorder -drive file=$GUEST_ROOT,if=virtio -drive file=$GUEST_DATA,if=virtio $extradisks -m $GUEST_RAM -monitor tcp::$GUEST_MONITOR_PORT,server,nowait -serial file:$GUEST_CONSOLE -daemonize -name $GUEST_NAME
}

# Shutdown guest ################################################

shutdown_guest () {

	# If the machine answers to ping, shut it down in a clean way
	# Otherwise, kill it.
	# We do this to stop the virtual machine in bounded time.
	# Otherwise, we may turn off the system without shutting down
	# other machines in a clean way

	if /bin/ping -c 1 -W 10 $GUEST_IP > /dev/null
	then
		# Guest answers to ping
		# Send it shutdown keys

		nc 127.0.0.1 $GUEST_MONITOR_PORT > /dev/null <<EOF
sendkey ctrl-alt-delete
EOF
	else
		# Using check_guest_status is a convenient way
		# to get the PID. We call it again here 
		# in case this function is not called from the
		# stop() function.

		check_guest_status
        	if [ $STATUS ]
		then
			/bin/kill -9 $STATUS
		fi
	fi
}

# Destroy guest ################################################

destroy_guest () {
	nc 127.0.0.1 $GUEST_MONITOR_PORT <<EOF
quit
EOF
}

# Enable / disable DNS requests from the guest ##################

guest_dns () {
	ACTION=$1
	$IPT -$ACTION INPUT -s $GUEST_IP -d $GUEST_GW -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -$ACTION INPUT -s $GUEST_IP -d $GUEST_GW -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -$ACTION OUTPUT -s $GUEST_GW -d $GUEST_IP -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
	$IPT -$ACTION OUTPUT -s $GUEST_GW -d $GUEST_IP -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT
}

enable_guest_dns () {
        guest_dns A
}

disable_guest_dns () {
        guest_dns D
}

# Enable / disable guest initiated connections ################
# Useful for package installs and updates

guest_connections () {
	ACTION=$1
        # Forward guest requests to the outside
	$IPT -$ACTION FORWARD -o $EXTIF -s $GUEST_IP -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	# Forward outside packets from existing connections to the guest
	$IPT -$ACTION FORWARD -i $EXTIF -d $GUEST_IP -m state --state ESTABLISHED,RELATED -j ACCEPT
	# Allow guest connections to the host (mainly for DNS)
	$IPT -$ACTION INPUT -s $GUEST_IP -d $GUEST_GW -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	$IPT -$ACTION OUTPUT -s $GUEST_GW -d $GUEST_IP -m state --state ESTABLISHED,RELATED -j ACCEPT
}

enable_guest_connections () {
	guest_connections A
}

disable_guest_connections () {
	guest_connections D
}

# ENABLES ACCESS TO AN HTTP PROXY ##############################################

__connection_to_proxy () {
	ACTION=$1
	$IPT -$ACTION FORWARD -p tcp -s $HTTP_PROXY_IP -d $GUEST_IP --dport http -j ACCEPT 
	$IPT -$ACTION FORWARD -p tcp -d $HTTP_PROXY_IP -s $GUEST_IP -m state --state ESTABLISHED,RELATED -j ACCEPT 
}

enable_connection_to_proxy () {
	__connection_to_proxy A
}

disable_connection_to_proxy () {
	__connection_to_proxy D
}

# ENABLES SMTP ACCESS ##########################################################

__guest_smtp () {
	ACTION=$1
	$IPT -$ACTION FORWARD -p tcp -s $GUEST_IP -d $SMTP_IP -m multiport --dport 25,587 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 
	$IPT -$ACTION FORWARD -p tcp -s $SMTP_IP -d $GUEST_IP -m state --state ESTABLISHED,RELATED -j ACCEPT 
}

enable_guest_smtp () {
	__guest_smtp A
}

disable_guest_smtp () {
	__guest_smtp D
}

# Enable / disable nat and port forwarding from the outside to the inside #######

__outside_port_forwarding () {
	ACTION=$1
	PROTOCOL=$2
	PORTS=$3
	$IPT -t nat -$ACTION PREROUTING -p $PROTOCOL -d $GUEST_PUBLIC_IP -m multiport --dport $PORTS -j DNAT --to-destination $GUEST_IP
	$IPT -$ACTION FORWARD -i $EXTIF -o $GUEST_IF -p $PROTOCOL -d $GUEST_IP -m multiport --dport $PORTS -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	$IPT -$ACTION FORWARD -s $GUEST_IP -i $GUEST_IF -o $EXTIF -p $PROTOCOL -m state --state ESTABLISHED,RELATED -j ACCEPT
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


# Enable / disable nat and port forwarding from the inside to the outside #######

__inside_port_forwarding () {
	ACTION=$1
	PROTOCOL=$2
	PORTS=$3
	# Not restricting to the outside interface, this allows connections
	# to internal network hosts
	$IPT -$ACTION FORWARD -p $PROTOCOL -s $GUEST_IP -m multiport --dport $PORTS -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	# Accept packets from existing connections to the guest
	$IPT -$ACTION FORWARD -p $PROTOCOL -d $GUEST_IP -m state --state ESTABLISHED,RELATED -j ACCEPT
}

inside_port_forwarding () {

	ACTION=$1

	if [ "$GUEST_OUTPUT_TCP_PORTS" != "" ]
	then
		__inside_port_forwarding $ACTION tcp $GUEST_OUTPUT_TCP_PORTS
	fi

	if [ "$GUEST_OUTPUT_UDP_PORTS" != "" ]
	then
		__inside_port_forwarding $ACTION udp $GUEST_OUTPUT_UDP_PORTS
	fi
}

enable_inside_port_forwarding () {
	inside_port_forwarding A
}

disable_inside_port_forwarding () {
	inside_port_forwarding D
}

# Enable ping to guest (from the host only) #################################### 

ping_to_guest () {
	ACTION=$1
	$IPT -$ACTION OUTPUT -p icmp -s $GUEST_GW -d $GUEST_IP -j ACCEPT
	$IPT -$ACTION INPUT -p icmp -s $GUEST_IP -d $GUEST_GW -m state --state RELATED,ESTABLISHED -j ACCEPT
	#$IPT -$ACTION OUTPUT -p icmp -d $GUEST_IP -j ACCEPT
	#$IPT -$ACTION INPUT -p icmp -s $GUEST_IP -m state --state RELATED,ESTABLISHED -j ACCEPT
}

enable_ping_to_guest () {
        ping_to_guest A
}

disable_ping_to_guest () {
        ping_to_guest D
}

# Enable / disable ssh to guest ##############################################

enable_ssh_to_guest () {
	if [ "$GUEST_SSH_PORT" != "" ]
	then
		__outside_port_forwarding A tcp $GUEST_SSH_PORT
	fi
} 	

disable_ssh_to_guest () {
	if [ "$GUEST_SSH_PORT" != "" ]
	then
		__outside_port_forwarding D tcp $GUEST_SSH_PORT
	fi
} 	

# Enable / disable host outgoing connections #################################

enable_any_host_connections () {
	$IPT -A OUTPUT -m state --state NEW -j ACCEPT
}

disable_any_host_connections () {
	$IPT -D OUTPUT -m state --state NEW -j ACCEPT
}

# Check guest running status ####################################

check_guest_status () {
	STATUS=`/usr/bin/pgrep -fu kvm "^/usr/bin/kvm .* \-name $GUEST_NAME$"`
}

# Make sure that the disk image is not currently mounted ########

check_disk_image_not_mounted () {
	file=$1
	filename=`basename $file`
        result=`/sbin/losetup -a | /bin/grep $filename`

	if [ "$result" != "" ]
        then
                log_failure_msg "Disk image $file is already mounted."
                log_failure_msg "Starting the VM will cause data corruption."
                log_failure_msg "Please unmount it first."
                log_end_msg 1
                exit 1
        fi
}

# Manipulate maintenance status #################################

maintenance_status_off () {
	$RM -f $GUEST_MAINTENANCE_FLAG
}

maintenance_status_on () {
 	/bin/mkdir -p $VARRUN
	/usr/bin/touch $GUEST_MAINTENANCE_FLAG
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

	# If kvm is still alive (guest OS not responding), quit the emulator

	check_guest_status
        if [ $STATUS ]
        then
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

# RC script: enable / disable  maintenance mode ################

enable_maintenance () {
	if [ ! -f $GUEST_MAINTENANCE_FLAG ]
	then
	   enable_guest_connections
	   enable_ssh_to_guest
	   maintenance_status_on
	fi
}

disable_maintenance () {
	if [ -f $GUEST_MAINTENANCE_FLAG ]
	then
	   disable_guest_connections
	   disable_ssh_to_guest
	   maintenance_status_off
	fi
}

# RC script: load guest iptables settings #######################
# Useful in case the host firewall script has been rerun,
# which erases the settings for all the guests

load_iptables () {

        enable_outside_port_forwarding
	enable_inside_port_forwarding
	enable_ping_to_guest

	if [ "$GUEST_NEED_DNS" = "yes" ]
	then
		enable_guest_dns
	fi

	if [ "$GUEST_NEED_SMTP" = "yes" ]
	then
		enable_guest_smtp
	fi

	if [ "$GUEST_BEHIND_HTTP_PROXY" = "yes" ]
	then
		enable_connection_to_proxy
	fi

	# Clear maintenance status flag
	# in case it is still on from an aborted run
	maintenance_status_off
}

# Script to remove iptables #####################################

remove_iptables () {

        disable_outside_port_forwarding
	disable_inside_port_forwarding
	disable_ping_to_guest

	if [ "$GUEST_NEED_DNS" = "yes" ]
	then
		disable_guest_dns
	fi

	if [ "$GUEST_NEED_SMTP" = "yes" ]
	then
		disable_guest_smtp
	fi

	if [ "$GUEST_BEHIND_HTTP_PROXY" = "yes" ]
	then
		disable_connection_to_proxy
	fi

	# Clear maintenance status flag
	# in case it is on
 	maintenance_status_off	
}

# RC script: get guest information ##############################
# (Value of a specified shell variable 

guest_info () {

	var="$"$1
	eval echo $var 
}

# Clean backup files ############################################

is_multiple_of () {

	# Tells whether the first argument is multiple of the second one

	result=`expr \( $1 / $2 \) \* $2`

	if [ $result = $1 ]
	then
		echo "true"
	else
		echo "false"
	fi
}

__remove_incremental_backup () {

	prefix=$1
	i=$2
	multiple=`echo 2 ^ $3 | bc`

	# Remove the incremental files at now-$2 days
	# unless num_days_since_epoch(now-$i) is a multiple of $multiple
	# or $multiple > 16 
	# Consequence:
	# - All incremental backups younger than 30 are kept 
	# - 1/2 incremental backups kept between 30 and 59 days
	# - 1/4 incremental backups kept between 60 and 89 days
	# - 1/8 incremental backups kept between 90 and 119 days
	# - 1/16 incremental backups kept between 120 and 149 days
	# - No incremental backups kept after 150 days
	#   (we keep full backups every month anyway)

	# It was necessary to use a fixed comparison point, which didn't change every day
	# That's why we chose not to make it relative to the current day
	 
	num_seconds=`date -d "-$i days" +%s`
	num_days=`expr $num_seconds / 3600 / 24`

	status=`is_multiple_of $num_days $multiple`
	
	if [ $multiple -gt 16 ] || [ "$status" = "false" ]
	then
		date=`date -d "-$i days" +%F`
		file=`__backup_incremental_name $prefix $date`.xz

		if [ -f $file ]
		then
			$KVM_MANAGER_ROOT/bin/kvm-rm $file
		fi
	fi
}
		
__backup_remove () {

	# Remove the backup files older than BACKUP_RETENTION days
	prefix=$1
	
	# Using `dirname $prefix` to make sure we don't run
	# rm in the / directory!

        i=31

	while [ $i -lt $BACKUP_RETENTION ]
	do
		__remove_incremental_backup $prefix $i `expr $i / 30`
		i=`expr $i + 1`
	done

	# Remove all files older than the retention period

	filename=`basename $prefix`
	find `dirname $prefix` -name "$filename*" -mtime +$BACKUP_RETENTION -exec $KVM_MANAGER_ROOT/bin/kvm-rm {} \; 
}

# Get the latest full backup file ###############################

__get_latest_full () {
	
	guest_disk=$1
	guest_backup=$2

	if test -n "`/bin/ls ${guest_backup}-full-* 2>/dev/null`"
	then
		LATEST_FULL=`/bin/ls -tr ${guest_backup}-full-* | tail -1`
        else
		LATEST_FULL=""
	fi
}

# Full backup code ##############################################

__backup_full () {

	guest_disk=$1
	guest_backup=$2
	__get_latest_full $guest_disk $guest_backup

	# Remove expired backups
	__backup_remove $guest_backup 

	# Create the new full backup
	suffix=-full-`date +%F`
	guest_backup_full=$guest_backup$suffix
	/bin/cp $guest_disk $guest_backup_full

	# Write the last 2 full backups to a file
	# That's useful for a machine replicating the backups with rsync:
	# it reads this file, and if it doesn't have the latest full yet,
	# it copies the previous full to this new full file, and only then
	# runs rsync. This way, we just transfer the differences, and not
	# the whole files.

	echo "$LATEST_FULL $guest_backup_full" > ${guest_backup}-fullinfo
}

backup_full () {
	__backup_full $GUEST_BOOT $GUEST_BOOT_BACKUP
	__backup_full $GUEST_ROOT $GUEST_ROOT_BACKUP
	__backup_full $GUEST_DATA $GUEST_DATA_BACKUP
}

# Incremental backup code #######################################

__backup_incremental_name () {

	backup_prefix=$1
	date=$2
	echo ${backup_prefix}-incremental-`date -d $date +%F`
}
	
__backup_incremental () {
	
	current=$1
	backup_prefix=$2

	# Remove expired backups
	__backup_remove $backup_prefix 

	# Find the latest full backup
	__get_latest_full $current $backup_prefix

	if  [ -f "$LATEST_FULL" ]
	then
		# Generate the rsync incremental backup
		dir=`dirname $LATEST_FULL`
		file=`basename $LATEST_FULL`
		cd $dir
		today=`date +%F`
		batch=`__backup_incremental_name $backup_prefix $today`
		/usr/bin/rsync -a --sparse --only-write-batch=$batch $current $file
		$RM ${batch}.sh

		# Compress the output
		# Don't use -9 compression, otherwise, you will use too much RAM
		# and freeze the host
		/usr/bin/xz -9 --force $batch
	else 
		# If there is no full backup yet (new machine), just create one
		# No need to make an incremental backup for the moment
		__backup_full $current $backup_prefix
	fi
}

backup_incremental () {
	__backup_incremental $GUEST_BOOT $GUEST_BOOT_BACKUP
	__backup_incremental $GUEST_ROOT $GUEST_ROOT_BACKUP
	__backup_incremental $GUEST_DATA $GUEST_DATA_BACKUP
}

# Main code for RC scripts ####################################################

rc_main () {
	case "$1" in
        	start|stop|status)
                	$1
                	;;
		enable-maintenance)
			enable_maintenance
			;;
		disable-maintenance)
			disable_maintenance
			;;
		load-iptables)
			load_iptables
			;;
		reload-iptables)
			disable_maintenance
			load_iptables
			;;
        	restart)
                	stop
                	start
                	;;

        	info)
			guest_info $2
			;;
        	*)
                	echo "Usage: /etc/init.d/kvm-www {start|stop|restart|status|reload-iptables|load-iptables|info|enable-maintenance|disable-maintenance}"
                	exit 1
                	;;
	esac

	exit 0
}

###############################################################
