#!/bin/bash
#
# This script turns the current computer into a temporary
# SOHO router. The current Internet connection is exposed to
# hosts connected to the supplied interface (LAN), by running
# dnsmasq to provide DHCP and DNS service, and setting up a
# MASQUERADE rule. Basic firewall rules are also setup.
#
# There need not be a working Internet connection in order to
# run this script. The connection can be established or changed
# at any time after running this script.
#
# The `soho.tftp` folder is also served via TFTP, with the
# included `pxelinux.0` set to boot. So if you want your clients
# to be able to netboot your favourite Linux distro, you need to
# extract the needed files in `soho.tftp`, create `pxelinux.cfg`
# accordingly and maybe an NFS share.
#
# ## Usage
#
# This script uses the `192.168.4.0/24` subnet for LAN, so make
# sure it's not being used before running it.
#
#     ./soho.sh <lan interface>
#
# Dependencies: iproute2 iptables dnsmasq
#
# The `reset` script may be used to clean up this setup.
#
set -e
cd $(dirname "$(readlink -e "$0")")
source utils.sh
auto_sudo $*

lan="$1"
if interface_exists "$lan"; [ $? != 0 ]; then
  echo "Usage: $0 <lan interface>"
  exit 1
fi

# enable routing
ip addr add 192.168.4.1/24 dev "$lan"
echo 1 > /proc/sys/net/ipv4/ip_forward
# add NAT
iptables -t nat -A POSTROUTING -s 192.168.4.0/24 -j MASQUERADE
# firewall
iptables -t filter -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t filter -A FORWARD ! -s 192.168.4.0/24 -d 192.168.4.0/24 -j DROP
# give DHCP / DNS / TFTP service
dnsmasq -C soho.dnsmasq.conf --tftp-root="$(pwd)/soho.tftp"
