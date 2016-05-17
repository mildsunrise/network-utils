#!/bin/bash
#
# A catch-all network configuration reset script, which can
# be useful when testing other network setup scripts. It will
# attempt to leave the network configuration as close
# as possible as it was just when the kernel booted. This means:
#
#  - No virtual interfaces (VLANs, bridges, tunnels, etc.).
#
#  - Each physical device has exactly one network interface,
#    down and with default name, MAC and medium-specific parameters
#    (autonegotiation for Ethernet interfaces, managed mode
#    for wireless, etc.).
#
#  - Firewall, traffic control, addresses, routes, ARP cache,
#    policies, tunnels, etc. are empty. Kernel variables
#    for network are set to default values.
#
# Note that this only touches the running kernel configuration, it
# doesn't modify any configuration files, so the reset is
# temporary and doesn't affect userspace things such as DNS.
# Servers providing just higher layer services (NTP, DNS, SMB,
# ...) won't be killed either.
#
# If you have many network namespaces (see ip-netns(8)), only the
# current one will be touched.
#
# Keep in mind there are some very special parameters that
# aren't trivial to reset, or whose default values aren't known.
# They will be annotated with TODOs or LEAKs in the code.
# It is however **never** acceptable to leave a recently booted
# kernel into a **different** state. If this happens, it's a
# bug and must be fixed.
#
# At the end, it can optionally try to unload network-specific modules
# such as netfilter, VLAN, PPPOE, etc, see below.
#
# ## Usage
#
#     ./reset.sh
#
# Dependencies: iproute2 ethtool(optional) iw(optional)
#               iptables(optional) ebtables(optional)
#
# **Only run this script if you know what you are doing.**
# Running it remotely is not a good idea unless you make sure
# to reconfigure the network afterwards, i.e.:
#
#     ./reset.sh; ifup eth0
#
# This script should not be run if the network is being
# heavily managed (by NetworkManager, shorewall, etc.). In
# this case, the manager will likely have an option to
# detach and reset the configuration.
#
# Certain variables modify script output (or behaviour):
#
#   - $VERBOSE (default 1) defines which messages get output:
#
#     0 -> only errors
#     1 -> errors, warnings
#     2 -> errors, warnings, info
#     3 -> errors, warnings, info, debug
#
#     Note that it only affects messages from the script
#     itself. Output from tools is always shown.
#
#   - $__reset_ignore_processes: if not empty, no processes will
#     be killed.
#
#   - $__reset_unload_modules: if not empty, the script will try
#     to unload common network modules from the kernel.
#
#   - $__reset_as_library: if not empty, the script will do nothing.
#     Intended for using this script as a function library.
#
# ### Use as a library
#
# To use this script as a function library, source it with
# `$__reset_as_library` set:
#
#     __reset_as_library=1
#     source reset.sh
#     reset_iptables # or some other function
#
# ## Development
#
# No errors should be printed. If errors are printed, it should be
# because of an unexpected situation (i.e. a driver refusing to
# reset some parameter) rather than an edge case.
#
# This script should have as fewer dependencies as possible.
# Using legacy tools is never allowed, however, so iproute2 is
# allowed as a dependency.
#
# Remember not everybody uses English. When parsing human-readable
# command output, always invoke the command with run_c.
#
# Always use `local` inside functions as appropiate. No need to use
# it in nested functions, if they are relatively short. Nested functions
# should be prefixed with __.
#
# When iterating over a set of interfaces while removing them, make
# sure to check the interface exists before operating on it. It may
# already have been removed as it was the child of another one.
#
cd $(dirname "$(readlink -e "$0")")
source utils.sh

IP=$(which ip)
TC=$(which tc)
IPTABLES=$(which iptables)
EBTABLES=$(which ebtables)
ETHTOOL=$(which ethtool)
IW=$(which iw)


# Main function. Resets everything
function reset_network {
  # Kill processes
  if [ -z "$__reset_ignore_processes" ]; then
    reset_processes
    sleep 0.5
  fi

  # Medium-specific
  reset_iw
  reset_ethtool
  #FIXME: bonding?

  # Global settings
  reset_ip_link
  reset_ip_tunnel
  reset_ip_tuntap
  reset_ip_l2tp
  reset_ip_basic
  reset_ip_rule
  reset_ip_neighbour
  reset_ip_ntable
  reset_ip_xfrm
  reset_iptables
  reset_ebtables
  reset_tc
  reset_variables

  # Complimentary
  if [ -z "$__reset_unload_modules" ]; then return; fi
  reset_modules
}


# Reset processes
function reset_processes {
  local pid; local cmdline
  function __kill_process {
    for pid in $(pidof "$1"); do
      cmdline="$(cat /proc/$pid/cmdline | tr '\0' ' ')"
      info_msg reset_processes "killing process $pid: $cmdline"
      kill "$pid"
    done
  }

  # Heavy managers
  __kill_process NetworkManager
  __kill_process shorewall
  # Routing
  __kill_process zebra
  __kill_process ospfd
  __kill_process isisd
  __kill_process ripd
  __kill_process ospf6d
  __kill_process ripngd
  __kill_process bgpd
  __kill_process pimd
  # VPN
  __kill_process openvpn
  __kill_process pptpd
  # PPP
  __kill_process pppd
  # PPPoE
  __kill_process pppoe
  __kill_process pppoe-server
  # DHCP client
  __kill_process dhclient
  __kill_process dhclient3
  __kill_process dhclient4
  __kill_process dhcpcd
  __kill_process udhcpc
  # DHCP server
  __kill_process dhcpd
  __kill_process dnsmasq
  __kill_process odhcpd
  # 802.11
  __kill_process wpa_supplicant
  __kill_process hostapd
  __kill_process airtun-ng
  # STP
  __kill_process mstdp
}


# Reset modules
function reset_modules {
  # We run it ignoring output because there are some legit reasons the
  # modules will fail to unload (another module depending on them, etc.).
  modprobe -r \
    ifb 8021q bonding veth bridge \
    pppoe pppox ppp_async ppp_deflate ppp_synctty ppp_mppe pptp \
    ip_tunnel ipip ip6_gre ip6_tunnel \
    l2tp_core l2tp_debugfs l2tp_eth l2tp_ip6 l2tp_ip l2tp_netlink l2tp_ppp \
    ipset ipvs nf_conntrack_amanda nf_conntrack_broadcast nf_conntrack_ftp nf_conntrack_h323 nf_conntrack_irc nf_conntrack nf_conntrack_netbios_ns nf_conntrack_netlink nf_conntrack_pptp nf_conntrack_proto_dccp nf_conntrack_proto_gre nf_conntrack_proto_sctp nf_conntrack_proto_udplite nf_conntrack_sane nf_conntrack_sip nf_conntrack_snmp nf_conntrack_tftp nf_nat_amanda nf_nat_ftp nf_nat_irc nf_nat nf_nat_proto_dccp nf_nat_proto_sctp nf_nat_proto_udplite nf_nat_sip nf_nat_tftp nfnetlink_acct nfnetlink_cthelper nfnetlink_cttimeout nfnetlink nfnetlink_log nfnetlink_queue nf_synproxy_core nf_tables nft_compat nft_counter nft_ct nft_exthdr nft_hash nft_limit nft_log nft_meta nft_nat nft_rbtree x_tables xt_addrtype xt_AUDIT xt_bpf xt_CHECKSUM xt_CLASSIFY xt_cluster xt_comment xt_connbytes xt_connlabel xt_connlimit xt_connmark xt_CONNSECMARK xt_conntrack xt_cpu xt_CT xt_dccp xt_devgroup xt_dscp xt_DSCP xt_ecn xt_esp xt_hashlimit xt_helper xt_hl xt_HL xt_HMARK xt_IDLETIMER xt_iprange xt_ipvs xt_LED xt_length xt_limit xt_LOG xt_mac xt_mark xt_multiport xt_nat xt_NETMAP xt_nfacct xt_NFLOG xt_NFQUEUE xt_osf xt_owner xt_physdev xt_pkttype xt_policy xt_quota xt_rateest xt_RATEEST xt_realm xt_recent xt_REDIRECT xt_sctp xt_SECMARK xt_set xt_socket xt_state xt_statistic xt_string xt_tcpmss xt_TCPMSS xt_TCPOPTSTRIP xt_tcpudp xt_TEE xt_time xt_TPROXY xt_TRACE xt_u32 \
    ip6table_filter ip6table_mangle ip6table_nat ip6table_raw ip6table_security ip6_tables ip6t_ah ip6t_eui64 ip6t_frag ip6t_hbh ip6t_ipv6header ip6t_MASQUERADE ip6t_mh ip6t_NPT ip6t_REJECT ip6t_rpfilter ip6t_rt ip6t_SYNPROXY nf_conntrack_ipv6 nf_defrag_ipv6 nf_nat_ipv6 nf_tables_ipv6 nft_chain_nat_ipv6 nft_chain_route_ipv6 \
    arptable_filter arp_tables arpt_mangle iptable_filter iptable_mangle iptable_nat iptable_raw iptable_security ip_tables ipt_ah ipt_CLUSTERIP ipt_ECN ipt_MASQUERADE ipt_REJECT ipt_rpfilter ipt_SYNPROXY ipt_ULOG nf_conntrack_ipv4 nf_defrag_ipv4 nf_nat_h323 nf_nat_ipv4 nf_nat_pptp nf_nat_proto_gre nf_nat_snmp_basic nf_tables_arp nf_tables_ipv4 nft_chain_nat_ipv4 nft_chain_route_ipv4 nft_reject_ipv4 \
    ebt_802_3 ebtable_broute ebtable_filter ebtable_nat ebtables ebt_among ebt_arp ebt_arpreply ebt_dnat ebt_ip6 ebt_ip ebt_limit ebt_log ebt_mark ebt_mark_m ebt_nflog ebt_pkttype ebt_redirect ebt_snat ebt_stp ebt_vlan nf_tables_bridge
}


# Reset iw
function reset_iw {
  local dev; local phy; local i
  # FIXME (iw 3.4): iw output is not stable, watch for changes
  # when it is, note it as minimum required version and remove this FIXME
  if [ -z "$IW" ]; then
    warning_msg reset_iw "iw not available, 802.11 subsystem not touched"
    return 1
  fi

  for dev in $(run_c $IW dev | grep '^	Interface' | cut -d' ' -f2); do
    debug_msg reset_iw "removing dev $dev"
    $IW dev "$dev" interface del
  done

  i=0
  for phy in $(run_c $IW phy | grep -v '^\s' | cut -d' ' -f2); do
    while dev="wlan$i"; interface_exists "$dev"; do ((i++)); done
    debug_msg reset_iw "creating dev $dev for $phy"
    $IW phy "$phy" interface add "$dev" type managed; ((i++))

    # TODO: reset phy parameters
  done
}


# Reset ethtool
function reset_ethtool {
  local dev
  if [ -z "$ETHTOOL" ]; then
    warning_msg reset_ethtool "ethtool not available, Ethernet devices not touched, MACs not reset"
    return 1
  fi

  function __handle_dev {
    debug_msg reset_ethtool "resetting dev $1"
    $ETHTOOL -s "$1" autoneg on
    # TODO: restart rest of ethtool parameters if possible
  }
  for dev in $(list_interfaces); do
    if $ETHTOOL "$dev" 2> /dev/null | grep "Supported link modes:" > /dev/null; then
      __handle_dev "$dev"
    fi
  done
}


# Reset ip link
function reset_ip_link {
  local dev; local ipset; local mtu; local multicast; local broadcast

  function __handle_dev {
    # FIXME: do interfaces appear this way on boot?
    # is lo treated this way? if not, put notice
    mtu=1500; multicast=on; broadcast="ff:ff:ff:ff:ff:ff"
    if [ "$1" == "lo" ]; then
      mtu=65536; multicast=off; broadcast="00:00:00:00:00:00"
    fi

    if run_i $IP link del dev "$1"; then
      info_msg reset_ip_link "removed dev $1"
    fi
    if interface_exists "$1"; then
      debug_msg reset_ip_link "resetting dev $1"
      ipset="$IP link set dev $1"
      $ipset state down
      $ipset arp on
      $ipset multicast "$multicast"
      $ipset dynamic off
      $ipset txqlen 1000
      $ipset mtu "$mtu"
      if [ "$1" != "lo" ] && run_i $ETHTOOL -P "$1"; then
        $ipset address $(run_c $ETHTOOL -P "$1" | cut -d' ' -f3)
      fi
      $ipset broadcast "$broadcast"
      # TODO: remove alias
      $ipset group default
      $ipset nomaster
    fi
  }
  for dev in $(list_interfaces); do
    __handle_dev "$dev"
  done
}


# Reset ip [m]address, ip [m]route, ip [m]rule
function reset_ip_basic {
  local dev

  debug_msg reset_ip_basic "flushing all routes"
  $IP route flush table all

  # FIXME (iproute2 3.12): multicast routes can't be changed,
  # but "this limitation may be removed in the future".

  function __handle_dev {
    debug_msg reset_ip_basic "flushing dev $1"
    $IP address flush dev "$1"
    # FIXME: do interfaces appear this way on boot?
    # is lo treated this way? if not, put notice
    if [ "$1" == "lo" ]; then
      $IP address add dev "$1" local 127.0.0.1/8
      $IP address add dev "$1" local ::1/128
    fi
    # TODO: remove multicast addresses
  }
  for dev in $($IP address | grep '^[0-9]' | cut -d' ' -f2 | cut -d':' -f1); do
    __handle_dev "$dev"
  done
}


# Reset ip tunnel
function reset_ip_tunnel {
  # TODO: remove ip tunnels
  true
}


# Reset ip tuntap
function reset_ip_tuntap {
  # TODO: remove ip tun/tap ifs
  true
}


# Reset ip l2tp
function reset_ip_l2tp {
  # TODO: remove ip l2tp tunnels
  true
}


# Reset ip [m]rule
function reset_ip_rule {
  debug_msg reset_ip_rule "flushing all rules"
  $IP rule flush
  $IP rule add priority 32766 table main
  $IP rule add priority 32767 table default

  debug_msg reset_ip_rule "flushing all multicast rules"
  $IP mrule flush
}


# Reset ip neighbour
function reset_ip_neighbour {
  debug_msg reset_ip_neighbour "flushing all neighbours"
  $IP neighbour flush nud all
}


# Reset ip ntable
function reset_ip_ntable {
  # TODO: reset ntable parameters
  true
}


# Reset ip xfrm
function reset_ip_xfrm {
  debug_msg reset_ip_xfrm "flushing all states"
  $IP xfrm state flush

  debug_msg reset_ip_xfrm "flushing all policies"
  $IP xfrm policy flush
}


# Reset iptables
function reset_iptables {
  local chain
  if [ -z "$IPTABLES" ]; then
    warning_msg reset_iptables "iptables not present, firewall not touched"
    return 1
  fi

  function __reset_table {
    debug_msg reset_iptables "flushing table $1"
    $IPTABLES -t "$1" -F && $IPTABLES -t "$1" -X
    for chain in $(run_c $IPTABLES -t "$1" -L | grep '^Chain' | cut -d' ' -f2); do
      debug_msg reset_iptables "resetting policy on $1 $chain"
      $IPTABLES -t "$1" -P "$chain" ACCEPT
    done
  }
  __reset_table mangle
  __reset_table nat
  __reset_table filter
  __reset_table raw
  __reset_table security
}


# Reset ebtables
function reset_ebtables {
  local chain
  if [ -z "$EBTABLES" ]; then
    warning_msg reset_ebtables "ebtables not present, bridge firewall not touched"
    return 1
  fi

  function __reset_table {
    debug_msg reset_ebtables "flushing table $1"
    $EBTABLES -t "$1" -F && $EBTABLES -t "$1" -X
    for chain in $(run_c $EBTABLES -t "$1" | grep -A1 '^Supported chain' | tail -n1); do
      debug_msg reset_ebtables "resetting policy on $1 $chain"
      $EBTABLES -t "$1" -P "$chain" ACCEPT
    done
  }
  __reset_table nat
  __reset_table filter
  __reset_table broute
}


# Reset tc
function reset_tc {
  local dev; local added
  function __reset_root_qdisc {
    # Ensure there's a root qdisc to remove, so that del won't fail
    run_i $TC qdisc add dev "$1" root handle 0: pfifo_fast
    added="$?"
    $TC qdisc del dev "$1" root
    if [ "$added" != 0 ]; then
      info_msg reset_tc "removed qdisc on dev $1"
    fi
  }
  for dev in $(list_interfaces); do
    __reset_root_qdisc "$dev"
  done
}


# Reset variables
function reset_variables {
  # TODO: reset common network variables
  true
}


if [ -z "$__reset_as_library" ]; then
  reset_network
fi
