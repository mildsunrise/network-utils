# Collection of utilities used in other scripts
# by sourcing this script.

function run_c {
  LC_ALL=C LANG=C LANGUAGES=C $*
}
function run_i {
  $* > /dev/null 2> /dev/null
}

function interface_exists {
  run_i ip link show dev "$1"
}
function list_interfaces {
  $IP link | grep '^[0-9]' | cut -d' ' -f2 | cut -d':' -f1 | cut -d'@' -f1
}

__verbosity="${VERBOSE:-1}"
function debug_msg {
  if [ "$__verbosity" -lt 3 ]; then return 0; fi
  echo "DEBUG [$1]: $2"
}
function info_msg {
  if [ "$__verbosity" -lt 2 ]; then return 0; fi
  echo "INFO [$1]: $2"
}
function warning_msg {
  if [ "$__verbosity" -lt 1 ]; then return 0; fi
  echo "WARNING [$1]: $2"
}
function error_msg {
  if [ "$__verbosity" -lt 0 ]; then return 0; fi
  echo "ERROR [$1]: $2"
}

function auto_sudo {
  if [ "$UID" != 0 ]; then
    sudo -E $0 $*; exit
  fi
}
