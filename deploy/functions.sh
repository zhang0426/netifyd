# Netify Agent Common Functions

[ -f /etc/conf.d/netifyd ] && source /etc/conf.d/netifyd
[ -f /etc/default/netifyd ] && source /etc/default/netifyd
[ -f /etc/sysconfig/netifyd ] && source /etc/sysconfig/netifyd

# Load defaults for RedHat/CentOS/Ubuntu/Debian
function load_defaults
{
    local options=""

    options=$NETIFYD_EXTRA_OPTS

    for entry in $NETIFYD_INTNET; do
        if [ "$entry" == "${entry/,/}" ]; then
            options="$NETIFYD_OPTS -I $entry"
            continue
        fi
        for net in ${entry//,/ }; do
            if [ "$net" == "${entry/,*/}" ]; then
                options="$options -I $net"
            else
                options="$options -A $net"
            fi
        done
    done

    for entry in $NETIFYD_EXTNET; do
        if [ "$entry" == "${entry/,/}" ]; then
            options="$options -E $entry"
            continue
        fi
        for ifn in ${entry//,/ }; do
            if [ "$ifn" == "${entry/,*/}" ]; then
                options="$options -E $ifn"
            else
                options="$options -N $ifn"
            fi
        done
    done

    options=$(echo "$options" |\
        sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$$//g')

    echo $options
}

# ClearOS: Dynamically add all configured LAN/WAN interfaces.
function load_clearos
{
    local options=""

    [ -f /etc/clearos/network.conf ] && source /etc/clearos/network.conf

    for ifn in $LANIF; do
        [ -z "$ifn" ] && break
        options="$options -I $ifn"
    done

    for ifn in $HOTIF; do
        [ -z "$ifn" ] && break
        options="$options -I $ifn"
    done

    for ifn in $EXTIF; do
        [ -z "$ifn" ] && break
        [ -f "/etc/sysconfig/network-scripts/ifcfg-${ifn}" ] &&
            source "/etc/sysconfig/network-scripts/ifcfg-${ifn}"
        if [ ! -z "$ETH" ]; then
            options="$options -E $ETH -N $ifn"
            unset ETH
        else
            options="$options -E $ifn"
        fi
    done

    options=$(echo "$options" |\
        sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$$//g')

    echo $options
}

# NethServer: Dynamically add all configured LAN/WAN interfaces.
function load_nethserver
{
    local options=""
    local ifcfg_sw="/etc/shorewall/interfaces"

    if [ -f "$ifcfg_sw" ]; then
        for ifn in "$(grep '^loc[[:space:]]' $ifcfg_sw | awk '{ print $2 }')"; do
            [ -z "$ifn" ] && break
            options="$options -I $ifn"
        done

        for ifn in "$(grep "^blue[[:space:]]" $ifcfg_sw | awk '{ print $2 }')"; do
            [ -z "$ifn" ] && break
            options="$options -I $ifn"
        done

        for ifn in "$(grep "^orang[[:space:]]" $ifcfg_sw | awk '{ print $2 }')"; do
            [ -z "$ifn" ] && break
            options="$options -I $ifn"
        done

        for ifn in "$(grep '^net[[:space:]]' $ifcfg_sw | awk '{ print $2 }')"; do
            [ -z "$ifn" ] && break
            [ -f "/etc/sysconfig/network-scripts/ifcfg-${ifn}" ] &&
                source "/etc/sysconfig/network-scripts/ifcfg-${ifn}"
            if [ ! -z "$ETH" ]; then
                options="$options -E $ETH -N $ifn"
                unset ETH
            else
                options="$options -E $ifn"
            fi
        done
    fi

    options=$(echo "$options" |\
        sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$$//g')

    echo $options
}

function load_modules
{
    /sbin/modprobe -q nfnetlink
    /sbin/modprobe -q nf_conntrack_netlink
}

function detect_os
{
    if [ -f /etc/clearos-release ]; then
        echo "clearos"
    elif [ -f /etc/nethserver-release ]; then
        echo "nethserver"
    elif [ -f /etc/gentoo-release ]; then
        echo "gentoo"
    else
        echo "unknown"
    fi
}

function auto_detect_options
{
    local options=""

    options=$(load_defaults)

    if [ "$NETIFYD_AUTODETECT" != "yes" ]; then
        echo $options
    else
        case "$(detect_os)" in
            clearos)
                options=$(load_clearos)
            ;;
            nethserver)
                options=$(load_nethserver)
            ;;
        esac
    fi

    echo $options
}

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4 syntax=sh
