#!/bin/bash

# Create IS-IS config
routerid=$(ifconfig | sed -Ee '/192\.168\.1[0-9]\./!d;s,.*inet (addr:)?192\.168\.1[0-9]\.([0-9]*)[ /].*,\2,' | head -1)

# Enable zebra and isis
test -e /etc/quagga/daemons && sed -ie 's/zebra=no/zebra=yes/;s/isisd=no/isisd=yes/' /etc/quagga/daemons
# root@vagrant:~# more /etc/quagga/zebra.conf

mkdir -p /run/quagga
chgrp quagga /run/quagga
chmod 775 /run/quagga

cat <<EOF > /etc/quagga/zebra.conf
hostname r${routerid}
password lab
enable password lab
log syslog
EOF

cat > /etc/quagga/isisd.conf <<EOIF
hostname r${routerid}
interface lo
line vty
log stdout
router isis ring
    net 00.0000.0000.00${routerid}.00
    metric-style wide
    is-type level-1
    lsp-gen-interval 10
    lsp-refresh-interval 60
    max-lsp-lifetime 360
interface eth0
    ip router isis ring
    isis circuit-type level-1
interface eth1
    ip router isis ring
    isis circuit-type level-1
interface eth2
    ip router isis ring
    isis circuit-type level-1
EOIF

# systemctl start zerba
zebra -d -A 127.0.0.1 -f /etc/quagga/zebra.conf
isisd -A 127.0.0.1 -f /etc/quagga/isisd.conf
