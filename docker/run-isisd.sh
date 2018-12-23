#!/bin/bash

# Create IS-IS config
routerid=$(ifconfig | sed -Ee '/192\.168\.1[0-9]\./!d;s,.*inet (addr:)?192\.168\.1[0-9]\.([0-9]*)[ /].*,\2,' | head -1)

# Enable zebra and isis
test -e /etc/frr/daemons && sed -ie 's/zebra=no/zebra=yes/;s/isisd=no/isisd=yes/' /etc/frr/daemons
# root@vagrant:~# more /etc/frr/zebra.conf

mkdir -p /run/frr
chgrp frr /run/frr
chmod 775 /run/frr

cat <<EOF > /etc/frr/zebra.conf
hostname r${routerid}
password lab
enable password lab
log syslog
EOF

cat > /etc/frr/isisd.conf <<EOIF
! -*- isis -*-
!
! ISISd sample configuration file
!
hostname r${routerid}
password foo
enable password foo
log stdout
!log file /tmp/isisd.log
!
!
router isis ring
 net 00.0000.0000.00${routerid}.00
 metric-style wide
 is-type level-1
! lsp-gen-interval 10
! lsp-refresh-interval 60
 lsp-lifetime 360
!  hostname isisd-router
!  area-password foobar
!  domain-password foobar
interface eth0
 ip router isis ring
 isis circuit-type level-1
interface eth1
 ip router isis ring
 isis circuit-type level-1
interface eth2
 ip router isis ring
 isis circuit-type level-1
! isis hello-interval 5
! isis lsp-interval 1000
! -- optional
! isis circuit-type level-1
! isis password lallaa level-1
! isis metric 1 level-1
! isis csnp-interval 5 level-1
! isis retransmit-interval 10
! isis retransmit-throttle-interval
! isis hello-multiplier 2 level-1
! isis priority 64
!
EOIF

# systemctl start zerba
/usr/lib/frr/zebra -d -A 127.0.0.1 -f /etc/frr/zebra.conf
/usr/lib/frr/isisd -A 127.0.0.1 -f /etc/frr/isisd.conf
