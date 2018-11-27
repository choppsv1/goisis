    # Install packages
    apt-get update
    apt-get install -y quagga quagga-doc

    # Create IS-IS config
    routerid=$(ifconfig | sed -Ee '/192\.168\.1[0-9]\./!d;s,.*inet (addr:)?192\.168\.1[0-9]\.([0-9]*)[ /].*,\2,' | head -1)

    # Enable zebra and isis
    test -e /etc/quagga/daemons && sed -ie 's/zebra=no/zebra=yes/;s/isisd=no/isisd=yes/' /etc/quagga/daemons
    # root@vagrant:~# more /etc/quagga/zebra.conf

    cat <<EOF > /etc/quagga/zebra.conf
hostname r${routerid}
password lab
enable password lab
EOF

    cat > /etc/quagga/isisd.conf <<EOIF
interface eth1
    ip router isis ring
interface lo
router isis ring
    net 00.0000.0000.00${routerid}.00
    metric-style wide
    is-type level-1
    lsp-gen-interval 10
    lsp-refresh-interval 60
    max-lsp-lifetime 360
line vty
EOIF
    systemctl start isisd || service quagga restart
