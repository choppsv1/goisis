# Install packages
apt-get update
apt-get install -y quagga quagga-doc

# Enable zebra and isis
sed -ie 's/zebra=no/zebra=yes/;s/isisd=no/isisd=yes/' /etc/quagga/daemons

# Copy default zebra config
cp /usr/share/doc/quagga/examples/zebra.conf.sample /etc/quagga/zebra.conf

# Create IS-IS config
cat > /etc/quagga/isisd.conf <<EOIF
    hostname r10
    password lab
    enable password lab
    interface eth1
      ip router isis ring
    interface lo
    router isis ring
      net 00.0000.0000.0010.00
      metric-style wide
    line vty
EOIF

service quagga restart
