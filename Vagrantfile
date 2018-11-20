# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.define "r10" do |r|
    r.vm.box = "hashicorp/precise32"

    # Add a private network between routers
    r.vm.network("private_network", ip: "192.168.10.10")
    r.vm.provision :shell, path: "bootstrap-gen-r10.sh"
  end
end
