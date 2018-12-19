# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.define "r10" do |r|
    r.vm.box = "bento/ubuntu-18.04"
    # r.vm.box = "bento/ubuntu-16.04"
    # r.vm.box = "hashicorp/precise32"

    # Add a private network between routers
    r.vm.network("private_network", ip: "192.168.11.10")
    r.vm.network("private_network", ip: "192.168.12.10")
    r.vm.provision :shell, path: "bootstrap-gen.sh"
  end
  config.vm.define "r20" do |r|
    r.vm.box = "bento/ubuntu-18.04"
    # r.vm.box = "bento/ubuntu-16.04"
    # r.vm.box = "hashicorp/precise32"

    # Add a private network between routers
    r.vm.network "private_network", ip: "192.168.13.20"
    r.vm.network "private_network", ip: "192.168.12.20"
    r.vm.provision :shell, path: "bootstrap-gen.sh"
  end
end
