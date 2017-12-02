# -*- mode: ruby -*-
# vi: set ft=ruby :
# Author: David Manouchehri

Vagrant.configure("2") do |config|
	config.vm.box = "bento/ubuntu-16.04"

	config.vm.synced_folder ".", "/vagrant", disabled: true

	config.vm.provision "shell", inline: <<-SHELL
		apt-get update
		# DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
		DEBIAN_FRONTEND=noninteractive apt-get -y install ccache cmake make g++-multilib gdb pkg-config realpath python-pexpect manpages-dev git ninja-build capnproto libcapnp-dev
		apt-get clean
	SHELL

	config.vm.provision "shell", privileged: false, inline: <<-SHELL
		git clone https://github.com/mozilla/rr.git
		cd rr
		mkdir obj
		cd obj
		cmake ..
		make -j8
		make test
	SHELL

	config.vm.provision "shell", inline: <<-SHELL
		cd /home/vagrant/rr/obj/
		make install
	SHELL

	%w(vmware_fusion vmware_workstation vmware_appcatalyst).each do |provider|
		config.vm.provider provider do |v|
			v.vmx["memsize"] = "4096"
			v.vmx['vpmc.enable'] = 'true'
			v.vmx['vhv.enable'] = 'true'
			v.vmx['vvtd.enable'] = 'true'
			v.vmx['monitor_control.disable_hvsim_clusters'] = 'true'
			v.vmx['virtualHW.version'] = '14'
			v.vmx['ethernet0.virtualDev'] = 'vmxnet3'
		end
	end
end
