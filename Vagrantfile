# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # Use custom Ubuntu Noble box
  # Note: Add the box first with: scripts/download_vm
  config.vm.box = "noble-server"
  
  # Configure VM settings
  config.vm.hostname = "rscaller-dev"
  
  # Use KVM provider (libvirt)
  config.vm.provider :libvirt do |libvirt|
    libvirt.driver = "kvm"
    libvirt.memory = 4096
    libvirt.cpus = 4
    libvirt.disk_bus = "virtio"
    libvirt.nic_model_type = "virtio"
    
    # Enable nested virtualization for kernel development
    libvirt.nested = true
    libvirt.cpu_mode = "host-passthrough"
    
    # Network configuration to avoid warnings
    libvirt.management_network_name = "default"
    libvirt.management_network_address = "192.168.121.0/24"
    
    # Additional settings to reduce warnings
    libvirt.connect_via_ssh = false
    libvirt.storage_pool_name = "default"
    
    
    # Graphics settings for debugging
    # libvirt.graphics_type = "vnc"
    # libvirt.graphics_port = 5900
    # libvirt.graphics_ip = "127.0.0.1"
  end
  
  # Mount the project directory
  config.vm.synced_folder ".", "/vagrant", type: "rsync"
  
  # Additional shared folders for kernel development
  # config.vm.synced_folder ".", "/home/vagrant/rscaller", type: "rsync"
  
  # Network configuration - use management network with hardcoded IP
  # config.vm.network :private_network, :ip => "192.168.56.10"
  
  # Configure SSH for better compatibility
  config.ssh.insert_key = false
  config.ssh.forward_agent = true
  
  
  # Provisioning script
  config.vm.provision "shell", inline: <<-SHELL
    # Configure network interface for management network
    # Configure the management network interface with static IP
    cat > /etc/netplan/50-vagrant.yaml << 'EOF'
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
      dhcp6: false
EOF
    
    # Apply network configuration
    netplan apply
    
    # Update system
    apt-get update
    apt-get upgrade -y
    
    # Install essential development tools
    apt-get install -y \
      build-essential \
      git \
      curl \
      wget \
      vim \
      tmux \
      htop \
      tree \
      unzip \
      software-properties-common \
      apt-transport-https \
      ca-certificates \
      gnupg \
      lsb-release
    
    # Install Docker
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    
    # Add vagrant user to docker group
    usermod -aG docker vagrant
    
    # Install kernel development tools
    apt-get install -y \
      linux-headers-$(uname -r) \
      linux-source \
      libncurses-dev \
      bison \
      flex \
      libssl-dev \
      libelf-dev \
      bc \
      rsync \
      dwarves \
      pahole \
      gdb \
      kgdb \
      kgdb-source
    
    # Install Python and pip for kernel build containers
    apt-get install -y python3 python3-pip python3-venv
    
    # Install Rust
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    echo 'source $HOME/.cargo/env' >> /home/vagrant/.bashrc
    
    # Clone kernel-build-containers
    cd /home/vagrant
    git clone https://github.com/a13xp0p0v/kernel-build-containers.git
    
    # Set up project directory
    chown -R vagrant:vagrant /home/vagrant/rscaller
    chown -R vagrant:vagrant /home/vagrant/kernel-build-containers
    
    # Create kernel build directory
    mkdir -p /home/vagrant/kernel-builds
    chown -R vagrant:vagrant /home/vagrant/kernel-builds
    
    echo "VM setup complete!"
    echo "Project is mounted at /home/vagrant/rscaller"
    echo "Kernel build containers at /home/vagrant/kernel-build-containers"
    echo "Kernel builds will be stored at /home/vagrant/kernel-builds"
  SHELL
  
  
  # Enable GUI for debugging (optional)
  # config.vm.provider :libvirt do |libvirt|
  #   libvirt.graphics_type = "spice"
  #   libvirt.graphics_port = 5900
  #   libvirt.graphics_ip = "127.0.0.1"
  #   libvirt.graphics_autoport = true
  #   libvirt.graphics_password = "vagrant"
  # end
end
