# Setup the environment

## Step 1: 

download eCTF source code

```shell
git clone https://github.com/mitre-cyber-academy/2020-ectf-insecure-example --recursive
git remote rename origin mitre
```

## Step 2: 

download Xilinx 2017.4 version (you need to create your own account)

https://www.xilinx.com/member/forms/download/xef-vivado.html?filename=Xilinx_Vivado_SDK_2017.4_1216_1.tar.gzPut 

this file in your download mitre repo root, no need to unzip.

## Step 3: setup the VM (50 GB disk, 2 CPU threads, 4 GB ram)

Install VirtualBox **6.0.12** + Extension pack https://www.virtualbox.org/wiki/Download_Old_Builds_6_0Install [vagrant](https://www.vagrantup.com/downloads.html), the latest version is 2.2.6,

for ubuntu, you can download it and just copy it to the /usr/bin file. 

```shell
mv download_path/Vagrant /usr/bin
```

## Step 4: Install the VM

In the mitre directory: 

```shell
vagrant up
```

## Step 5: Install the Xilinx 

in the VM --> Chose webpack
Building example:

Check sharing files in /ectf/

Login the VM, `cd /ectf/tools/`, then follow steps:[**https://github.com/mitre-cyber-academy/2020-ectf-insecure-example/blob/master/getting_started.md#building-the-reference-design**](https://github.com/mitre-cyber-academy/2020-ectf-insecure-example/blob/master/getting_started.md#building-the-reference-design)



# Errors

### sharing folder empty or permission denied

If the shared folder /ectf is empty, maybe modify them manually**![img](https://lh5.googleusercontent.com/sGw6UPKgd3X3HYKkFXIUyKiZNSPCmQJ5-mLDkSmi0bmcpRtDnK0GMiTWSEeRxozwXeT59yTueAW3WIlMKo8238SaGVKtPBA9YNt9MRJeToI1SxVuX-VhnCzRZL9AO89oFa-ibEMh)**

In your VM, input command

```shell
sudo usermod -a -G vboxsf vagrant
```

Then reboot the VM

### file format

If you use the windows as the host, when you run the example code in the VM, you may meet such error, that’s because of the format of the file

> /usr/bin/env: ‘python3\r’: No such file or directory

```shell
sudo apt install dos2unix
dos2unix yourfile_name 
```

### time skew

> make: warning: Clock skew detected.

Change the time of your VM:

```
sudo date <mmddhrmnyyyy>
Eg. sudo date 012219002020
```

### command not found

> bootgen: command not found

Load the source of xilinx

```
cd <xilinx>; 
source settings.sh
```