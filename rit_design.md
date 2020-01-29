# 2020 MITRE Collegiate eCTF RIT System Design and Implementation

## Getting Started

## Vulnerabilities in the MITRE reference system

 * 

## Project structure
The example code is structured as follows

 * `boot-image/` - Contains a stock FSBL, `image.ub`, and `u-boot.elf` for booting the project on the board. The stock FSBL is only provided for the purposes of making the `miPod.bin`, since `bootgen` requires you provide a bootloader when creating a `.bin` image.
 * `mb/` - Contains example DRM project for running on the soft-core MicroBlaze. See [DRM README](mb/README.md)
 * `miPod/` - Contains example miPod project for running the Linux-side miPod driver. See [miPod README](miPod/README.md)
 * `pl/` - Contains example PL implementation with soft-core MicroBlaze and audio codec. See [PL README](pl/README.md)
 * `tools/` - Contains example provisioning tools. See [tools README](tools/README.md)
 * `vagrant/` - Contains files for configuring the Vagrant environment. See [Vagrant README](vagrant/README.md)
 * `vivado-boards/` - Contains Vivado libraries for the board
 * `Vagrantfile` - Vagrantfile for launching the Vagrant environment - DO NOT CHANGE
 * `sample-audio` - Sample audio files for you to use

## RIT System (design 0)

  See `cacti_sig.c` and `memops.c` in the mb src directory for a partial (libsodium integration not complete) implementation.
  
  Each song file contains the following protections:
    a drm header with the owner, approved regions, and some other metadata. this is signed at build-time by a mipod private key (which is deleted after build), and verified at run-time with the public key.
    a shared users section, containing all users shared with. this is signed (along with the preceeding drm header) by a derived key based on the user's pin combined with a salt.
    each audio segment in the song contains the song id (a 12-16 byte unique ID), and its relative segment index, and is encrypted with a key stored in hardware. this is verified with the mipod private key before decryption.
  
  The key derivation process should look similar to the following:
    mipod sends username and pin to fpga
    fpga copies it into local memory and verifies the user exists
    fpga loads a per-user hardware-stores salt value, and combines it with the user pin
    fpga sends that value to a KDF (scrypt+sha512 seems to be the most punishing we can get away with and still make a standalone application with, due to argon2 memory requirements (ie too many malloc() calls))
    fpga stores (locally) the derived value and signs some value, then attempts to verify the signature with the public key.
    fpga tells the mipod application success/fail.
    
