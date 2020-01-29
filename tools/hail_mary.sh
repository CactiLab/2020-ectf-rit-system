#!/bin/bash

source /opt/Xilinx/SDK/2017.4/settings64.sh

mkdir global_provisioning/audio -p
./createRegions --region-list "United States" "Japan" "Australia" --outfile global_provisioning/region.secrets
./createUsers --user-list "drew:1234567890" "ben:00000000" "misha:0987654321" --outfile global_provisioning/user.secrets
./protectSong --region-list "United States" --region-secrets-path global_provisioning/region.secrets --outfile global_provisioning/audio/demo.drm --infile ../sample-audio/Sound-Bite_One-Small-Step.wav --owner "drew" --user-secrets-path global_provisioning/user.secrets
./createDevice --region-list "United States" "Japan" --region-secrets-path global_provisioning/region.secrets --user-list "drew" "ben" "misha" --user-secrets-path global_provisioning/user.secrets --device-dir device1
./buildDevice -p ../ -n rit_pl_proj -bf all -secrets_dir device1/
./packageDevice ../boot-image/template.bif device1/miPod.bin ../mb/Cora-Z7-07S/download.bit
./deployDevice /dev/sdb ../BOOT.BIN global_provisioning/audio/ ../mb/miPod/Debug/miPod ../boot-image/image.ub --mipod-bin-path device1/miPod.bin
