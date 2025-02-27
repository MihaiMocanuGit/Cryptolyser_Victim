#!/bin/bash

export OPENSSL_ia32cap="~0x200000200000000"
export OPENSSL_armcap=0X1B
build_type=$1

echo "build_type = $build_type"
echo "OPENSSL_ia32cap = $OPENSSL_ia32cap"
echo "OPENSSL_armcap = $OPENSSL_armcap"

echo "Setting build options"
time (cmake -DCMAKE_BUILD_TYPE="$build_type" -S . -B build-"$build_type" && echo "Building $build_type" && cmake --build build-"$build_type")

echo "Running"
sudo nice -n -20 build-"$build_type"/Cryptolyser_Victim 8081

#OPENSSL_armcap=0x1B: This forces OpenSSL to disable ARMv8 crypto extensions, effectively disabling hardware acceleration on ARM (including AES instructions on a Raspberry Pi 4).
#OPENSSL_ia32cap="~0x200000200000000": Disables AES-NI on x86/x64 systems

#From OpenSSL crypto/arm_arch.h:
# # define ARMV7_NEON      (1<<0)
# # define ARMV7_TICK      (1<<1)
# # define ARMV8_AES       (1<<2)
# # define ARMV8_SHA1      (1<<3)
# # define ARMV8_SHA256    (1<<4)
# # define ARMV8_PMULL     (1<<5)
#
# We want:
# 5 4 3 2 1 0
# 0 1 1 0 1 1 -> 1B
