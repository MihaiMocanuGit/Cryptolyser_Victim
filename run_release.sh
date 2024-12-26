#!/bin/bash

echo "Setting build options" 
cmake -DCMAKE_BUILD_TYPE=release -S . -B build-release 
echo "Building" 
cmake --build build-release 
echo "Runnning" 
build-release/Cryptolyser_Victim 8081
