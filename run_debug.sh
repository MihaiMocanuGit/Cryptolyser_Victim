#!/bin/bash

echo "Setting build options" 
cmake -DCMAKE_BUILD_TYPE=debug -S . -B build-debug 
echo "Building" 
cmake --build build-debug 
echo "Runnning" 
build-debug/Cryptolyser_Victim 8081
