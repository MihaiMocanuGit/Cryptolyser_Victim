#!/bin/bash

time (echo "Setting build options" && cmake -DCMAKE_BUILD_TYPE=release -S . -B build-release && echo "Building" && cmake --build build-release) && echo "Running" && build-release/Cryptolyser_Victim 8081
