#!/bin/bash
echo "Building disassembler for Linux..."
g++ core/disassembler.cpp -o core/disassembler -Icore/include core/capstone.lib
if [ $? -eq 0 ]; then
    echo "Build successful!"
else
    echo "Build failed!"
    exit 1
fi
