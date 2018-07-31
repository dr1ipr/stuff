#!/bin/bash

if [ "$#" -ne 2 ]; then
	echo "Usage: $0 go_x86_script.go output.exe"
	exit
fi

# take the first argument and build an x86 binary from go
filename=$(basename $1)
filename2=$(basename $2)
sans_extension="${filename2%.*}"

echo [*] Copy Files to tmp for building
mkdir -p /tmp/MemoryModule/build/

rsync -r ./MemoryModule/build686/ /tmp/MemoryModule/build/

cp ./MemoryModule/MemoryModule.h /tmp/MemoryModule/

cp $1 /tmp/$sans_extension.go

cd /tmp/
echo [*] Building...
export GOOS=windows; export GOARCH=386; export CGO_ENABLED=1; export CXX=i686-w64-mingw32-g++; export CC=i686-w64-mingw32-gcc
GOOS=windows; CXX=i686-w64-mingw32-g++; CC=i686-w64-mingw32-gcc; GCCFLAGS="-m32 -fmessage-length=0" CGO_ENABLED=1 GOOS=windows GOARCH=386 go build $sans_extension.go 

echo [*] Building complete

rm -rf /tmp/MemoryModule

cd - 1> /dev/null

echo [*] Copy $2 to output

cp /tmp/$2 ./output/

echo [*] Cleaning up

rm /tmp/$2 
rm /tmp/$sans_extension.go

echo [*] Done
