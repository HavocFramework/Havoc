#!/bin/bash

if [ ! -d "dir/x86_64-w64-mingw32-cross" ]; then
	sudo apt -qq --yes install golang-go nasm mingw-w64 wget >/dev/null 2>&1
	if [ ! -f /tmp/mingw-musl.tgz ]; then
		wget https://musl.cc/x86_64-w64-mingw32-cross.tgz -q -O /tmp/mingw-musl.tgz
	fi
	
	if [ ! -d "data" ]; then
		mkdir data
	fi

	tar zxf /tmp/mingw-musl.tgz -C data
fi
