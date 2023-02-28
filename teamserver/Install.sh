#!/bin/bash

sudo apt -qq --yes install golang-go nasm mingw-w64 wget >/dev/null 2>&1

if [ ! -d "dir/x86_64-w64-mingw32-cross" ]; then
	if [ ! -f /tmp/mingw-musl.tgz ]; then
		wget https://musl.cc/x86_64-w64-mingw32-cross.tgz -q -O /tmp/mingw-musl.tgz
	fi

	tar zxf /tmp/mingw-musl.tgz -C data
fi
