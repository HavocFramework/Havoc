#!/bin/bash

if [ ! -d "dir/x86_64-w64-mingw32-cross" ]; then
	sudo apt -qq --yes install golang-go nasm mingw-w64 wget >/dev/null 2>&1

	if [ ! -d "data" ]; then
		mkdir data
	fi

	if [ ! -f /tmp/mingw-musl-64.tgz ]; then
		wget https://musl.cc/x86_64-w64-mingw32-cross.tgz -q -O /tmp/mingw-musl-64.tgz
	fi


	tar zxf /tmp/mingw-musl-64.tgz -C data

	if [ ! -f /tmp/mingw-musl-32.tgz ]; then
		wget https://musl.cc/i686-w64-mingw32-cross.tgz -q -O /tmp/mingw-musl-32.tgz
	fi

	tar zxf /tmp/mingw-musl-32.tgz -C data
fi
