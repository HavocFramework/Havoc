# Havoc Teamserver Client

Havoc Gui Client source code. 

### Build the Teamserver Client
- **Pre-requisites**
	- Package list:
		1. `Python-3.10`
		2. `python3-dev`
		3. `libspdlog-dev`
		4. `qt5`-packages
		5. `libboost-all-dev`
	- **If you are running Ubuntu 20.04/22.04** as your base OS, you must first enable Python3.10 in your APT repos before you will be able to run the client successfully:
		1. `sudo apt install build-essential`
		2. `sudo add-apt-repository ppa:deadsnakes/ppa`
		3. `sudo apt update`
		4. `sudo apt install python3.10 python3.10-dev`
	- **If you are running Debian 10/11** as your base OS, you must also first setup the `bookworm` repo for getting Python3.10:
		1. `sudo apt install build-essential`
		2. `sudo apt update`
		2. `echo 'deb http://ftp.de.debian.org/debian bookworm main' >> /etc/apt/sources.list`
		4. `sudo apt install python3-dv python3.10-dev libpython3.10 libpython3.10-dev python3.10`
		5. One liner for installing all necessary packages: `sudo apt install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev`
- **Local Build**
	- To build the Teamserver Client locally, perform the following steps:
		1. `make`
		5. `./Havoc`
	- You should now have a fully built Teamserver client available.
- **Docker Build**
	- To build the Teamserver Client with Docker, perform the following steps:
		1. Build the Dockerfile with Jenkins:
			* `sudo docker build -t havoc-client -f Client-Dockerfile .``
		2. (Optionally) Create a data volume for persistence:
			* `sudo docker volume create havoc-c2-client`
		2. Next, we want to run the container:
                        * `sudo docker run -p 443:443 -p 40056:40056 -it -d -v havoc-c2-client:/data havoc-client`
                3. We can now enter the built container and execute the client.
			* Currently, there is no remote viewing of the container, so, good luck with that.
- **Jenkins Docker Build**
	- To Create a Jenkins instance to perform repeated or modified builds of the Teamserver client, perform the following steps:
		1. Build the Dockerfile with Jenkins(located in the `Havoc`-root folder):
			* `sudo docker build -f JC-Dockerfile .`
		2. Next, we want to run the container:
			* `sudo docker run -p8080:8080 -it -d -v havoc-c2-data:/data havoc-client`
		3. We can now visit Jenkins at `localhost:8080` and create a Pipeline to build the Havoc Teamserver!
			* For a pre-done Groovy script, please see the `Havoc-Teamserver.groovy` in the `Assets` folder.
