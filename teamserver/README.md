# Havoc Teamserver

Source code of Havoc teamserver. Written in Golang.


### Build the Teamserver
- **Pre-requisites**
	1. Go1.18
- **Native**
	- To build the Teamserver client locally, run the following command in this folder(`~/Havoc/Teamserver/`):
		1. `make`
	- That's it! If it ran successfully to completion, you should now have a compiled binary ready for use in the `/bin` folder.
	- Example use with a prewritten profile: `sudo ./teamserver server --profile profiles/havoc.yaotl --verbose`
	- Example use with default profile: `sudo ./teamserver --default --verbose`
- **Docker**
	- To build the Teamserver client using a local Docker container, run the following commands(assuming you have Docker installed):
		1. Build the Dockerfile:
			* `sudo docker build -t havoc-teamserver -f Teamserver-Dockerfile .`
		2. (Optional) Create a persistent data volume for the container:
			* `sudo docker volume create havoc-c2-data`
		3. Run the container:
			* `sudo docker run -it -d -v havoc-c2-data:/data havoc-teamserver`
- **Jenkins Docker**
	- We can also build the Teamserver binary using a pre-configured Jenkins Docker image.
		1. From the parent folder(`Havoc`), run the following command to build the container:
			* `sudo docker build -t jenkins-havoc-teamserver -f JT-Dockerfile .``
		2. (Optionally) Create a persistent data volume for the container:
			* `sudo docker volume create havoc-cicd-c2-data`
		2. Next, we want to run the container:
			* `sudo docker run -p8080:8080 -it -d -v havoc-cicd-c2-data:/data jenkins-havoc-teamserver`
		3. We can now visit Jenkins at `localhost:8080` and create a Pipeline to build the Havoc Teamserver!
			* For a pre-done Groovy script, please see the `Havoc-Teamserver.groovy` in the `Assets` folder.


### Run the Teamserver
- **Base:**
	- The teamserver can also be used directly:
		* `./teamserver -h`
		* `./teamserver server --profile profiles/havoc.yaotl -v`
		* `./teamserver server --default -v`
- **Docker**
	- We can run the teamserver completely from within a container!
	1. Build the container: 
		* `sudo docker build -f Client-Dockerfile .`
	2. Launch the container (be sure to change the port mapping to match your environment):
		* `sudo docker run -p40056:40056 -p 443:443 -it -d -v havoc-c2-data:/data jenkins-havoc-client`
	3. Access the teamserver at `localhost:40056` using your Teamserver client.
