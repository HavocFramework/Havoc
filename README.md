<div align="center">
  <img width="125" src="Assets/Havoc.png">
</div>

## Havoc 
- Havoc is a modern and malleable post-exploitation command and control framework.
- It was designed, developed, and primarily directed by @c5pider.
- If you would like to help contribute code (Contributing.md) or funds for helping with further development(Patreon link: F), both are highly appreciated.

### Contributing
- See 'CONTRIBUTING.md'


### Quick-Start
- Currently, Havoc has been confirmed to work on Debian 10/11, Kali Linux(latest), and Ubuntu 20.04/22.04;
- **Teamserver and Teamserver-Client Quickstart**
	- **Debian 10/11; Kali(rolling); Ubuntu 20.04/22.04 Quickstart Instructions**
		1. Clone the Havoc repo to your local machine:
			* `git clone https://github.com/HavocFramework/Havoc`
		2. Install the pre-requisite packages for the teamserver(Golang 1.19):
			* https://go.dev/doc/install
		3. Navigate into the `./Havoc/Teamserver/` directory, and build the teamserver with the following command:
			* `make`
		4. You should now have the `Teamserver` binary available at `./Havoc/Teamserver/Build/Bin/Teamserver`
		5. You can run the teamserver with the following command:
			* `sudo ./teamserver server --profile ../../profiles/havoc_default.yaotl -v --debug-dev`
			* This should result in the Teamserver now running locally in your terminal.
		6. Now, to build the client, we need to ensure we have the proper packages.
			* We first need to ensure that we have the appropriate repos setup for the necessary packages (Python3.10-dev)
			* `echo 'deb http://ftp.de.debian.org/debian bookworm main' >> /etc/apt/sources.list`
		7. Then we can Install all necessary packages: `sudo apt install -y git build-essential apt-utils cmake	 libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev mingw-w64 nasm python3 python3-pip python3-all-dev python3.10-dev libpyton3.10 libpython3.10-dev python3.10  qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev`
		8. Once we've installed all the pre-requisite packages, we can build the Teamserver-Client:
			* `mkdir Build`
			* `cd Build`
			* `cmake ..`
			* `cd ..`
			* `./Havoc.sh`
		9. The Teamserver-Client should now be built with successful completion of the last command.
		10. Since we Have the Teamserver already running, we can simply launch the Teamserver-Client:
			* `./Havoc`
		11. You should now see the Teamserver-Client window open:
			* <Insert image of teamserver client window>
		12. We must now enter the credentials for the Teamserver we wan	t to connect to:
			* <Insert image of teamserver client window connecting to localhost instance>
		13. We now have a Teamserver instance and an associated client to interact with it running!
- **Creating a Listener, and Spawning an Agent**
	* This part assumes you have a Teamserver running, with a Teamserver-client connected to the running instance.
	- **Creating a Listener:**
		1. To create a new listener, we must first open the `Listeners` subwindow.
			* To do this, in the upper left hand corner, click on the `View` button, and then on the `Listeners` button in the drop down menu.
			* <image>	
		2. You should see a new sub window in the bottom of the server window, with the title of `Listeners` on the header tab.
		3. You should also now see 4 buttons on the bottom of the server window, `Add`, `Remove`, `Restart`, `Edit`.
			* <image>
		4. We want to click the `Add` button.
		5. Once we click the `Add` button, you should see a new window come up, with the title of `Create Listener`.
		6. We will want to fill out the appropriate information for each field in the `Create Listener` window.
			* Please note that you must 'right-click' in order to interact with the `Headers` and `Uris` fields currently.
		7. After entering the appropriate information into each field, then click the `Save` button.
		8. The window will close, and you will now see a new line in the `Listeners` sub-window.
		9. We now have an active Listener, and are ready to receive an incoming agent's communications!
	- **Spawning an Agent:**
		1. To create an Agent Payload, we must first open the `Payload` window.
			* We can do so by going up to the upper left hand corner, and clicking on the `Attack` button. 
		2. Doing so, we see the `Payload` button appear in the drop down menu. We want to then click on it.
		3. This will open the `Payload` window, where we may then configure the various options for generating our payload.
		4. Once we have selected the appropriate options, we then click on the `Generate` button.
			* <image>
		5. It might take a little bit for the compilation to take place. Once it has completed, it will prompt you as to where to save the resulting file output.
		6. After selecting where to save the file, you will now have a generated agent ready for execution or injection!
