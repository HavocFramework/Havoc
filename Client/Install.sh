echo "[*] Install needed libraries and packages for the Havoc client..."

sudo apt update
sudo apt --yes install cmake make python3-dev qtbase5-dev libqt5websockets5-dev libspdlog-dev python3-dev libboost-all-dev g++ gcc

make clean
./Build.sh
cmake --build Build
echo "[*] Libs are installed and Client has been build."
