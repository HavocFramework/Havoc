echo "[*] Install libs for the teamserver..."

sudo apt --yes install golang-go nasm mingw-w64 wget 

wget https://musl.cc/x86_64-w64-mingw32-cross.tgz -O /tmp/mingw-musl.tgz 
tar zxvf /tmp/mingw-musl.tgz -C data
