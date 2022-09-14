sudo docker build -f Client-Dockerfile .
sudo docker run -p8080:8080 -it -d -v havoc-c2-data:/data jenkins-havoc-client
