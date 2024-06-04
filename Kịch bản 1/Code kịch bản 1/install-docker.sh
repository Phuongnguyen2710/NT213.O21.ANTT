#to remove old versions
sudo apt-get remove docker docker-engine docker.io containerd runc

#dependencies install
sudo apt-get update
sudo apt-get install --yes \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common
    
#adding GPG key
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -

#adding repository
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/debian \
   buster \
   stable"
   
#fresh install docker engine
sudo apt-get update
sudo apt-get install --yes docker-ce docker-ce-cli containerd.io

#downloading docker compose
sudo curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
