#!/bin/bash


echo "
	/|        /|                          
	||        ||                     _.._ 
	||        ||        .-,.--.    .' .._|
	||  __    ||  __    |  .-. |   | '    
	||/'__ '. ||/'__ '. | |  | | __| |__  
	|:/   '. '|:/   '. '| |  | ||__   __| 
	||     | |||     | || |  '-    | |    
	||\    / '||\    / '| |        | |    
	|/\'..' / |/\'..' / | |        | |    
	'   '-'   '   '-'   |_|        | |    
								   |_|    
"

echo "Would you like to install couchdb"
PS3="Please select an option : "
choices=("yes" "no")
select choice in "${choices[@]}"; do
        case $choice in
                yes)

                                        echo "Donwloading docker compose "
                                        curl -sSL https://raw.githubusercontent.com/bitnami/bitnami-docker-couchdb/master/docker-compose.yml > docker-compose.yml
                                        docker-compose up -d
                                        sleep 1
                                        break
                                        ;;
                                no)
                                        echo "Skipping couchdb installation ..."
                                        sleep 1
                                        break
                                        ;;
        esac
done

echo -e "To begin initialization please fill your: "
read -p 'Couchdb administrator: ' admin
read -p 'Administrator password: ' passwd
read -p 'Couchdb Url in format [proto]://[host]:[port]: ' url

echo "Creating BBRF DB"  
curl -u $admin:$passwd -X PUT $url/bbrf 

read -p 'BBRF username: ' user
read -p 'BBRF password: ' upass

echo "Creating user in couchdb users"
curl -u $admin:$passwd -X PUT $url/_users/org.couchdb.user:bbrf \
     -H "Accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{\"name\": \"$user\", \"password\": \"$upass\", \"roles\": [], \"type\": \"user\"}"

echo "Adding user to BBRF DB "
curl -u $admin:$passwd -X PUT $url/bbrf/_security -d "{\"admins\": {\"names\": [\"$user\"],\"roles\": []}}"

echo "Creating views"
curl -u $user:$upass -X PUT $url/bbrf/_design/bbrf -d @views.json

mkdir ~/.bbrf/
touch ~/.bbrf/config.json
read -p 'Slack Token: ' slack
echo -e "{\n\"username\": \"$user\",\n \"password\": \"$upass\",\n\"couchdb\": \"$url/bbrf\",\n \"slack_token\": \"$slack\"\n}" >> ~/.bbrf/config.json
echo "Default config file created ~/.bbrf/config.json"

echo -e "function bbrf4() {\nsource $PWD/.env/bin/activate; \npython $PWD/bbrf.py \"\$@\" \ndeactivate \n}\n">> ~/.bash_profile
source ~/.bash_profile
echo "All done ./bbrf"
