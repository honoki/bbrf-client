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
                                       
\"I added some ASCII art because you can't have a bash script without ASCII art\"  - @plenumlab

"
echo "Would you like to install CouchDB first? (Requires docker-compose.)"
PS3="Please select an option : "
choices=("yes" "no")
select choice in "${choices[@]}"
do
    case "$choice" in
        "yes")
            echo "Downloading docker compose "
            curl -sSL https://raw.githubusercontent.com/bitnami/bitnami-docker-couchdb/master/docker-compose.yml > docker-compose.yml
            docker-compose up -d
            sleep 1
            break
            ;;
        "no")
            echo "Skipping CouchDB installation ..."
            sleep 1
            break
            ;;
    esac
done

echo -e "To configure the BBRF CouchDB server, please enter your: "
read -p 'CouchDB administrator: ' admin
read -p 'Administrator password: ' passwd
read -p 'CouchDB URL in format [proto]://[host]:[port]: ' url

echo "Creating BBRF database..."  
curl -u $admin:$passwd -X PUT $url/bbrf 

echo "Please enter the details for a new user in CouchDB."
read -p 'Username: ' user
read -p 'Password: ' upass

echo "Creating the low-privilege user..."
curl -u $admin:$passwd -X PUT $url/_users/org.couchdb.user:bbrf \
     -H "Accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{\"name\": \"$user\", \"password\": \"$upass\", \"roles\": [], \"type\": \"user\"}"

echo "Configuring access rights to the BBRF database..."
curl -u $admin:$passwd -X PUT $url/bbrf/_security -d "{\"admins\": {\"names\": [\"$user\"],\"roles\": []}}"

echo "Creating required views..."
curl -u $user:$upass -X PUT $url/bbrf/_design/bbrf -d @views.json

# echo "Saving default config to ~/.bbrf/config.json"
# mkdir ~/.bbrf/
# touch ~/.bbrf/config.json
# read -p 'Please enter a Slack token: ' slack
# echo -e "{\n\"username\": \"$user\",\n \"password\": \"$upass\",\n\"couchdb\": \"$url/bbrf\",\n \"slack_token\": \"$slack\"\n}" >> ~/.bbrf/config.json

# echo -e "function bbrf() {\nsource $PWD/.env/bin/activate; \npython $PWD/bbrf.py \"\$@\" \ndeactivate \n}\n" >> ~/.bash_profile
# source ~/.bash_profile

echo "All done ./bbrf"