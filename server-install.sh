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

echo "Would you like to install CouchDB first? (Requires docker.io & docker-compose.)"
PS3="Please select an option (1 Or 2): "
choices=("yes" "no")
select choice in "${choices[@]}"; do
        case $choice in
                yes)

                                        echo "Downloading CouchDb docker-compose file"
                                        curl -sSL https://raw.githubusercontent.com/bitnami/bitnami-docker-couchdb/master/docker-compose.yml > docker-compose.yml
										echo "Replacing default password and removing ports 9100,4369"
										adminpass=$(openssl rand -base64 32)
										
										# Check if script is ran on MacOs, if so: use extra single quotes in SED command.
										if [[ "$OSTYPE" == "darwin"* ]]; then MACOS="''"; fi
										
										sed -i $MACOS "s|=couchdb|=$adminpass|g" docker-compose.yml
										sed -i $MACOS "s|- '4369:4369'||g" docker-compose.yml
										sed -i $MACOS "s|- '9100:9100'||g" docker-compose.yml
										echo "Your administrator username is admin"
										echo "Your administrator password is $adminpass"
                                        docker-compose up -d
                                        sleep 1
                                        break
                                        ;;
                no)
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
read -p 'Password (leave blank to generate a strong one): ' upass
[ -z "$upass" ] && upass=$(openssl rand -base64 32) && echo "Password for low-privilege user is: $upass"

echo "Creating the low-privilege user..."
curl -u $admin:$passwd -X PUT $url/_users/org.couchdb.user:$user \
     -H "Accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{\"name\": \"$user\", \"password\": \"$upass\", \"roles\": [], \"type\": \"user\"}"

echo "Configuring access rights to the BBRF database..."
curl -u $admin:$passwd -X PUT $url/bbrf/_security -d "{\"admins\": {\"names\": [\"$user\"],\"roles\": []}}"

echo "Creating required views..."
curl -u $user:$upass -X PUT $url/bbrf/_design/bbrf -d @views.json



echo -e "\nCreate a (default) config file under ~/.bbrf/config.json :\n"
echo -e "{\n\"username\": \"$user\",\n \"password\": \"$upass\",\n\"couchdb\": \"$url/bbrf\",\n \"slack_token\": \"$slack\"\n}" 


echo -e "\nBelow is an example of the bash function :\n"
echo -e "function bbrf() {\nsource $PWD/.env/bin/activate; \npython $PWD/bbrf.py \"\$@\" \ndeactivate \n}\n"

echo "Server setup completed..."
