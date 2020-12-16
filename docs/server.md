# CouchDB server 

Before you can make use of the bbrf client, make sure you set up a bbrf server first. The tool was built to work with the document-based database [CouchDB](couchdb.apache.org) and a number of preconfigured views that enable querying the data in a format that suits the use cases of the bbrf client.

For the best results, I recommend you deploy to a VPS so you can interact with the data from all your machines, VPS boxes and lambdas.

## Manual

Skip ahead to [server-install.sh below](#server-installsh) to try an automated installation of the server. A manual installation requires the following:

* Deploy the [CouchDB image from Bitnami](https://aws.amazon.com/marketplace/pp/B01M0RA8RQ?ref=cns_srchrow) from the AWS Marketplace or using docker:
    ```bash
    curl -sSL https://raw.githubusercontent.com/bitnami/bitnami-docker-couchdb/master/docker-compose.yml > docker-compose.yml
    docker-compose up -d
    ```
* My current setup runs on a `t3a.small` tier in AWS and seems to effortlessly support 116 thousand documents at the time of writing;
* I strongly suggest enabling (only) https on your server;
* When up and running, browse to the web interface on `https://<your-instance>:6984/_utils/#/_all_dbs` and check if everything's OK
* Create the `bbrf` user (additional documentation [here](https://docs.couchdb.org/en/stable/intro/security.html)) via curl:

    ```bash
    COUCHDB=https://<yourinstance>:6984/
    
    curl -X PUT $COUCHDB"_users" \
         -u admin:password
         
    curl -X PUT curl -X PUT $COUCHDB"/_users/org.couchdb.user:bbrf" \
         -u admin:password \
         -H "Accept: application/json" \
         -H "Content-Type: application/json" \
         -d '{"name": "bbrf", "password": "<choose a decent password>", "roles": [], "type": "user"}'
    ```

* Create a new database called `bbrf`:

    ```bash
    curl -X PUT $COUCHDB"bbrf" \
         -u admin:password
    ```

* Grant access rights to the new database:
    ```bash
    curl -X PUT $COUCHDB"bbrf/_security" \
         -u admin:password \
         -d "{\"admins\": {\"names\": [\"bbrf\"],\"roles\": []}}"
    ```

* Configure the required views via curl:
    ```bash
    curl -X PUT $COUCHDB"bbrf/_design/bbrf" \
         -u admin:password \
         -H "Content-Type: application/json" \
         -d @views.json
    ```

## server-install.sh


Thanks to [@plenumlab](https://twitter.com/plenumlab), you can run the following for an easy out-of-the-box installation of the CouchDB server. Run this on the VPS where you want to install the server. This script requires Docker.

  * `git clone https://github.com/honoki/bbrf-client`
  * `cd bbrf-client`
  * `chmod +x server-install.sh`
  * `./server-install.sh`