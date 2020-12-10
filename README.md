# bbrf-client

The client component of the Bug Bounty Reconnaissance Framework (BBRF) is intended to facilitate the workflows of security researchers across multiple devices.

Read the blog post: https://honoki.net/2020/10/08/introducing-bbrf-yet-another-bug-bounty-reconnaissance-framework/

The primary function of the client is providing easy access to information that is stored in a centralized BBRF document store. For example, to quickly create and initialize a new program with a couple of domains, you can try:

```bash
# create a new program
bbrf new vzm
bbrf inscope add '*.yahoo.com' '*.yahoo.be'
bbrf domain add www.yahoo.com www.yahoo.be
```

To add a list of ips from a file or other program, you can pipe into `bbrf`:

```bash
bbrf use vzm
cat ips.txt | bbrf ip add -
```

Now, to list all known domains belonging to the active program:

```bash
bbrf domains
```

## Installation

### CouchDB server 

To use the bbrf client, make sure you set up the bbrf server first. The tool was built to work with the document-based database [CouchDB](couchdb.apache.org). Below is a suggested way of deploying, but YMMV.

#### Manually

* Deploy the [CouchDB image from Bitnami](https://aws.amazon.com/marketplace/pp/B01M0RA8RQ?ref=cns_srchrow) from the AWS Marketplace or using docker:
    ```bash
    curl -sSL https://raw.githubusercontent.com/bitnami/bitnami-docker-couchdb/master/docker-compose.yml > docker-compose.yml
    docker-compose up -d
    ```
* My current setup runs on a `t3a.small` tier in AWS and seems to effortlessly support 116 thousand documents at the time of writing;
* I strongly suggest enabling (only) https on your server;
* When up and running, browse to the web interface on `https://<your-instance>:5984/_utils/#/_all_dbs` and check if everything's OK
* Create the `bbrf` user (additional documentation [here](https://docs.couchdb.org/en/stable/intro/security.html)) via curl:

    ```bash
    COUCHDB=https://<yourinstance>:5984/
    
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

#### Via `server-install.sh`


Thanks to @plenumlab, you can run the following for an easy out-of-the-box installation of the CouchDB server. Run this on the VPS where you want to install the server. This script requires Docker.

  * `git clone https://github.com/honoki/bbrf-client`
  * `cd bbrf-client`
  * `chmod +x server-install.sh`
  * `./server-install.sh`

### Client

Now you have a server up and running, go ahead and clone this repository.

  * `git clone https://github.com/honoki/bbrf-client`
  * `cd bbrf-client`
  * `virtualenv --python=python3 .env && source .env/bin/activate && pip install -r requirements.txt`

### Setup

Register the function `bbrf` in your `.bash_profile` (or whichever shell you use):

```bash
function bbrf() {
        source ~/bbrf-client/.env/bin/activate;
        python ~/bbrf-client/bbrf.py "$@"
        deactivate
}
```

### Configuration

Create a file `~/.bbrf/config.json` with the required configuration:

```json
{
    "username": "bbrf",
    "password": "<your secure password>",
    "couchdb": "https://<your-instance>:5984/bbrf",
    "slack_token": "<a slack token to receive notifications>"
}
```

## Usage

```
Usage:
  bbrf (new|use|disable|enable) <program>
  bbrf program (list [--show-disabled] | active)
  bbrf domains [--view <view> (-p <program> | --all)]
  bbrf domain (add|remove|update) ( - | <domain>...) [-p <program> -s <source>]
  bbrf ips [--view <view> --filter-cdns (-p <program> | --all)]
  bbrf ip (add|remove|update) ( - | <ip>...) [-p <program> -s <source>]
  bbrf scope (in|out) [(--wildcard [--top])] ([-p <program>] | (--all [--show-disabled]))
  bbrf (inscope|outscope) (add|remove) (- | <element>...) [-p <program>]
  bbrf url add ( - | <url>...) [-d <hostname> -s <source> --show-new -p <program>]
  bbrf urls (-d <hostname> | [-p <program>] | --all)  
  bbrf blacklist (add|remove) ( - | <element>...) [-p <program>]
  bbrf task (list|(add|remove) <task>)
  bbrf run <task> [-p <program>]
  bbrf show <document>
  bbrf listen
  bbrf alert ( - | <message>) [-s <source>]
```

### Examples

Create and configure a new program with a defined scope:

[![asciicast](https://asciinema.org/a/6GWe0GxUnFhTmPIqzh97iA6g5.png)](https://asciinema.org/a/6GWe0GxUnFhTmPIqzh97iA6g5)

When adding domains to your database, note that `bbrf` will automatically remove duplicates and check against the defined scope.

[![asciicast](https://asciinema.org/a/SxDNPfB7QDa1Q9etSEFhSoe28.png)](https://asciinema.org/a/SxDNPfB7QDa1Q9etSEFhSoe28)

Integrate with recon tools you already know and love:

[![asciicast](https://asciinema.org/a/ItX9xMdTuUm02G40rNNN4YUFz.png)](https://asciinema.org/a/ItX9xMdTuUm02G40rNNN4YUFz)

Resolve domains with [`massdns`](https://github.com/blechschmidt/massdns), format with `awk`, and save results with `bbrf`:

```bash
bbrf domains --view unresolved | \
    massdns -t A -o Snlqr -r resolvers.txt | \
    # reformat output to put query and response on the same line for grepping
    awk -v FS="\n" -v RS="\n\n" '{print $1";"$2}' | \
    # pipe output to multiple greps
    tee \
      >(grep ' A ' | awk -F' ' '{print $4":"$7}' | bbrf domain update -) \
      >(grep ' A ' | awk -F' ' '{print $7":"$4}' | bbrf ip add - -s massdns) \
      >(grep ' A ' | awk -F' ' '{print $7":"$4}' | bbrf ip update -);
```

#### URLs

BBRF will help you manage your URLs, and store their hostname, port, status code and content length for you:

```bash
bbrf url add 'https://www.example.com:8443/a' 'http://www.example.com/b' 'http://www.example.com/c 200 1234'
```

Two formats are accepted: `<url>` or `<url> <statuscode> <contentlength>` delimited by spaces.

The `<url>` can be absolute or relative. A relative URL will require the `-d <hostname>` flag to be specified or will be skipped. Whenever the `-d` flag is set, it will compare that with the hostname parsed from the URL, and skip the URL if they do not match.

Relative URLs and URLs that do not specify a scheme (`http://` or `https://`) will always be interpreted with scheme `http://`. If no port is found, ports 80 and 443 will be used as a default depending on the scheme.

The flag `--show-new` will print a list of new and updated URLs if they were added, or if their status code and/or content length were updated respectively:

```bash
cat urls.txt | bbrf url add - --show-new
[UPDATED] https://sub.example.com:8443/b
[NEW] http://www.example.com/a
[NEW] http://www.example.com/c
```

To view a list of stored URLs of your active program, simply use:

```
bbrf urls
``` 

Or, to return URLs belonging to a specific host:

```
bbrf urls -d www.example.com
``` 

To list URLs across all programs, run:

```
bbrf urls --all
```

### Listener

In order to process changes and alerts as they are pushed to the data store, you need to have an active listener running somewhere: `bbrf listen`

This will start listening for changes and push alerts to your configured Slack instance.

## AWS Lambda

The bbrf client can be deployed in AWS Lambda via the [Serverless framework](https://www.serverless.com/).

```bash
> cd bbrf-client
> sls deploy
Serverless: Generated requirements from /.../bbrf-client/requirements.txt in /.../bbrf-client/.serverless/requirements.txt...
Serverless: Using static cache of requirements found at /root/.cache/serverless-python-requirements/d4b86359825bfe10a33e24ee5e467c63305fbf34f10b8a76fd27bbaac517bdb5_slspyc ...
Serverless: Packaging service...
Serverless: Excluding development dependencies...
Serverless: Injecting required Python packages to package...
Serverless: Uploading CloudFormation file to S3...
Serverless: Uploading artifacts...
Serverless: Uploading service bbrf.zip file to S3 (1.28 MB)...
Serverless: Validating template...
Serverless: Updating Stack...
Serverless: Checking Stack update progress...
..............
Serverless: Stack update finished...
Service Information
service: bbrf
stage: dev
region: us-east-1
stack: bbrf-dev
resources: 11
api keys:
  None
endpoints:
  POST - https://[redacted].execute-api.us-east-1.amazonaws.com/dev/bbrf
functions:
  bbrf: bbrf-dev-bbrf
layers:
  None
Serverless: Removing old service artifacts from S3...
Serverless: Run the "serverless" command to setup monitoring, troubleshooting and testing.
```

Now you can interact with the client via the Lambda API Gateway as follows:

```
> curl https://[redacted].execute-api.us-east-1.amazonaws.com/dev/bbrf -d 'task=domains -p vzm'
aa.calendar.yahoo.com
address.news.yahoo.com
admin.finance.yahoo.com
ads.finance.yahoo.com
alpha.news.yahoo.com
api-sched-v3.admanagerplus.yahoo.com
```
