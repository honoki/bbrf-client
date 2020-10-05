# bbrf-client

The client component of the Bug Bounty Reconnaissance Framework (BBRF) is intended to facilitate the workflows of security researchers across multiple devices.

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

### Setting up locally

  * `git clone https://github.com/honoki/bbrf-client`
  * `cd bbrf-client/init`
  * `chmod +x init.sh`
  * `./init.sh`

### CouchDB server 

To use the bbrf client, makes sure you set up the bbrf server first. The tool was built to work with the document-based database [CouchDB](couchdb.apache.org). Below is a suggested way of deploying, but YMMV.

* Deploy the [CouchDB image from Bitnami](https://aws.amazon.com/marketplace/pp/B01M0RA8RQ?ref=cns_srchrow) from the AWS Marketplace;
* My current setup runs on a `t3a.small` tier and seems to effortly support 116 thousand documents at the time of writing;
* I strongly suggest enabling (only) https on your server;
* When up and running, browse to the web interface on `https://<your-instance>:6984/_utils/#/_all_dbs` and check if everything's OK
* Create the `bbrf` user (additional documentation [here](https://docs.couchdb.org/en/stable/intro/security.html)) via curl:

```
curl -X PUT https://<your-instance>:6984/_users/org.couchdb.user:bbrf \
     -u admin:password \
     -H "Accept: application/json" \
     -H "Content-Type: application/json" \
     -d '{"name": "bbrf", "password": "<choose a decent password>", "roles": [], "type": "user"}'
```

* Create a new database `bbrf` via the web interface, and allow the user `bbrf` to access it.
* Create at least the following views via `https://<your-instance>:6984/_utils/#/database/bbrf/new_view`
    - `domains`:
    ```javascript
    function (doc) {
      if(doc.type == "domain")
      emit(doc.program, doc._id);
    }
    ```
    - `ips`
    ```javascript
    function (doc) {
      if(doc.type == "ip")
      emit(doc.program, doc._id);
    }
    ```
    - `programs`
    ```javascript
    function (doc) {
      if(doc.type == "program")
      emit(doc._id, 1);
    }
    ```
    - `domains_resolved`
    ```javascript
    function (doc) {
      if(doc.type == "domain" && doc.ips.length > 0)
      emit(doc.program, doc._id);
    }
    ```
    - `domains_unresolved`
    ```javascript
    function (doc) {
      if(doc.type == "domain" && (!doc.hasOwnProperty("ips") || doc.ips.length === 0))
      emit(doc.program, doc._id);
    }
    ```
    - `alerts`
    ```javascript
    function (doc) {
      if(doc.type == "alert")
      emit(doc.program, doc.message);
    }
    ```
    - `tasks`
    ```javascript
    function (doc) {
      if(doc.type == "task")
      emit( doc.name, 1);
    }
    ```

### Client

Now the server is up and running, go ahead and clone this repository.

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
    "couchdb": "https://<your-instance>:6984/bbrf",
    "slack_token": "<a slack token to receive notifications>"
}
```

## Usage

```
Usage:
  bbrf (new|use) <program> [--disabled --passive-only]
  bbrf program (list|active|scope [--wildcard [--top]] [-p <program>])
  bbrf domains [--view <view>] [-p <program> --all]
  bbrf domain (add|remove|update) ([-] | <domain>...) [-p <program>] [-s <source>]
  bbrf ips [--view <view>] [-p <program> | --all]
  bbrf ip (add|remove|update) ([-] | <ip>...) [-p <program>] [-s <source>]
  bbrf (inscope|outscope) (add|remove) ([-] | <element>...) [-p <program>]
  bbrf blacklist (add|remove) ([-] | <element>...) [-p <program>]
  bbrf run <task> [-p <program>]
  bbrf show <document>
  bbrf listen
  bbrf alert <message> [-s <source>]
  bbrf --version
```

### Listener

In order to process changes and alerts as they are pushed to the data store, you need to have an active listener running somewhere: `bbrf listen`


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

Now interact with the client via the Lambda API Gateway as follows:

```
> curl https://[redacted].execute-api.us-east-1.amazonaws.com/dev/bbrf -d 'task=domains -p vzm'
aa.calendar.yahoo.com
address.news.yahoo.com
admin.finance.yahoo.com
ads.finance.yahoo.com
alpha.news.yahoo.com
api-sched-v3.admanagerplus.yahoo.com
```
