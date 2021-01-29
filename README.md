# bbrf-client

## Introduction

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


## Documentation

 * [Install the CouchDB server](https://github.com/honoki/bbrf-server) - Ensure you have set up a BBRF server before using the client;
 * [Configure the client](docs/client.md) - learn how to start using the client on your workstations;
 * [AWS Lambda](docs/aws-lambda.md) - for more advanced use cases, deploy a bbrf client to AWS Lambda to integrate with bbrf agents and other lambdas;
 * [Usage](docs/usage.md) - view a number of more advanced examples, and learn how to set up a listener.
 
## Dashboard

If you like looking at your data in another way than via a terminal window, you can make use of the bbrf dashboard on https://bbrf.me. Just plug in your server URL, username and password, and the dashboard will pull your data and make it searchable. Note that all communication to the server happens via your browser, so your data remains safe!

[![asciicast](docs/bbrf-dashboard.gif)](https://bbrf.me/)

If you're having CORS-related issues, make sure the origin `https://bbrf.me` is explicitly allowed in your database configuration:

```bash
curl -X PUT $COUCHDB"_node/_local/_config/cors/origins" -u admin:password -d '"https://bbrf.me"'
```
