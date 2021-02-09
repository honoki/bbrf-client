![PyPI](https://img.shields.io/pypi/v/bbrf)
![PyPI - Downloads](https://img.shields.io/pypi/dm/bbrf)

## Introduction

The client component of the Bug Bounty Reconnaissance Framework (BBRF) is intended to facilitate the workflows of security researchers across multiple devices.

Read the blog post: https://honoki.net/2020/10/08/introducing-bbrf-yet-another-bug-bounty-reconnaissance-framework/

The primary function of the client is providing easy access to information that is stored in a centralized BBRF document store. For example, to quickly create and initialize a new program with a couple of domains, you can try:

```
# create a new program
~# bbrf new vzm
~# bbrf inscope add '*.yahoo.com' '*.yahoo.be'
~# bbrf domain add www.yahoo.com www.yahoo.be
```

To add a list of ips from a file or other program, you can pipe into `bbrf`:

```
~# bbrf use vzm
~# cat ips.txt | bbrf ip add -
```

Now, to list all known domains belonging to the active program:

```
~# bbrf domains
```


## Documentation

 * [Install the BBRF server](https://github.com/honoki/bbrf-server) - ensure you have a BBRF server running before making use of the client;
 * [AWS Lambda](/docs/aws-lambda.md) - for more advanced use cases, deploy a BBRF client to AWS Lambda to integrate with BBRF agents and other lambdas;
 * [Usage](/docs/usage.md) - view a number of more advanced examples, and learn how to set up a listener.

## Installation

```
~# pip install bbrf
~# bbrf --version
```

## Configuration

To start using the command line interface, you need to create the config file `~/.bbrf/config.json` with the following contents:

```json
{
    "username": "bbrf",
    "password": "<your secure password>",
    "couchdb": "https://<your-instance>:6984/bbrf",
    "slack_token": "<a slack token to receive notifications>"
}
```

Now you're ready to use BBRF from your command line:

```
~# bbrf programs
```

## Python module

To use BBRF in your Python projects, use the interface as follows:

```python
from bbrf.bbrf import BBRFClient as bbrf

# this will use the system's default ~/.bbrf/config.json file:
programs = bbrf('programs').run()

# to specify a custom configuration, provide a second argument:
conf = {
    "username": "bbrf",
    "password": "<your secure password>",
    "couchdb": "https://<your-instance>:6984/bbrf",
    "slack_token": "<a slack token to receive notifications>"
}

domains = bbrf('domains --view resolved', conf).run()
```

## Dashboard

If you like browsing through your recon data with a GUI, you can make use of the [bbrf dashboard](https://github.com/honoki/bbrf-dashboard) on https://bbrf.me. Just plug in your server URL, username and password, and the dashboard will pull your data and make it searchable. Note that all communication to the server happens via your browser, so your data remains safe!

[![asciicast](docs/bbrf-dashboard.gif)](https://bbrf.me/)