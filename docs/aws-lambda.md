# AWS Lambda

The bbrf client can be easily deployed to AWS Lambda via the [Serverless framework](https://www.serverless.com/). I recommend using this if you want to consume output of tools without having a local installation of the bbrf client ready.

```
~# cd bbrf-client
~# serverless deploy
[...snip...]
api keys:
  None
endpoints:
  POST - https://[redacted].execute-api.us-east-1.amazonaws.com/dev/bbrf
functions:
  bbrf: bbrf-dev-bbrf
```

Now you can run bbrf commands in the cloud via the Lambda API Gateway as follows:

```
~# curl https://[redacted].execute-api.us-east-1.amazonaws.com/dev/bbrf -d 'task=domains -p vzm'
aa.calendar.yahoo.com
address.news.yahoo.com
admin.finance.yahoo.com
ads.finance.yahoo.com
alpha.news.yahoo.com
api-sched-v3.admanagerplus.yahoo.com
```

## Python example

The following python definition will allow you to run e.g. `bbrf('domains -p vzm')` to return a list of domains for the program `vzm`. This can be very powerful when used in seperate bbrf-enabled AWS lambdas ("agents") to regularly run repetitive tasks like crt.sh queries or sublister.

```python
import json
import requests
import boto3
import psycopg2

BBRF_ENDPOINT = 'https://[redacted].execute-api.us-east-1.amazonaws.com/dev/bbrf'

def bbrf(command):
    return json.loads(requests.post(BBRF_ENDPOINT, 'task='+command).text)
```