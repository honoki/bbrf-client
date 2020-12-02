import sys
from bbrf import BBRFClient
import json
import os


def endpoint(event, context):
    
    # Parse parameters from POST body:
    if 'body' in event and event['body'] and 'task' in event['body']:
        task = event['body'].split('=')[1]
        print(task)
    else:
        print(event)
        return {"statusCode": 400, "body": "ERROR - program or task not found."}
    
    bbrf = BBRFClient(
        task,
        config={
          "couchdb": os.environ['BBRF_COUCHDB_URL'],
          "username": os.environ['BBRF_USERNAME'],
          "password": os.environ['BBRF_PASSWORD'],
          "slack_token": os.environ['BBRF_SLACK_TOKEN'],
        }
    )
    output = bbrf.run()
    
    response = {
        "statusCode": 200,
        "headers": {},
        "body": json.dumps(output),
        "isBase64Encoded": False
    }
    
    return response


if __name__ == '__main__':
    print(endpoint(json.loads('{"body": "task=program list"}'), {}))