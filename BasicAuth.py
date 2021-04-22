import boto3
import urllib
import base64
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    client = boto3.client('secretsmanager')
    request = event['Records'][0]['cf']['request']
    headers = request['headers']
    response = {
        'status': '401',
        'statusDescription': 'Unauthorized',
        'headers': {
            'www-authenticate': [{
                'key': 'WWW-Authenticate',
                'value': 'Basic realm = User Visible Realm'
            }]
        }
    }
    try:
        if 'authorization' in headers.keys():
            print("Found Auth header - Authenticating...")
            authHeader = headers['authorization']
            authDict = authHeader[0]
            authValue = authDict.get('value')
            username = '<USERNAME>'
            password = client.get_secret_value(SecretId='<AWSSECRETID>').get('SecretString')
            if password:
                cred = (username + ":" + password).encode('utf-8')
                cred64 = base64.b64encode(cred)
                san64 = cred64.decode('utf-8')
                san264 = san64.replace("'", "")
                validator = ("Basic %s" % san264)
                if authValue == validator:
                    print("Success")
                    return request
                else:
                    print("Invalid Username or Password")
                    return response
            else:
                print("Unable to retrieve secret")
        else:
            print("Didn't find Auth header. First time?")
            return response
    except ClientError as e:
        print('Error', e)
        return response
