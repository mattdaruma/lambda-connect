import boto3
import json
import os
import time
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode

# Environment variables
USER_POOL_ID = 'us-west-2_ZqHOYBFnn'
REGION = 'us-west-2'
TABLE_NAME = 'moyabe-connections'

# Cognito Keys URL
KEYS_URL = f'https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json'

# Fetch and cache the keys
with urllib.request.urlopen(KEYS_URL) as f:
    response = f.read()
KEYS = json.loads(response.decode('utf-8'))['keys']

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(TABLE_NAME)

def lambda_handler(event, context):
    print("connect event:", event)
    connection_id = event.get('requestContext', {}).get('connectionId')

    try:
        token = event.get('queryStringParameters', {}).get('token')
        if not token:
            print("Missing token")
            return {'statusCode': 401, 'body': 'Unauthorized'}

        # Get the headers of the token
        headers = jwt.get_unverified_headers(token)
        kid = headers['kid']

        # Find the key in the JWKS
        key_index = -1
        for i in range(len(KEYS)):
            if kid == KEYS[i]['kid']:
                key_index = i
                break
        if key_index == -1:
            print("Claimed key not in JWKS")
            return {'statusCode': 401, 'body': 'Unauthorized'}

        # Construct the public key
        public_key = jwk.construct(KEYS[key_index])

        # Get the last two parts of the token
        message, encoded_signature = str(token).rsplit('.', 1)

        # Decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

        # Verify the signature
        if not public_key.verify(message.encode("utf8"), decoded_signature):
            print("Signature verification failed")
            return {'statusCode': 401, 'body': 'Unauthorized'}

        # Since the signature is verified, we can now safely use the claims
        claims = jwt.get_unverified_claims(token)

        # Verify the token expiration
        if time.time() > claims['exp']:
            print("Token is expired")
            return {'statusCode': 401, 'body': 'Unauthorized'}

        # Verify the audience (aud claim)
        # Note: You might need to adjust this depending on your Cognito client setup
        # For this example, we are not checking the aud claim.

        username = claims.get('cognito:username')
        if not username:
            username = claims.get('username')

        preferred_username = claims.get('preferred_username')

        # Store the connection
        item = {
            'connectionId': connection_id,
            'username': username
        }
        if preferred_username:
            item['preferredUsername'] = preferred_username

        table.put_item(Item=item)

        print(f"Successfully authenticated and stored connection for user {username}")
        return {'statusCode': 200, 'body': 'Connected.'}

    except Exception as e:
        print(f"Error: {e}")
        return {'statusCode': 500, 'body': 'Internal server error'}