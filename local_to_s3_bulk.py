import json
import boto3
import base64
import os
import paramiko
from pathlib import Path, PureWindowsPath
from botocore.exceptions import ClientError
from scp import SCPClient

def validate_sourcepath(spath):
    if not(spath and spath.strip()): 
        print('source path is empty')
        return False
    elif "\\" in spath and "/" in spath:
        print('malformed source path: ' + spath)
        return False
    else:
        return True 

def lambda_handler(event, context):
    
    source_path = event['source_path']
    source_server = event['source_server_ip']
    ssh_username = event['ssh_username']
    landing_path = '/tmp/store/' 
    ssh_keyname = 'ssh_private_key.pem'
    secret_name = event['ssh_secret_name']
    secret_type = event['ssh_secret_type']
    region = event['region']
    target_bucket = event['target_bucket_name']
    
    spath_ok = validate_sourcepath(source_path)
    if spath_ok == False:
        quit()


    # Create OS agnostic source path
    if "\\" in source_path:
        sos = 'w' # source os is windows
        list_files_cmd = "dir " + source_path + " /b /a-d /o:gn"
        orig_source_path = source_path
        source_path = str(PureWindowsPath(source_path)).replace("\\","/")
        print(orig_source_path)
    else:
        sos = 'l' # source os is linux based
        list_files_cmd = "find " + source_path + " -maxdepth 1 -type f -not -path '*/\.*'"
        source_path = str(Path(source_path))

    print(source_path)


    # Extract source folder from source path
    source_folder = str(source_path).split("/", -1)[-1]
    print(source_folder)

    
    # create landing path in lambda runtime environment
    os.makedirs(landing_path, exist_ok=True)
    # create a boto3 session
    session = boto3.session.Session()


    # create a Secrets Manager client
    secrets_client = session.client(
        service_name='secretsmanager',
        region_name=region
    )


    # retrieve the ssh key from Secrets Manager
    try:
        get_secret_value_response = secrets_client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            print("Secrets Manager can't decrypt the protected secret text using the provided KMS key.")
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            print("An error occurred on the server side.")
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("You provided an invalid value for a parameter.")
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("You provided a parameter value that is not valid for the current state of the resource.")
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("We can't find the resource that you asked for.")
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])


    # creating an ssh client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())


    # connect to the remote server (file source server) via ssh
    if secret_type == 'p': 
        try:
            ssh.connect(source_server, username=ssh_username, password=secret)
            print('Successfully Connected to ' + source_server)
        except:
            print('Connection Failed. Please check connection parameters and try again.')

    elif secret_type == 'k':
        try:
            # store the retrieved ssh key into a .pem file
            pemfile = open('/tmp/' + ssh_keyname, 'w')
            pemfile.write(secret)
            pemfile.close()
            ssh_key = paramiko.RSAKey.from_private_key_file('/tmp/' + ssh_keyname)
            ssh.connect(source_server, username=ssh_username, pkey=ssh_key)
            print('Successfully Connected to ' + source_server)
        except:
            print('Connection Failed. Please check connection parameters and try again.')            
    else:
        print("secret type can have only two possible values. 'p' for password and 'k' for RSA private key")
        quit()


    # use scp to copy source files into lambda runtime environment
    try:
        with SCPClient(ssh.get_transport()) as scp:
             scp.get(source_path, recursive=True, local_path=landing_path)

        print('files copied to lambda runtime env at this path: ' + landing_path)
        scp.close()
        print('scp closed')
        
    except:
        print('Error copying files to lambda runtime environment')

    finally:
        ssh.close()        
        print('ssh closed')

        
    #create an S3 client
    s3_client = session.client(
        service_name='s3',
        region_name=region
    )


    # upload the source files to the target S3 bucket
    try:
        for root, dirs, files in os.walk(landing_path):
            for fname in files:
                abs_filepath = os.path.join(root,fname)
                print(abs_filepath)
                s3_path = abs_filepath.replace(landing_path,"")
                s3_client.upload_file(abs_filepath, target_bucket, s3_path)
                print(s3_path + ' upload complete')
    except ClientError as e:
        print('the s3 upload block is broken')
        raise e   
        
    return {
        'statusCode': 200,
        'body': json.dumps('Successfully copied all files to target S3 bucket ' + target_bucket + '/' + source_folder)
    }
