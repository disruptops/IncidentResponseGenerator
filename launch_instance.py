import json
import boto3
import os

def launch_instance(event, context):
    ec2 = boto3.client('ec2', region_name='us-east-2')
    ami = os.environ['AMI']
    launch = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType='t2.micro')