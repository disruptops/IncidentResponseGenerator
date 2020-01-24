# IncidentResponseGenerator

This application simulates an attack on AWS infrastructure. It was built for the Securosis/Cloud Security Alliance Advanced Cloud Security Practitioner training class.

This code is designed to be run inside an instance with an IAM role with admin privileges. Some caveats:

* DO NOT RUN THIS IN ANY ACCOUNT OTHER THAN A TRAINING ACCOUNT!!
* This will make changes to your account that, while within the terms of service of AWS, could create security exposures. It should be safe but we make no warranties or promises and it absolutely should never be run on a *real* account.
* The code is deliberately not commented just to make life a little harder on students.
* The associated config file has some values that would allow Securosis cross account access. CHANGE THIS TO AN ACCOUNT YOU CONTROL!!
    * We can't actually use this access since we don't know the target account and we don't scan millions of AWS accounts to see if we can get in, but you have been warned.
* The default app uses two lambda functions in amn S3 bucket we control, THIS IS ARBITRARY CODE EXECUTION!
    * We've included the code so you can host it in your own bucket.
    * In future updates we will change the config file to point to an S3 bucket so you don't have to change the code, but right now you need to update the code yourself.
* Cleanup is currently manual. In the future we will provide a cleaner script. SOmeday.

## How we use this in training

We publish a public AMI with this app pre-loaded. Students run a CloudFormation template that creates a new IAM rule and instance profile, then launches an instance with the AMI, where the code runs on initial boot. This takes a few minutes and then we have the students attempt to contain and respond to the simulated attack. No network exposures are created and no secrets are leaked.

This version was created for an exercise that should take about an hour, including launch, response, cleanup, and discussion.

## Future plans

1. Add additional attack types for an upcoming advanced incident response class we are working on.
2. Create a cleaner script.
3. Add command line arguments for which attacks to include or exclude.
