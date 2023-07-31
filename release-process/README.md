# Setting up AWS-based rr release testing

* Create an AWS account.
* Switch to the `us-east-2` (Ohio) region. The AMI IDs under `distro-configs` are all for the `us-east-2` region so this region must be used.
* Use the EC2 console to create a keypair named `rr-testing`. This will download a file called `rr-testing.pem` containing the private key; move it somewhere safe and `chmod go-r ...` to make ssh happy.
* Install `boto3` locally, e.g. using `pip install boto3`.
* Install `aws-cli` locally, e.g. using [these instructions](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).
* Set `AWS_DEFAULT_REGION=us-east-2`, `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in your environment.
* Create AWS resources using `aws cloudformation create-stack --stack-name rr-testing --template-body file://path/to/rr-testing-cloud-formation.json`.
  * In the future, use `aws cloudformation update-stack  --stack-name rr-testing --template-body file://path/to/rr-testing-cloud-formation.json` to update when that configuration file changes.
