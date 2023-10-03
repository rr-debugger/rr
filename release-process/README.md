# Setting up AWS-based rr release testing

* Create an AWS account.
* Switch to the `us-east-2` (Ohio) region. The AMI IDs under `distro-configs` are all for the `us-east-2` region so this region must be used.
* Use the EC2 console to create a keypair named `rr-testing`. This will download a file called `rr-testing.pem` containing the private key; move it somewhere safe and `chmod go-r <path>/rr-testing.pem` to make ssh happy.
* Install `boto3` locally, e.g. using `pip install boto3`.
* Install `aws-cli` locally, e.g. using [these instructions](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).
* Set `AWS_DEFAULT_REGION=us-east-2`, `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in your environment.
* Create AWS resources using `aws cloudformation create-stack --stack-name rr-testing --template-body file://path/to/rr-testing-cloud-formation.json`.
  * In the future, use `aws cloudformation update-stack  --stack-name rr-testing --template-body file://path/to/rr-testing-cloud-formation.json` to update when that configuration file changes.

# Preparing a release

If you want to support any new distro versions, add files to `release-process/distro-configs`. Likewise remove any config files for distro versions no longer supported. Make sure to commit all changes to the local `master` branch before runnging `prepare-release.py`. Then:
```
release-process/prepare-release.py <major>.<minor>.0 <path>/rr-testing.pem
```
This will (re)create a `release` branch in Github, then start a number of EC2 VMs for testing and packaging. When a VM successfully completes its work, you will see lines like
```
Tests succeeded for centos9 arm64
```
When a VM fails, you will see something like
```
Tests failed (VM kept): see /tmp/rr-release-logs/debian12.arm64
```
The output log should help diagnose the problem. At the end of the log is an SSH command you can use to log into the VM for further debugging. Make sure to shut down any failing VMs when you're done, either using `sudo shutdown now` in an SSH session, or from the AWS EC2 console.

Repeat until there are no more failures or any failures are ignorable (e.g. due to [#3607](https://github.com/rr-debugger/rr/issues/3607)). The built packages will be in `/tmp/rr-dist`; there should be two `.deb`s, two `.rpm`s, and two `.tar.gz`s.

# Completing the release

- [ ] Cherry-pick `release` to `master` and update tag: `git cherry-pick release; git tag -f <major>.<minor>.0` (Not sure why the tag needs to be updated...)
- [ ] Push changes to Github: `git push origin; git push --tags origin`. Once this is done there is no turning back!
- [ ] [Create release and upload packages](https://github.com/mozilla/rr/releases) from `/tmp/rr-dist`
- [ ] Update gh-pages: `./scripts/update-gh-pages.sh && git push origin`
- [ ] Update [News wiki page](https://github.com/mozilla/rr/wiki/News)
- [ ] Post to rr-dev mailing list.

# Testing a specific distro/CPU configuration

The `release-process/test-system.py` script can be used to start an AWS EC2 VM to test a specific distro version and CPU combination. E.g.
```
release-process/test-system.py --keep-vm release-process/distro-configs/centos9.json arm64 ~/rr-testing.pem >& /tmp/output
```
This will start the VM, build rr, and run tests. Whether or not the tests succed, the VM will keep running and `/tmp/output` will end with an SSH command to log into the VM --- very handy for testing new distro versions or just running rr tests on a beefy machine. `test-system.py` has various options for customizing the instance type etc.

This is helpful for debugging intermittent rr test failures. For example, in a VM, you can run
```
cd ~/rr/src/test
for i in `seq 1 100`; do bash cont_race.run & done
```
to run 100 parallel instances of the `cont_race` test. If that doesn't show your bug, try 1000 instances instead. Running instances in parallel stresses thread scheduling and exposes more bugs.
