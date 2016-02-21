# ec2.cli
`ec2.cli` is a simple & fast alternative command line utiltity for communicating with AWS EC2 machines. The goal is to provide the ability to gain SSH access quickly without any prior knowledge of the target machine. The cli has been designed to provide a tab completion interface for speed and ease.

## installation
* Download the latest executable from the [releases page](https://github.com/markwallsgrove/ec2.cli/releases/) for your operating system
* Extract the executable `tar -xzf ec2.cli-*.tar.gz`
* Execute `ec2.cli setup` (mandatory for tab completion) 
* Open a new tab or source `source ~/.bashrc` and/or `source ~/.zshrc`

## configuration
The following items might need changing depending on your environment.
* `AWS_ACCESS_KEY_ID` `AWS_SECRET_ACCESS_KEY` environment variables are used by default, or
* If you use `~/.aws/credentials`, execute `ec2.cli set awsProfile PROFILE` to set the name of the profile, or
* `ec2.cli set awsAccessKey KEY` & `ec2.cli set awsSecretKey KEY` if you do not use `~/.aws/credentials`
* `ec2.cli set cert FILELOC` define where to find your SSH private file
* `ec2.cli set user USERNAME` if you use a different username on your EC2 machines than the current user
* `ec2.cli set region AWSREGION` if your machines are not located in `eu-west-1`

## environment
* Base directory: `~/.ec2.cli`
* Executable location: `~/.ec2.cli/ec2.cli`
* Cache location: `~/.ec2.cli/cache`
* Config location: `~/.ec2.cli/config`

## uninstalling
* Remove `~/.ec2.cli`
* Remove the hand full of lines that was appended to `~/.bashrc` and/or `~/.zshrc`
