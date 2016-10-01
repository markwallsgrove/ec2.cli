package instances

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/markwallsgrove/ec2.cli/profile"
	logging "github.com/op/go-logging"
)

var regexWhiteChars = regexp.MustCompile("[^a-zA-Z0-9]")

var log = logging.MustGetLogger("ec2.cli")
var logFormat = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)
var backend = logging.NewLogBackend(os.Stderr, "", 0)
var formatter = logging.NewBackendFormatter(backend, logFormat)

func init() {
	logging.SetBackend(formatter)
}

// Instance represents an ec2 instance meta data
type Instance struct {
	Name          string
	Addr          string
	ID            string
	PublicDNSName string
	InstanceType  string
	CertName      string
	Tags          []string
}

func (i *Instance) getNormalisedName() string {
	return fmt.Sprintf("%s_%s", regexWhiteChars.ReplaceAllString(i.Name, "_"), i.ID)
}

// FindByHostname filter the ec2 meta data by the hostname
func FindByHostname(profile profile.Profile, hostName string) (*Instance, error) {
	instances, err := GetAll(profile)
	instance := &Instance{}

	if err == nil {
		log.Debug("looking for instance", hostName)
		instance, found := instances[hostName]

		if !found {
			err = fmt.Errorf("unknown instance: %s", hostName)
		}

		return instance, err
	}

	return instance, err
}

// GetAll retreive all meta data representing ec2 instances
func GetAll(profile profile.Profile) (map[string]*Instance, error) {
	instances := getInstanceCache(profile)

	if len(instances) > 0 {
		log.Debug("loaded instances from cache")
		return instances, nil
	}

	config := getAWSConfiguration(profile)
	if region := profile.Region(); region != "" {
		log.Debug("using region", profile.Region())
		config.Region = aws.String(region)
	}

	svc := ec2.New(session.New(), &config)
	resp, err := svc.DescribeInstances(nil)

	if err != nil {
		log.Error("cannot describe instances", err)
		return instances, err
	}

	for _, res := range resp.Reservations {
		for _, inst := range res.Instances {
			instance := new(Instance)

			instance.Tags = make([]string, len(inst.Tags))
			for index, keys := range inst.Tags {
				instance.Tags[index] = *keys.Value
				if *keys.Key == "Name" {
					instance.Name = regexWhiteChars.ReplaceAllString(*keys.Value, "_")
					instance.ID = *inst.InstanceId
				}
			}

			instance.PublicDNSName = *inst.PublicDnsName
			instance.InstanceType = *inst.InstanceType
			instance.CertName = *inst.KeyName

			if inst.PublicIpAddress != nil {
				instance.Addr = *inst.PublicIpAddress
			} else if inst.PrivateIpAddress != nil {
				instance.Addr = *inst.PrivateIpAddress
			}

			if instance.Name != "" && instance.Addr != "" {
				instances[instance.getNormalisedName()] = instance
			} else {
				log.Debug("instance has no name or address", fmt.Sprintf("%+v\n", instance))
			}
		}
	}

	return instances, storeInstanceCache(profile, instances)
}

func getInstanceCache(profile profile.Profile) map[string]*Instance {
	cache := map[string]*Instance{}

	cacheLocation := fmt.Sprintf("%s/cache/%s_%s.cache", profile.BaseDir(), profile.Name(), profile.Region())
	log.Debug("loading cache from", cacheLocation)

	if info, err := os.Stat(cacheLocation); err != nil {
		log.Debug("could not load cache", err)
		return cache
	} else if profile.MaxCacheAge() == 0 {
		log.Debug("cache expiry set to zero, removing")
		os.Remove(cacheLocation)
		return cache
	} else if int(time.Since(info.ModTime()).Seconds()) > profile.MaxCacheAge() {
		log.Debug("cache has expired, removing")
		return cache
	}

	contents, err := ioutil.ReadFile(cacheLocation)
	if err != nil {
		log.Error("cannot read cache, ignoring, ", err)
		return cache
	}

	buffer := bytes.Buffer{}
	buffer.Write(contents)

	d := gob.NewDecoder(&buffer)
	err = d.Decode(&cache)

	if err != nil {
		log.Error("cannot decode cache,", err)
	}

	return cache
}

func storeInstanceCache(profile profile.Profile, cache map[string]*Instance) error {
	if err := os.MkdirAll(fmt.Sprintf("%s/cache", profile.BaseDir()), 0770); err != nil {
		log.Error("cannot create cache directory,", err)
		return err
	}

	cacheLocation := fmt.Sprintf(
		"%s/cache/%s_%s.cache", profile.BaseDir(), profile.Name(), profile.Region(),
	)

	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(cache)

	if err != nil {
		log.Error("cannot encode cache,", err)
		return err
	}

	log.Debug("writing cache to", cacheLocation)
	return ioutil.WriteFile(cacheLocation, buffer.Bytes(), 0770)
}

func getAWSConfiguration(profile profile.Profile) aws.Config {
	awsCredentialsLoc := fmt.Sprintf("%s/.aws/credentials", profile.HomeDir())
	var creds *credentials.Credentials

	if awsAccessKey, awsSecretKey := profile.AWSAccessKey(), profile.AWSSecretKey(); awsAccessKey != "" && awsSecretKey != "" {
		log.Debug("using access/secret keys from profile")
		creds = credentials.NewStaticCredentials(
			profile.AWSAccessKey(),
			profile.AWSSecretKey(),
			"",
		)
	} else if awsProfile := profile.AWSProfile(); awsProfile != "" {
		log.Debug("loading shared credentials from", awsCredentialsLoc)
		creds = credentials.NewSharedCredentials(
			awsCredentialsLoc, awsProfile,
		)
	} else {
		log.Debug("using environmental aws access/secret keys")
		creds = credentials.NewEnvCredentials()
	}

	return aws.Config{Credentials: creds}
}
