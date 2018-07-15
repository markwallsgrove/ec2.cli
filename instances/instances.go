package instances

import (
	"fmt"
	"regexp"

	"github.com/markwallsgrove/ec2.cli/logging"
	"github.com/markwallsgrove/ec2.cli/marshaller"
	"github.com/markwallsgrove/ec2.cli/profile"
	"github.com/markwallsgrove/ec2.cli/vendor"
)

var log = logging.Log
var regexWhiteChars = regexp.MustCompile("[^a-zA-Z0-9]")

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

// Instances retrieves meta data from ec2
type Instances struct {
	vendor.Initiator
	marshaller.FileMarshaller
}

// FindByHostname filter the ec2 meta data by the hostname
func (i *Instances) FindByHostname(profile *profile.Profile, hostName string) (*Instance, error) {
	instances, err := i.All(profile)
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

func (i *Instances) getInstanceCache(profile *profile.Profile) map[string]*Instance {
	filename := ""
	i.Unmarshall(filename)
	return nil
}

// All retreive all meta data representing ec2 instances
func (i *Instances) All(profile *profile.Profile) (map[string]*Instance, error) {
	instances := i.getInstanceCache(profile)

	if len(instances) > 0 {
		log.Debug("loaded instances from cache")
		return instances, nil
	}

	svc := i.Connect()
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

	return instances, i.storeInstanceCache(profile, instances)
}
