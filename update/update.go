package update

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"

	update "github.com/inconshreveable/go-update"
	logging "github.com/op/go-logging"
)

var releasesAPI string = "https://api.github.com/repos/markwallsgrove/ssh_alias_ec2/releases"
var version string = "0.5.3"

var publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvbKUOY+q3YFsJXCbPeT5VsVj69+K
lc/qbJVx/ZsbbPOTiMoWdQ7vENoMcqPgB7O6ouHoLo1FlOazHEnQVcFXoA==
-----END PUBLIC KEY-----
`)

var forwardAssetFilePattern = regexp.MustCompile(fmt.Sprintf(
	"/f-%s-%s\\.(hash|sig|diff)$", runtime.GOOS, runtime.GOARCH,
))

var backwardsAssetFilePattern = regexp.MustCompile(fmt.Sprintf(
	"/b-%s-%s\\.(hash|sig|diff)$", runtime.GOOS, runtime.GOARCH,
))

var log = logging.MustGetLogger("ec2.cli")
var logFormat = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)
var backend = logging.NewLogBackend(os.Stderr, "", 0)
var formatter = logging.NewBackendFormatter(backend, logFormat)

func init() {
	logging.SetBackend(formatter)
}

func downloadFile(uri string, loc string, errChannel chan error) {
	log.Debug("downloading", uri, "to", loc)

	output, err := os.Create(loc)
	if err != nil {
		errChannel <- err
		return
	}

	defer output.Close()

	response, err := http.Get(uri)
	if err != nil {
		errChannel <- err
		return
	}

	defer response.Body.Close()

	_, err = io.Copy(output, response.Body)
	if err != nil {
		errChannel <- err
		return
	}

	errChannel <- errors.New("")
}

type Release struct {
	Version string  `json:"tag_name"`
	Body    string  `json:"body"`
	Assets  []Asset `json:"assets"`
}

func (release *Release) DownloadAssets(pattern regexp.Regexp, location string) error {
	if len(release.Assets) == 0 {
		return errors.New("Release contains zero assets")
	}

	downloading := 0
	errChannel := make(chan error)
	for _, asset := range release.Assets {
		if pattern.MatchString(asset.DownloadUrl) == false {
			continue
		}

		go downloadFile(asset.DownloadUrl, path.Join(location, asset.Name), errChannel)
		downloading += 1
	}

	var err error
	for i := 0; i < downloading; i++ {
		err = <-errChannel
		if err.Error() != "" {
			break
		}
	}

	close(errChannel)
	if err.Error() != "" {
		return err
	}

	return nil
}

type Asset struct {
	Name        string `json:"name"`
	DownloadUrl string `json:"browser_download_url"`
}

func getReleases() ([]Release, error) {
	res, err := http.Get(releasesAPI)
	if err != nil {
		return []Release{}, err
	}

	defer res.Body.Close()

	var releases []Release
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&releases)
	return releases, err
}

func getNextRelease(releases []Release, version string, downgrade bool) (Release, bool, bool) {
	for index, release := range releases {
		if release.Version == version {
			earliestRelease := index+1 == len(releases)
			if index == 0 {
				return releases[0], true, earliestRelease
			} else if downgrade {
				return releases[index], false, earliestRelease
			} else {
				return releases[index-1], false, earliestRelease
			}
		}
	}

	return Release{}, false, false
}

func Patch(downgrade bool) error {
	releases, err := getReleases()
	if err != nil {
		return err
	}

	if len(releases) < 2 {
		return errors.New("Zero new releases are available")
	}

	release, latest, earliest := getNextRelease(releases, version, downgrade)
	if release.Version == "" {
		// TODO: could this happen after many updates? Does Github use pagination?
		return errors.New("ERROR: cannot find version information. Please re-download")
	} else if latest == true && downgrade == false {
		return errors.New("Latest version already installed")
	} else if downgrade == true && earliest == true {
		return errors.New("ec2.cli is already at the earliest available release")
	}

	if downgrade {
		err = release.DownloadAssets(*backwardsAssetFilePattern, "/tmp")
	} else {
		err = release.DownloadAssets(*forwardAssetFilePattern, "/tmp")
	}

	if err != nil {
		return err
	}

	if err = applyPatch("/tmp", downgrade); err != nil {
		return err
	} else if downgrade == true {
		log.Info("successfully downgraded from", release.Version)
	} else {
		log.Info("successfully updated from", release.Version)
	}

	return nil
}

func applyPatch(filesLoc string, downgrade bool) error {
	log.Debug("patching...")

	var direction string
	if downgrade == true {
		direction = "b"
	} else {
		direction = "f"
	}

	hashLoc := path.Join(filesLoc, fmt.Sprintf("%s-%s-%s.hash", direction, runtime.GOOS, runtime.GOARCH))
	sigLoc := path.Join(filesLoc, fmt.Sprintf("%s-%s-%s.sig", direction, runtime.GOOS, runtime.GOARCH))
	diffLoc := path.Join(filesLoc, fmt.Sprintf("%s-%s-%s.diff", direction, runtime.GOOS, runtime.GOARCH))

	defer removePatchFiles([]string{hashLoc, sigLoc, diffLoc})

	_, hashLocErr := os.Stat(hashLoc)
	_, sigLocErr := os.Stat(sigLoc)
	_, diffErr := os.Stat(diffLoc)

	if hashLocErr != nil || sigLocErr != nil || diffErr != nil {
		return errors.New("No all required files are available for download")
	}

	file, err := os.Open(diffLoc)
	if err != nil {
		return err
	}

	// Signature of the new executable, signed by the private cert
	signature, err := ioutil.ReadFile(sigLoc)
	if err != nil {
		return err
	}

	// SHA-256 hash of the patch file
	hash, err := ioutil.ReadFile(hashLoc)
	if err != nil {
		return err
	}

	// Remove newline from the file
	checksum, err := hex.DecodeString(strings.TrimSpace(string(hash)))
	if err != nil {
		return err
	}

	opts := update.Options{
		Patcher:   update.NewBSDiffPatcher(),
		Checksum:  checksum,
		Signature: signature,
	}

	err = opts.SetPublicKeyPEM(publicKey)
	if err != nil {
		return err
	}

	return update.Apply(file, opts)
}

func removePatchFiles(files []string) {
	for _, file := range files {
		os.Remove(file)
	}
}
