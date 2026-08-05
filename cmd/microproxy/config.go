package main

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"

	"github.com/dobrevit/microproxy"
)

const (
	authTypeBasic  = "basic"
	authTypeDigest = "digest"
)

// fileConfig is what a microproxy.toml describes: the library's configuration
// plus the file paths that only a standalone proxy has any use for.
type fileConfig struct {
	microproxy.Config

	AccessLog   string `toml:"access_log"`
	ActivityLog string `toml:"activity_log"`
	AuthType    string `toml:"auth_type"`
	AuthFile    string `toml:"auth_file"`
	AuthRealm   string `toml:"auth_realm"`

	// HTTPListen is where the /health endpoint is served. The proxy itself
	// does not listen there.
	HTTPListen string `toml:"http_listen"`
}

// loadConfig reads and validates a configuration file. It reports an error
// rather than terminating, so that a failed reload can keep the running
// configuration in place.
func loadConfig(path string) (*fileConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("can't open configuration file: %w", err)
	}
	defer file.Close()

	var conf fileConfig

	if _, err := toml.NewDecoder(file).Decode(&conf); err != nil {
		return nil, fmt.Errorf("couldn't parse configuration file: %w", err)
	}

	if err := conf.validate(); err != nil {
		return nil, err
	}

	return &conf, nil
}

func (c *fileConfig) validate() error {
	if c.AuthFile != "" && c.AuthType == "" {
		return fmt.Errorf("missed mandatory configuration parameter 'auth_type'")
	}

	if c.AuthType != "" && c.AuthType != authTypeBasic && c.AuthType != authTypeDigest {
		return fmt.Errorf("incorrect authentication type '%s'", c.AuthType)
	}

	if c.HealthCheckEnabled == "on" && c.HTTPListen == "" {
		return fmt.Errorf("'enable_health_check' needs 'http_listen' to serve the endpoint on")
	}

	return c.Config.Validate()
}

// credentials loads the user database the configuration points at, or nil when
// the proxy authenticates nobody.
func (c *fileConfig) credentials() (microproxy.Credentials, error) {
	if c.AuthFile == "" {
		return nil, nil
	}

	switch c.AuthType {
	case authTypeBasic:
		users, err := microproxy.LoadBasicUsersFile(c.AuthRealm, c.AuthFile)
		if err != nil {
			return nil, fmt.Errorf("couldn't read the basic auth file: %w", err)
		}

		return users, nil
	case authTypeDigest:
		users, err := microproxy.LoadDigestUsersFile(c.AuthRealm, c.AuthFile)
		if err != nil {
			return nil, fmt.Errorf("couldn't read the digest auth file: %w", err)
		}

		return users, nil
	default:
		return nil, fmt.Errorf("unsupported authentication type '%s'", c.AuthType)
	}
}
