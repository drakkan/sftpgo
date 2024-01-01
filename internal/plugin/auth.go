// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package plugin

import (
	"errors"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/sftpgo/sdk/plugin/auth"

	"github.com/drakkan/sftpgo/v2/internal/logger"
)

// Supported auth scopes
const (
	AuthScopePassword            = 1
	AuthScopePublicKey           = 2
	AuthScopeKeyboardInteractive = 4
	AuthScopeTLSCertificate      = 8
)

// KeyboardAuthRequest defines the request for a keyboard interactive authentication step
type KeyboardAuthRequest struct {
	RequestID string   `json:"request_id"`
	Step      int      `json:"step"`
	Username  string   `json:"username,omitempty"`
	IP        string   `json:"ip,omitempty"`
	Password  string   `json:"password,omitempty"`
	Answers   []string `json:"answers,omitempty"`
	Questions []string `json:"questions,omitempty"`
}

// KeyboardAuthResponse defines the response for a keyboard interactive authentication step
type KeyboardAuthResponse struct {
	Instruction string   `json:"instruction"`
	Questions   []string `json:"questions"`
	Echos       []bool   `json:"echos"`
	AuthResult  int      `json:"auth_result"`
	CheckPwd    int      `json:"check_password"`
}

// Validate returns an error if the KeyboardAuthResponse is invalid
func (r *KeyboardAuthResponse) Validate() error {
	if len(r.Questions) == 0 {
		err := errors.New("interactive auth error: response does not contain questions")
		return err
	}
	if len(r.Questions) != len(r.Echos) {
		err := fmt.Errorf("interactive auth error: response questions don't match echos: %v %v",
			len(r.Questions), len(r.Echos))
		return err
	}
	return nil
}

// AuthConfig defines configuration parameters for auth plugins
type AuthConfig struct {
	// Scope defines the scope for the authentication plugin.
	// - 1 means passwords only
	// - 2 means public keys only
	// - 4 means keyboard interactive only
	// - 8 means TLS certificates only
	// you can combine the scopes, for example 3 means password and public key, 5 password and keyboard
	// interactive and so on
	Scope int `json:"scope" mapstructure:"scope"`
}

func (c *AuthConfig) validate() error {
	authScopeMax := AuthScopePassword + AuthScopePublicKey + AuthScopeKeyboardInteractive + AuthScopeTLSCertificate
	if c.Scope == 0 || c.Scope > authScopeMax {
		return fmt.Errorf("invalid auth scope: %v", c.Scope)
	}
	return nil
}

type authPlugin struct {
	config  Config
	service auth.Authenticator
	client  *plugin.Client
}

func newAuthPlugin(config Config) (*authPlugin, error) {
	p := &authPlugin{
		config: config,
	}
	if err := p.initialize(); err != nil {
		logger.Warn(logSender, "", "unable to create auth plugin: %v, config %+v", err, config)
		return nil, err
	}
	return p, nil
}

func (p *authPlugin) initialize() error {
	killProcess(p.config.Cmd)
	logger.Debug(logSender, "", "create new auth plugin %q", p.config.Cmd)
	if err := p.config.AuthOptions.validate(); err != nil {
		return fmt.Errorf("invalid options for auth plugin %q: %v", p.config.Cmd, err)
	}

	secureConfig, err := p.config.getSecureConfig()
	if err != nil {
		return err
	}
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: auth.Handshake,
		Plugins:         auth.PluginMap,
		Cmd:             p.config.getCommand(),
		SkipHostEnv:     true,
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
		AutoMTLS:     p.config.AutoMTLS,
		SecureConfig: secureConfig,
		Managed:      false,
		Logger: &logger.HCLogAdapter{
			Logger: hclog.New(&hclog.LoggerOptions{
				Name:        fmt.Sprintf("%v.%v", logSender, auth.PluginName),
				Level:       pluginsLogLevel,
				DisableTime: true,
			}),
		},
	})
	rpcClient, err := client.Client()
	if err != nil {
		logger.Debug(logSender, "", "unable to get rpc client for auth plugin %q: %v", p.config.Cmd, err)
		return err
	}
	raw, err := rpcClient.Dispense(auth.PluginName)
	if err != nil {
		logger.Debug(logSender, "", "unable to get plugin %v from rpc client for command %q: %v",
			auth.PluginName, p.config.Cmd, err)
		return err
	}

	p.service = raw.(auth.Authenticator)
	p.client = client

	return nil
}

func (p *authPlugin) exited() bool {
	return p.client.Exited()
}

func (p *authPlugin) cleanup() {
	p.client.Kill()
}

func (p *authPlugin) checkUserAndPass(username, password, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	return p.service.CheckUserAndPass(username, password, ip, protocol, userAsJSON)
}

func (p *authPlugin) checkUserAndTLSCertificate(username, tlsCert, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	return p.service.CheckUserAndTLSCert(username, tlsCert, ip, protocol, userAsJSON)
}

func (p *authPlugin) checkUserAndPublicKey(username, pubKey, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	return p.service.CheckUserAndPublicKey(username, pubKey, ip, protocol, userAsJSON)
}

func (p *authPlugin) checkUserAndKeyboardInteractive(username, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	return p.service.CheckUserAndKeyboardInteractive(username, ip, protocol, userAsJSON)
}

func (p *authPlugin) sendKeyboardIteractiveRequest(req *KeyboardAuthRequest) (*KeyboardAuthResponse, error) {
	instructions, questions, echos, authResult, checkPassword, err := p.service.SendKeyboardAuthRequest(
		req.RequestID, req.Username, req.Password, req.IP, req.Answers, req.Questions, int32(req.Step))
	if err != nil {
		return nil, err
	}
	return &KeyboardAuthResponse{
		Instruction: instructions,
		Questions:   questions,
		Echos:       echos,
		AuthResult:  authResult,
		CheckPwd:    checkPassword,
	}, nil
}
