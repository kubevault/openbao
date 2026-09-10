// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package etcd implements an OpenBao v5 database plugin for etcd's built-in
// auth store. Dynamic credentials become native etcd users created via the
// v3 Auth API, with permissions coming from pre-existing roles named in
// creation_statements.
package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/mitchellh/mapstructure"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/builtin/database/dbtls"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	etcdTypeName = "etcd"

	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 10) (.RoleName | truncate 10) (random 15) (unix_time) | replace "." "-" | truncate 60 }}`

	defaultDialTimeout = 5 * time.Second
)

// ReportedVersion is overridable at build time.
var ReportedVersion = ""

// Etcd implements dbplugin.Database against etcd's v3 Auth API.
// creation_statements is a JSON document `{"roles":["role1","role2"]}`
// listing pre-existing etcd roles to grant the new user.
type Etcd struct {
	mu sync.Mutex

	config           *etcdConfig
	client           *clientv3.Client
	usernameProducer template.StringTemplate
}

type etcdConfig struct {
	Endpoints   []string `mapstructure:"endpoints"`
	Username    string   `mapstructure:"username"`
	Password    string   `mapstructure:"password"`
	DialTimeout string   `mapstructure:"dial_timeout"`
}

type etcdStatement struct {
	Roles []string `json:"roles"`
}

var (
	_ dbplugin.Database       = (*Etcd)(nil)
	_ logical.PluginVersioner = (*Etcd)(nil)
)

func New() (any, error) {
	db := newEtcd()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

func newEtcd() *Etcd {
	return &Etcd{}
}

func (e *Etcd) secretValues() map[string]string {
	if e.config == nil {
		return map[string]string{}
	}
	return map[string]string{e.config.Password: "[password]"}
}

func (e *Etcd) Type() (string, error) {
	return etcdTypeName, nil
}

func (e *Etcd) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (e *Etcd) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.client != nil {
		_ = e.client.Close()
	}
	e.client = nil
	return nil
}

func (e *Etcd) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg := &etcdConfig{}
	if err := mapstructure.WeakDecode(req.Config, cfg); err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	cfg.Endpoints = sanitizeEndpoints(cfg.Endpoints)
	if len(cfg.Endpoints) == 0 {
		return dbplugin.InitializeResponse{}, errors.New("endpoints is required")
	}

	dialTimeout := defaultDialTimeout
	if cfg.DialTimeout != "" {
		d, err := parseutil.ParseDurationSecond(cfg.DialTimeout)
		if err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("invalid dial_timeout: %w", err)
		}
		dialTimeout = d
	}

	tlsSettings, err := dbtls.Decode(req.Config)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	clientCfg := clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: dialTimeout,
		Username:    cfg.Username,
		Password:    cfg.Password,
		Context:     ctx,
	}
	if tlsSettings.Configured() {
		tlsConfig, err := tlsSettings.Build(hostFromEndpoint(cfg.Endpoints[0]))
		if err != nil {
			return dbplugin.InitializeResponse{}, err
		}
		clientCfg.TLS = tlsConfig
	}

	cli, err := clientv3.New(clientCfg)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("etcd client: %w", err)
	}

	usernameTemplate, err := strutil.GetString(req.Config, "username_template")
	if err != nil {
		_ = cli.Close()
		return dbplugin.InitializeResponse{}, err
	}
	if usernameTemplate == "" {
		usernameTemplate = defaultUserNameTemplate
	}
	up, err := template.NewTemplate(template.Template(usernameTemplate))
	if err != nil {
		_ = cli.Close()
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username_template: %w", err)
	}
	if _, err := up.Generate(dbplugin.UsernameMetadata{}); err != nil {
		_ = cli.Close()
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username template: %w", err)
	}

	if e.client != nil {
		_ = e.client.Close()
	}
	e.config = cfg
	e.client = cli
	e.usernameProducer = up

	if req.VerifyConnection {
		verifyCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		defer cancel()
		if _, err := cli.AuthStatus(verifyCtx); err != nil {
			_ = cli.Close()
			e.client = nil
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to verify connection: %w", err)
		}
	}

	return dbplugin.InitializeResponse{Config: req.Config}, nil
}

// NewUser creates an etcd user via UserAdd and grants each role in the
// statement via UserGrantRole. If a role grant fails (for example the role
// does not exist), the just-created user is deleted so no half-configured
// user is left behind.
func (e *Etcd) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	if len(req.Statements.Commands) == 0 {
		return dbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	var stmt etcdStatement
	if err := json.Unmarshal([]byte(req.Statements.Commands[0]), &stmt); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("creation_statements must be a JSON role doc: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.client == nil {
		return dbplugin.NewUserResponse{}, errors.New("database not initialized")
	}

	username, err := e.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	if _, err := e.client.UserAdd(ctx, username, req.Password); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("create etcd user: %w", err)
	}

	cleanup := func(opErr error) (dbplugin.NewUserResponse, error) {
		_, _ = e.client.UserDelete(ctx, username)
		return dbplugin.NewUserResponse{}, opErr
	}

	for _, role := range stmt.Roles {
		if role == "" {
			continue
		}
		if _, err := e.client.UserGrantRole(ctx, username, role); err != nil {
			return cleanup(fmt.Errorf("grant role %q: %w", role, err))
		}
	}

	return dbplugin.NewUserResponse{Username: username}, nil
}

func (e *Etcd) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("missing username")
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}
	if req.Password == nil {
		return dbplugin.UpdateUserResponse{}, nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.client == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("database not initialized")
	}

	if _, err := e.client.UserChangePassword(ctx, req.Username, req.Password.NewPassword); err != nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("change etcd user password: %w", err)
	}
	return dbplugin.UpdateUserResponse{}, nil
}

func (e *Etcd) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	if req.Username == "" {
		return dbplugin.DeleteUserResponse{}, errors.New("missing username")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.client == nil {
		return dbplugin.DeleteUserResponse{}, errors.New("database not initialized")
	}

	if _, err := e.client.UserDelete(ctx, req.Username); err != nil {
		if isUserNotFound(err) {
			return dbplugin.DeleteUserResponse{}, nil
		}
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("delete etcd user: %w", err)
	}
	return dbplugin.DeleteUserResponse{}, nil
}

// --- helpers ---------------------------------------------------------------

func isUserNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "user name not found")
}

func sanitizeEndpoints(endpoints []string) []string {
	var clean []string
	for _, e := range endpoints {
		for part := range strings.SplitSeq(e, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				clean = append(clean, part)
			}
		}
	}
	return clean
}

// hostFromEndpoint extracts a bare hostname from an etcd endpoint for use as
// the default TLS server name, accepting both scheme-qualified
// (https://host:2379) and bare (host:2379) forms.
func hostFromEndpoint(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	host := endpoint
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}
