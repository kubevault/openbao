// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package etcd

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/stretchr/testify/require"
)

func TestEtcd_TypeAndVersion(t *testing.T) {
	db := newEtcd()
	typ, err := db.Type()
	require.NoError(t, err)
	require.Equal(t, etcdTypeName, typ)
	require.Equal(t, ReportedVersion, db.PluginVersion().Version)
}

func TestEtcd_SanitizeEndpoints(t *testing.T) {
	require.Equal(
		t,
		[]string{"https://etcd1.example:2379", "https://etcd2.example:2379"},
		sanitizeEndpoints([]string{"https://etcd1.example:2379,https://etcd2.example:2379"}),
	)
	require.Equal(
		t,
		[]string{"etcd1:2379", "etcd2:2379"},
		sanitizeEndpoints([]string{" etcd1:2379 ", "etcd2:2379"}),
	)
	require.Nil(t, sanitizeEndpoints(nil))
}

func TestEtcd_HostFromEndpoint(t *testing.T) {
	require.Equal(t, "etcd.example.com", hostFromEndpoint("https://etcd.example.com:2379"))
	require.Equal(t, "etcd.example.com", hostFromEndpoint("etcd.example.com:2379"))
	require.Equal(t, "etcd.example.com", hostFromEndpoint("etcd.example.com"))
}

func TestEtcd_IsUserNotFound(t *testing.T) {
	require.False(t, isUserNotFound(nil))
	require.False(t, isUserNotFound(context.DeadlineExceeded))
	require.True(t, isUserNotFound(&testErr{"etcdserver: user name not found"}))
}

type testErr struct{ msg string }

func (e *testErr) Error() string { return e.msg }

func TestEtcd_StatementParsing(t *testing.T) {
	raw := `{"roles":["reader","editor"]}`
	var s etcdStatement
	require.NoError(t, json.Unmarshal([]byte(raw), &s))
	require.Equal(t, []string{"reader", "editor"}, s.Roles)
}

func TestEtcd_Initialize_RequiresEndpoints(t *testing.T) {
	db := newEtcd()
	_, err := db.Initialize(t.Context(), dbplugin.InitializeRequest{
		Config: map[string]any{
			"username": "root",
			"password": "password",
		},
	})
	require.ErrorContains(t, err, "endpoints is required")
}

func TestEtcd_Initialize_InvalidDialTimeout(t *testing.T) {
	db := newEtcd()
	_, err := db.Initialize(t.Context(), dbplugin.InitializeRequest{
		Config: map[string]any{
			"endpoints":    "etcd.example.com:2379",
			"username":     "root",
			"password":     "password",
			"dial_timeout": "not-a-duration",
		},
	})
	require.ErrorContains(t, err, "invalid dial_timeout")
}

func TestEtcd_Initialize_RejectsIncompleteClientIdentity(t *testing.T) {
	db := newEtcd()
	_, err := db.Initialize(t.Context(), dbplugin.InitializeRequest{
		Config: map[string]any{
			"endpoints":       "etcd.example.com:2379",
			"username":        "root",
			"password":        "password",
			"tls_certificate": "certificate",
		},
	})
	require.ErrorContains(t, err, "both tls_certificate and tls_key are required")
}

func TestEtcd_UpdateUser_Validation(t *testing.T) {
	db := newEtcd()
	_, err := db.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing username")

	_, err = db.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{Username: "u"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no changes requested")
}

func TestEtcd_DeleteUser_Validation(t *testing.T) {
	db := newEtcd()
	_, err := db.DeleteUser(context.Background(), dbplugin.DeleteUserRequest{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing username")
}

func TestEtcd_NotInitialized(t *testing.T) {
	db := newEtcd()

	_, err := db.NewUser(context.Background(), dbplugin.NewUserRequest{
		Statements: dbplugin.Statements{
			Commands: []string{`{"roles":["reader"]}`},
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "database not initialized")

	_, err = db.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{
		Username: "u",
		Password: &dbplugin.ChangePassword{NewPassword: "p"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "database not initialized")

	_, err = db.DeleteUser(context.Background(), dbplugin.DeleteUserRequest{
		Username: "u",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "database not initialized")
}

func TestEtcd_NewUser_EmptyCreationStatement(t *testing.T) {
	db := newEtcd()
	_, err := db.NewUser(context.Background(), dbplugin.NewUserRequest{})
	require.Error(t, err)
}

func TestEtcd_Acceptance(t *testing.T) {
	if os.Getenv("BAO_ACC") != "1" || os.Getenv("ETCD_ENDPOINTS") == "" {
		t.Skip("set BAO_ACC=1 and ETCD_ENDPOINTS to run etcd acceptance tests")
	}
}
