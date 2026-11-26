// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package truststore_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/truststore"
)

func setupPathSecurityConfig(t *testing.T) string {
	t.Helper()

	oldUserConfigDir := dir.UserConfigDir
	configDir := t.TempDir()
	dir.UserConfigDir = configDir
	t.Cleanup(func() {
		dir.UserConfigDir = oldUserConfigDir
	})
	return configDir
}

func writePathSecurityFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteCertPathSecurityAllowsExistingLayouts(t *testing.T) {
	configDir := setupPathSecurityConfig(t)
	storeDir := filepath.Join(configDir, dir.TrustStoreDir, "x509", "ca", "path-security")

	dottedCert := filepath.Join(storeDir, "example.com.crt")
	nestedCert := filepath.Join(storeDir, "levels", "v1.2", "nested.crt")
	nonCanonicalDirCert := filepath.Join(storeDir, "existing nested dir", "cert.crt")
	writePathSecurityFile(t, dottedCert)
	writePathSecurityFile(t, nestedCert)
	writePathSecurityFile(t, nonCanonicalDirCert)

	if err := truststore.DeleteCert("ca", "path-security", "example.com.crt", true); err != nil {
		t.Fatalf("DeleteCert() dotted file returned error: %v", err)
	}
	if _, err := os.Stat(dottedCert); !os.IsNotExist(err) {
		t.Fatalf("dotted certificate was not deleted, stat error: %v", err)
	}

	nestedRelativePath := filepath.Join("levels", "v1.2", "nested.crt")
	if err := truststore.DeleteCert("ca", "path-security", nestedRelativePath, true); err != nil {
		t.Fatalf("DeleteCert() nested file returned error: %v", err)
	}
	if _, err := os.Stat(nestedCert); !os.IsNotExist(err) {
		t.Fatalf("nested certificate was not deleted, stat error: %v", err)
	}
	emptyParent := filepath.Dir(nestedCert)
	if _, err := os.Stat(emptyParent); !os.IsNotExist(err) {
		t.Fatalf("empty nested parent %s should be removed, stat error: %v", emptyParent, err)
	}
	if _, err := os.Stat(filepath.Dir(emptyParent)); err != nil {
		t.Fatalf("non-empty ancestor should remain: %v", err)
	}

	nonCanonicalRelativePath := filepath.Join("existing nested dir", "cert.crt")
	if err := truststore.DeleteCert("ca", "path-security", nonCanonicalRelativePath, true); err != nil {
		t.Fatalf("DeleteCert() with an existing non-canonical directory returned error: %v", err)
	}
	if _, err := os.Stat(nonCanonicalDirCert); !os.IsNotExist(err) {
		t.Fatalf("certificate in non-canonical directory was not deleted: %v", err)
	}
}

func TestDeleteCertPathSecurityBlocksTraversal(t *testing.T) {
	configDir := setupPathSecurityConfig(t)
	storeDir := filepath.Join(configDir, dir.TrustStoreDir, "x509", "ca", "path-security")
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}

	outsideDir := filepath.Join(configDir, "outside-parent")
	outsideCert := filepath.Join(outsideDir, "outside.crt")
	writePathSecurityFile(t, outsideCert)

	relativeCert, err := filepath.Rel(storeDir, outsideCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := truststore.DeleteCert("ca", "path-security", relativeCert, true); err == nil {
		t.Fatal("DeleteCert() with path traversal expected an error")
	}
	if _, err := os.Stat(outsideCert); err != nil {
		t.Fatalf("outside certificate must remain: %v", err)
	}
	if _, err := os.Stat(outsideDir); err != nil {
		t.Fatalf("outside parent directory must remain: %v", err)
	}
}

func TestDeleteCertPathSecurityBlocksSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test is not reliable without elevated privileges on Windows")
	}

	configDir := setupPathSecurityConfig(t)
	storeDir := filepath.Join(configDir, dir.TrustStoreDir, "x509", "ca", "path-security")
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}

	outsideCert := filepath.Join(configDir, "outside.crt")
	writePathSecurityFile(t, outsideCert)
	linkPath := filepath.Join(storeDir, "linked.crt")
	if err := os.Symlink(outsideCert, linkPath); err != nil {
		t.Skipf("symlinks are not supported: %v", err)
	}

	if err := truststore.DeleteCert("ca", "path-security", "linked.crt", true); err == nil {
		t.Fatal("DeleteCert() with an escaping symlink expected an error")
	}
	if _, err := os.Stat(outsideCert); err != nil {
		t.Fatalf("outside certificate target must remain: %v", err)
	}
	if _, err := os.Lstat(linkPath); err != nil {
		t.Fatalf("symlink must remain after rejected deletion: %v", err)
	}
}

func TestDeleteCertPathSecurityFileNameRules(t *testing.T) {
	tests := []struct {
		name string
		cert string
		want bool
	}{
		{name: "dotted file", cert: "example.com.crt", want: true},
		{name: "hidden file", cert: ".hidden", want: true},
		{name: "nested path base name", cert: filepath.Join("level-1", "v1.2", "cert_1.pem"), want: true},
		{name: "traversal base name", cert: filepath.Join("..", "outside.crt"), want: true},
		{name: "empty", cert: "", want: false},
		{name: "current directory", cert: ".", want: false},
		{name: "parent directory only", cert: "..", want: false},
		{name: "invalid character", cert: "cert$.crt", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cert != "" && !filepath.IsAbs(tt.cert) && truststore.IsValidFileName(filepath.Base(tt.cert))
			if got != tt.want {
				t.Fatalf("certificate name validation for %q = %v, want %v", tt.cert, got, tt.want)
			}
		})
	}
}
