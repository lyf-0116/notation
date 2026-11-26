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

package truststore

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	corex509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go/dir"
)

func TestAddCert(t *testing.T) {
	defer func(oldDir string) {
		dir.UserConfigDir = oldDir
	}(dir.UserConfigDir)

	t.Run("empty store type", func(t *testing.T) {
		expectedErrMsg := "store type cannot be empty"
		err := AddCert("", "", "test", false)
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected err: %v, but got: %v", expectedErrMsg, err)
		}
	})

	t.Run("invalid store type", func(t *testing.T) {
		expectedErrMsg := "unsupported store type: invalid"
		err := AddCert("", "invalid", "test", false)
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected err: %v, but got: %v", expectedErrMsg, err)
		}
	})

	t.Run("invalid store name", func(t *testing.T) {
		expectedErrMsg := "named store name needs to follow [a-zA-Z0-9_.-]+ format"
		err := AddCert("", "ca", "test%", false)
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected err: %v, but got: %v", expectedErrMsg, err)
		}
	})

	t.Run("no valid certificate in file", func(t *testing.T) {
		path := filepath.FromSlash("testdata/invalid.txt")
		expectedErrMsg := "x509: malformed certificate"
		err := AddCert(path, "ca", "test", false)
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected err: %v, but got: %v", expectedErrMsg, err)
		}
	})

	t.Run("cert already exists", func(t *testing.T) {
		configDir := t.TempDir()
		dir.UserConfigDir = configDir
		path := filepath.FromSlash("testdata/fixtures/ca.crt")
		if err := AddCert(path, "ca", "test", false); err != nil {
			t.Fatalf("failed to add the first certificate: %v", err)
		}
		// the same certificate under a different file name must still be
		// detected as a duplicate based on its thumbprint
		duplicatePath := filepath.Join(configDir, "different-name.crt")
		if err := os.WriteFile(duplicatePath, mustReadFile(t, path), 0600); err != nil {
			t.Fatal(err)
		}
		expectedErrMsg := `certificate with subject "CN=Test CA" already exists in the Trust Store`
		err := AddCert(duplicatePath, "ca", "test", false)
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected err: %v, but got: %v", expectedErrMsg, err)
		}
	})

	t.Run("same file name with different content is allowed", func(t *testing.T) {
		dir.UserConfigDir = t.TempDir()
		firstPath := filepath.Join(t.TempDir(), "ca.crt")
		if err := os.WriteFile(firstPath, mustReadFile(t, filepath.FromSlash("testdata/fixtures/ca.crt")), 0600); err != nil {
			t.Fatal(err)
		}
		secondPath := filepath.Join(t.TempDir(), "ca.crt")
		if err := os.WriteFile(secondPath, mustReadFile(t, filepath.FromSlash("testdata/fixtures/ca2.crt")), 0600); err != nil {
			t.Fatal(err)
		}
		if err := AddCert(firstPath, "ca", "test", false); err != nil {
			t.Fatalf("failed to add the first certificate: %v", err)
		}
		if err := AddCert(secondPath, "ca", "test", false); err != nil {
			t.Fatalf("expected the different certificate with the same file name to be added, but got: %v", err)
		}
	})

	t.Run("leaf certificate is rejected by ca store", func(t *testing.T) {
		dir.UserConfigDir = t.TempDir()
		path := filepath.FromSlash("testdata/fixtures/leaf.crt")
		err := AddCert(path, "ca", "test", false)
		if err == nil || !strings.Contains(err.Error(), `is not a CA certificate`) {
			t.Fatalf("expected a CA validation error, but got: %v", err)
		}
	})

	t.Run("CA certificate without keyCertSign is rejected by ca store", func(t *testing.T) {
		dir.UserConfigDir = t.TempDir()
		path := filepath.FromSlash("testdata/fixtures/ca_nocertsign.crt")
		err := AddCert(path, "ca", "test", false)
		if err == nil || !strings.Contains(err.Error(), "keyCertSign key usage must be set") {
			t.Fatalf("expected a key usage validation error, but got: %v", err)
		}
	})

	t.Run("self-signed non-CA certificate is accepted by signingAuthority store", func(t *testing.T) {
		dir.UserConfigDir = t.TempDir()
		path := filepath.FromSlash("testdata/fixtures/leaf.crt")
		if err := AddCert(path, "signingAuthority", "test", false); err != nil {
			t.Fatalf("expected the self-signed non-CA certificate to be added, but got: %v", err)
		}
	})

	t.Run("CA certificate is rejected by signingAuthority store", func(t *testing.T) {
		dir.UserConfigDir = t.TempDir()
		path := filepath.FromSlash("testdata/fixtures/ca.crt")
		err := AddCert(path, "signingAuthority", "test", false)
		if err == nil || !strings.Contains(err.Error(), "is a CA certificate") {
			t.Fatalf("expected a CA rejection error, but got: %v", err)
		}
	})

	t.Run("non-self-signed certificate is rejected by signingAuthority store", func(t *testing.T) {
		dir.UserConfigDir = t.TempDir()
		path := filepath.FromSlash("testdata/fixtures/issued.crt")
		err := AddCert(path, "signingAuthority", "test", false)
		if err == nil || !strings.Contains(err.Error(), "is not self-signed") {
			t.Fatalf("expected a self-signed validation error, but got: %v", err)
		}
	})

	t.Run("timestamping certificate is accepted by tsa store", func(t *testing.T) {
		dir.UserConfigDir = t.TempDir()
		path := filepath.FromSlash("testdata/fixtures/tsa.crt")
		if err := AddCert(path, "tsa", "test", false); err != nil {
			t.Fatalf("expected the timestamping certificate to be added, but got: %v", err)
		}
	})

	t.Run("ordinary signing certificate is rejected by tsa store", func(t *testing.T) {
		dir.UserConfigDir = t.TempDir()
		path := filepath.FromSlash("testdata/fixtures/leaf.crt")
		err := AddCert(path, "tsa", "test", false)
		if err == nil || !strings.Contains(err.Error(), "timeStamping extended key usage must be set") {
			t.Fatalf("expected a timestamping validation error, but got: %v", err)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.FromSlash("../../../../internal/testdata/Empty.txt")
		expectedErr := errors.New("no valid certificate found in the empty file")
		err := AddCert(path, "ca", "test", false)
		if err == nil || err.Error() != "no valid certificate found in the file" {
			t.Fatalf("expected err: %v, but got: %v", expectedErr, err)
		}
	})

	t.Run("multi-certificate file is split and validated per certificate", func(t *testing.T) {
		dir.UserConfigDir = t.TempDir()
		path := filepath.FromSlash("testdata/fixtures/multi_ca.pem")
		if err := AddCert(path, "ca", "test", false); err != nil {
			t.Fatalf("expected the multi-certificate file to be added, but got: %v", err)
		}
		storePath := filepath.Join(dir.UserConfigDir, "truststore", "x509", "ca", "test")
		firstFile := filepath.Join(storePath, "multi_ca_1.pem")
		secondFile := filepath.Join(storePath, "multi_ca_2.pem")
		firstCerts := readCerts(t, firstFile)
		secondCerts := readCerts(t, secondFile)
		if len(firstCerts) != 1 || len(secondCerts) != 1 {
			t.Fatalf("expected each split file to contain one certificate, but got %d and %d", len(firstCerts), len(secondCerts))
		}
		if certThumbprint(firstCerts[0]) == certThumbprint(secondCerts[0]) {
			t.Fatal("expected the split files to contain the two different certificates")
		}
	})

	t.Run("duplicate certificate inside one file is rejected", func(t *testing.T) {
		dir.UserConfigDir = t.TempDir()
		path := filepath.FromSlash("testdata/fixtures/duplicate_in_file.pem")
		err := AddCert(path, "ca", "test", false)
		if err == nil || !strings.Contains(err.Error(), "already exists in the Trust Store") {
			t.Fatalf("expected a duplicate error, but got: %v", err)
		}
		storePath := filepath.Join(dir.UserConfigDir, "truststore", "x509", "ca", "test")
		if _, err := os.Stat(storePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected nothing to be written on rejection, but store exists: %v", err)
		}
	})

	t.Run("rejected multi-certificate file writes nothing", func(t *testing.T) {
		dir.UserConfigDir = t.TempDir()
		// a leaf bundled with CAs fails the ca type validation
		mixedPath := filepath.Join(t.TempDir(), "mixed.pem")
		content := append(mustReadFile(t, filepath.FromSlash("testdata/fixtures/ca.crt")), mustReadFile(t, filepath.FromSlash("testdata/fixtures/leaf.crt"))...)
		if err := os.WriteFile(mixedPath, content, 0600); err != nil {
			t.Fatal(err)
		}
		if err := AddCert(mixedPath, "ca", "test", false); err == nil {
			t.Fatal("expected the mixed bundle to be rejected by the ca store validation")
		}
		storePath := filepath.Join(dir.UserConfigDir, "truststore", "x509", "ca", "test")
		if _, err := os.Stat(storePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected nothing to be written on rejection, but store exists: %v", err)
		}
	})

	t.Run("failed to add cert to store", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}

		dir.UserConfigDir = t.TempDir()
		if err := os.Chmod(dir.UserConfigDir, 0000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(dir.UserConfigDir, 0700)

		path := filepath.FromSlash("testdata/NotationTestRoot.pem")
		expectedErrMsg := "permission denied"
		err := AddCert(path, "ca", "test", false)
		if err == nil || !strings.Contains(err.Error(), expectedErrMsg) {
			t.Fatalf("expected err: %v, but got: %v", expectedErrMsg, err)
		}
	})
}

func TestDeleteAllCerts(t *testing.T) {
	defer func(oldDir string) {
		dir.UserConfigDir = oldDir
	}(dir.UserConfigDir)

	t.Run("store does not exist", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}

		dir.UserConfigDir = "testdata"
		expectedErrMsg := `stat testdata/truststore/x509/tsa/test: no such file or directory`
		err := DeleteAllCerts("tsa", "test", true)
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected err: %v, but got: %v", expectedErrMsg, err)
		}
	})
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func readCerts(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	certs, err := corex509.ReadCertificateFile(path)
	if err != nil {
		t.Fatalf("failed to read certificates from %s: %v", path, err)
	}
	return certs
}
