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
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	corex509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/display"
	"github.com/notaryproject/notation/v2/internal/osutil"
)

// AddCert adds a single cert file at path to the trust store
// under dir truststore/x509/storeType/namedStore
func AddCert(path, storeType, namedStore string, display bool) error {
	// initialize
	certPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if storeType == "" {
		return errors.New("store type cannot be empty")
	}
	if !IsValidStoreType(storeType) {
		return fmt.Errorf("unsupported store type: %s", storeType)
	}
	if !IsValidFileName(namedStore) {
		return errors.New("named store name needs to follow [a-zA-Z0-9_.-]+ format")
	}

	// check if the target path is a x509 certificate
	// (support PEM and DER formats)
	certs, err := corex509.ReadCertificateFile(certPath)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return errors.New("no valid certificate found in the file")
	}

	// core process
	// get the trust store path
	trustStorePath, err := dir.ConfigFS().SysPath(dir.TrustStoreDir, "x509", storeType, namedStore)
	if err := CheckNonErrNotExistError(err); err != nil {
		return err
	}

	// every certificate in the file is validated against the target store
	// type before any file is written, so a rejected file never leaves a
	// partial state in the trust store.
	for _, cert := range certs {
		if err := validateCertForStoreType(cert, truststore.Type(storeType)); err != nil {
			return err
		}
	}

	// duplicate detection is based on the certificate thumbprint instead of
	// the file name: the same certificate cannot be added twice, even when it
	// is provided under a different file name, while different certificates
	// sharing a file name are still accepted.
	existingThumbprints, err := thumbprintsInStore(trustStorePath)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(certs))
	var targetPaths []string
	for index, cert := range certs {
		thumbprint := certThumbprint(cert)
		if existingThumbprints[thumbprint] || seen[thumbprint] {
			return fmt.Errorf("certificate with subject %q already exists in the Trust Store", cert.Subject)
		}
		seen[thumbprint] = true

		targetPath, err := targetCertPath(trustStorePath, filepath.Base(certPath), len(certs), index, targetPaths)
		if err != nil {
			return err
		}
		targetPaths = append(targetPaths, targetPath)
	}

	// write out: a single-certificate file is copied as-is, while a
	// multi-certificate file is split into one file per certificate so that
	// each certificate can be independently validated and managed.
	if err := os.MkdirAll(trustStorePath, 0700); err != nil {
		return err
	}
	if len(certs) == 1 {
		sourceBytes, err := os.ReadFile(certPath)
		if err != nil {
			return err
		}
		if err := osutil.WriteFileWithPermission(targetPaths[0], sourceBytes, 0600, false); err != nil {
			return err
		}
	} else {
		for index, cert := range certs {
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			if err := osutil.WriteFileWithPermission(targetPaths[index], pemBytes, 0600, false); err != nil {
				return err
			}
		}
	}

	// write out
	if display {
		for _, targetPath := range targetPaths {
			fmt.Printf("Successfully added %s to named store %s of type %s\n", filepath.Base(targetPath), namedStore, storeType)
		}
	}
	return nil
}

// validateCertForStoreType checks that cert is eligible for the target trust
// store type before it is added. The check only applies to certificates being
// newly added; certificates already stored in an existing trust store are not
// re-validated.
func validateCertForStoreType(cert *x509.Certificate, storeType truststore.Type) error {
	switch storeType {
	case truststore.TypeCA:
		return validateCACert(cert)
	case truststore.TypeSigningAuthority:
		return validateSigningAuthorityCert(cert)
	case truststore.TypeTSA:
		return validateTSACert(cert)
	default:
		return fmt.Errorf("unsupported store type: %s", storeType)
	}
}

// validateCACert requires the CA bit and the certificate signing key usage,
// which together allow the certificate to issue other certificates.
func validateCACert(cert *x509.Certificate) error {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return fmt.Errorf("certificate with subject %q is not a CA certificate and cannot be added to a trust store of type %q: the CA bit in basic constraints must be present and set to true", cert.Subject, truststore.TypeCA)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("certificate with subject %q cannot be added to a trust store of type %q: the keyCertSign key usage must be set", cert.Subject, truststore.TypeCA)
	}
	return nil
}

// validateSigningAuthorityCert requires a self-signed, self-issued certificate
// that does not carry the CA bit, so the trusted signing authority cannot be
// used to expand trust onto an arbitrary issuance chain.
func validateSigningAuthorityCert(cert *x509.Certificate) error {
	if cert.BasicConstraintsValid && cert.IsCA {
		return fmt.Errorf("certificate with subject %q is a CA certificate and cannot be added to a trust store of type %q", cert.Subject, truststore.TypeSigningAuthority)
	}
	selfSigned, err := isSelfSignedCert(cert)
	if err != nil {
		return fmt.Errorf("certificate with subject %q is not self-signed and cannot be added to a trust store of type %q: %w", cert.Subject, truststore.TypeSigningAuthority, err)
	}
	if !selfSigned {
		return fmt.Errorf("certificate with subject %q is not self-signed and cannot be added to a trust store of type %q", cert.Subject, truststore.TypeSigningAuthority)
	}
	return nil
}

// validateTSACert requires the timeStamping extended key usage, which is the
// property that distinguishes a timestamping certificate from an ordinary
// signing certificate.
func validateTSACert(cert *x509.Certificate) error {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			return nil
		}
	}
	return fmt.Errorf("certificate with subject %q cannot be added to a trust store of type %q: the timeStamping extended key usage must be set", cert.Subject, truststore.TypeTSA)
}

// isSelfSignedCert reports whether cert is self-signed and self-issued.
// CheckSignatureFrom is not used here because it rejects non-CA certificates
// while signing authority certificates are self-signed non-CA certificates.
func isSelfSignedCert(cert *x509.Certificate) (bool, error) {
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return false, err
	}
	return bytes.Equal(cert.RawSubject, cert.RawIssuer), nil
}

// certThumbprint returns the lowercase hex-encoded SHA-256 thumbprint of the
// DER-encoded certificate.
func certThumbprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// thumbprintsInStore collects the thumbprints of all certificates already
// stored under trustStorePath. Files that cannot be parsed as certificates are
// ignored so that pre-existing, non-conformant trust stores keep working.
func thumbprintsInStore(trustStorePath string) (map[string]bool, error) {
	thumbprints := make(map[string]bool)
	entries, err := os.ReadDir(trustStorePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return thumbprints, nil
		}
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		certs, err := corex509.ReadCertificateFile(filepath.Join(trustStorePath, entry.Name()))
		if err != nil {
			continue
		}
		for _, cert := range certs {
			thumbprints[certThumbprint(cert)] = true
		}
	}
	return thumbprints, nil
}

// targetCertPath determines the file path for a certificate being added.
// A single-certificate file keeps its original file name. Certificates from
// a multi-certificate file are written as <name>_<index>.<ext> and any name
// already taken on disk or in this batch is made unique with a numeric suffix.
func targetCertPath(trustStorePath, baseName string, totalCerts, index int, planned []string) (string, error) {
	if totalCerts == 1 {
		candidate := filepath.Join(trustStorePath, baseName)
		ext := filepath.Ext(baseName)
		stem := strings.TrimSuffix(baseName, ext)
		for suffix := 2; ; suffix++ {
			taken, err := pathExists(candidate)
			if err != nil {
				return "", err
			}
			if !taken && !containsPath(planned, candidate) {
				return candidate, nil
			}
			candidate = filepath.Join(trustStorePath, fmt.Sprintf("%s_%d%s", stem, suffix, ext))
		}
	}
	ext := filepath.Ext(baseName)
	stem := strings.TrimSuffix(baseName, ext)
	candidate := filepath.Join(trustStorePath, fmt.Sprintf("%s_%d%s", stem, index+1, ext))
	for suffix := 2; ; suffix++ {
		taken, err := pathExists(candidate)
		if err != nil {
			return "", err
		}
		if !taken && !containsPath(planned, candidate) {
			return candidate, nil
		}
		candidate = filepath.Join(trustStorePath, fmt.Sprintf("%s_%d_%d%s", stem, index+1, suffix, ext))
	}
}

func pathExists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func containsPath(paths []string, target string) bool {
	for _, path := range paths {
		if path == target {
			return true
		}
	}
	return false
}

// ListCerts walks through root and returns all x509 certificates in it,
// sub-dirs are ignored.
func ListCerts(root string, depth int) ([]string, error) {
	maxDepth := strings.Count(root, string(os.PathSeparator)) + depth
	var certPaths []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.Count(path, string(os.PathSeparator)) > maxDepth {
			return fs.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			certs, err := corex509.ReadCertificateFile(path)
			if err != nil {
				return err
			}
			if len(certs) != 0 {
				certPaths = append(certPaths, path)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return certPaths, nil
}

// ShowCerts writes out details of certificates
func ShowCerts(certs []*x509.Certificate) {
	fmt.Println("Certificate details")
	fmt.Println("--------------------------------------------------------------------------------")
	for ind, cert := range certs {
		showCert(cert)
		if ind != len(certs)-1 {
			fmt.Println("--------------------------------------------------------------------------------")
		}
	}
}

// showCert displays details of a certificate
func showCert(cert *x509.Certificate) {
	fmt.Println("Issuer:", cert.Issuer)
	fmt.Println("Subject:", cert.Subject)
	fmt.Println("Valid from:", cert.NotBefore)
	fmt.Println("Valid to:", cert.NotAfter)
	fmt.Println("IsCA:", cert.IsCA)

	h := sha256.Sum256(cert.Raw)
	fmt.Println("SHA256 Thumbprint:", strings.ToLower(hex.EncodeToString(h[:])))
}

// DeleteAllCerts deletes all certificate files from the trust store
// under dir truststore/x509/storeType/namedStore
func DeleteAllCerts(storeType, namedStore string, confirmed bool) error {
	path, err := dir.ConfigFS().SysPath(dir.TrustStoreDir, "x509", storeType, namedStore)
	if err != nil {
		return err
	}
	prompt := fmt.Sprintf("Are you sure you want to delete all certificates in %q of type %q?", namedStore, storeType)
	confirmed, err = display.AskForConfirmation(os.Stdin, prompt, confirmed)
	if err != nil {
		return err
	}
	if !confirmed {
		return nil
	}
	if _, err = os.Stat(path); err != nil {
		return err
	}
	if err = os.RemoveAll(path); err != nil {
		return err
	}

	// write out on success
	fmt.Printf("Successfully deleted %s\n", path)
	return nil
}

// DeleteCert deletes a specific certificate file from the
// trust store, namely truststore/x509/storeType/namedStore/cert
func DeleteCert(storeType, namedStore, cert string, confirmed bool) error {
	path, err := dir.ConfigFS().SysPath(dir.TrustStoreDir, "x509", storeType, namedStore, cert)
	if err != nil {
		return err
	}
	prompt := fmt.Sprintf("Are you sure you want to delete %q in %q of type %q?", cert, namedStore, storeType)
	confirmed, err = display.AskForConfirmation(os.Stdin, prompt, confirmed)
	if err != nil {
		return err
	}
	if !confirmed {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	if err = os.Remove(path); err != nil {
		return err
	}

	// remove the trust store directory if empty
	storePath := filepath.Dir(path)
	empty, err := osutil.IsDirEmpty(storePath)
	if err != nil {
		// in this case, empty is always false
		fmt.Fprintf(os.Stderr, "Warning: failed to check if the trust store directory %s is empty: %v\n", storePath, err)
	}
	if empty {
		if err := os.Remove(storePath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove the empty trust store directory %s: %v\n", storePath, err)
		}
	}

	// write out on success
	fmt.Printf("Successfully deleted %s from trust store %s of type %s\n", cert, namedStore, storeType)
	return nil
}

// CheckNonErrNotExistError returns nil when err is nil or err is fs.ErrNotExist
func CheckNonErrNotExistError(err error) error {
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// IsValidStoreType checks if storeType is supported
func IsValidStoreType(storeType string) bool {
	for _, t := range truststore.Types {
		if storeType == string(t) {
			return true
		}
	}
	return false
}

// IsValidFileName checks if a file name is cross-platform compatible
func IsValidFileName(fileName string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(fileName)
}
