// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package encryption provides methods for encrypting backups.
package encryption

import (
	"fmt"
	"io"
	"os"

	"filippo.io/age"

	"github.com/siderolabs/talos-backup/pkg/util"
)

// EncryptFile encrypts a file with one or more age X25519 public keys.
func EncryptFile(fileToEncryptPath string, publicKeys []string) (string, error) {
	encryptedFileName, err := encryptFile(fileToEncryptPath, publicKeys)

	if err != nil && encryptedFileName != "" {
		util.CleanupFile(encryptedFileName)
	}

	return encryptedFileName, err
}

// encryptFile encrypts a file with one or more age X25519 public keys.
func encryptFile(fileToEncryptPath string, publicKeys []string) (string, error) {
	recipients := make([]age.Recipient, 0, len(publicKeys))
	for _, key := range publicKeys {
		recipient, err := age.ParseX25519Recipient(key)
		if err != nil {
			return "", fmt.Errorf("failed to parse public key: %w", err)
		}

		recipients = append(recipients, recipient)
	}

	fileToEncrypt, err := os.OpenFile(fileToEncryptPath, os.O_RDONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("failed to open file for encryption %q: %w", fileToEncryptPath, err)
	}

	defer fileToEncrypt.Close() //nolint:errcheck

	encryptedFileName := fileToEncryptPath + ".age"

	encryptedFile, err := os.OpenFile(encryptedFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("failed to allocate encrypted file %q: %w", encryptedFileName, err)
	}

	defer encryptedFile.Close() //nolint:errcheck

	w, err := age.Encrypt(encryptedFile, recipients...)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt file %q: %w", fileToEncryptPath, err)
	}

	if _, err := io.Copy(w, fileToEncrypt); err != nil {
		return "", fmt.Errorf("failed to write encrypted file %q: %w", encryptedFileName, err)
	}

	if err := w.Close(); err != nil {
		return "", fmt.Errorf("failed to close writer: %w", err)
	}

	if err := encryptedFile.Sync(); err != nil {
		return "", fmt.Errorf("failed to sync encrypted file to disk: %w", err)
	}

	return encryptedFileName, nil
}
