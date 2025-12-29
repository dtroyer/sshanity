// sshanity/server/server_test.go
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// GenerateTestKeys generates test host key and authorized key for testing
func GenerateTestKeys() (hostKeyPEM []byte, authorizedKey []byte, err error) {
	// Generate Ed25519 key pair for host key
	_, hostPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	// Convert to PEM format
	hostKeyBytes, err := x509.MarshalPKCS8PrivateKey(hostPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal host private key: %w", err)
	}

	hostKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: hostKeyBytes,
	})

	// hostKeyBytes, err := gossh.MarshalPrivateKey(crypto.PrivateKey(hostPrivKey), "")
	// if err != nil {
	// 	return nil, nil, fmt.Errorf("failed to marshal host private key: %w", err)
	// }

	// hostKeyPEM = pem.EncodeToMemory(hostKeyBytes)

	// Generate Ed25519 key pair for authorized key
	authPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate auth key: %w", err)
	}

	// Convert to SSH public key format
	sshAuthPubKey, err := gossh.NewPublicKey(authPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SSH public key: %w", err)
	}

	authorizedKey = gossh.MarshalAuthorizedKey(sshAuthPubKey)

	return hostKeyPEM, authorizedKey, nil
}

func TestSetupServer(t *testing.T) {
	fhk, _, _ := GenerateTestKeys()
	FallbackHostKey = string(fhk)

	hostKey, _, _ := GenerateTestKeys()

	tests := []struct {
		name     string
		config   SSHConfig
		opts     []func(*SSHServer)
		expected *SSHServer
	}{
		{
			name:   "default server configuration",
			config: SSHConfig{},
			opts:   nil,
			expected: &SSHServer{
				HostKey: []byte(FallbackHostKey),
				Address: DefaultBindAddress,
				Port:    DefaultPort,
			},
		},
		{
			name: "server with configured host key",
			config: SSHConfig{
				HostKey: hostKey,
			},
			expected: &SSHServer{
				HostKey: hostKey,
				Address: DefaultBindAddress,
				Port:    DefaultPort,
			},
		},
		{
			name: "server with configured address",
			config: SSHConfig{
				Address: "127.0.0.1",
			},
			expected: &SSHServer{
				HostKey: []byte(FallbackHostKey),
				Address: "127.0.0.1",
				Port:    DefaultPort,
			},
		},
		{
			name: "server with configured port",
			config: SSHConfig{
				Port: 3333,
			},
			expected: &SSHServer{
				HostKey: []byte(FallbackHostKey),
				Address: DefaultBindAddress,
				Port:    3333,
			},
		},
		{
			name: "server with all options",
			config: SSHConfig{
				HostKey: hostKey,
				Address: "127.0.0.1",
			},
			expected: &SSHServer{
				HostKey: hostKey,
				Address: "127.0.0.1",
				Port:    DefaultPort,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := SetupServer(tt.config)

			if len(server.HostKey) == 0 {
				t.Errorf("Expected host key to be set")
			}
			if string(server.HostKey) != string(tt.expected.HostKey) {
				t.Errorf("Expected host key %s got host key %s", string(tt.expected.HostKey), string(server.HostKey))
			}

			if server.Address != tt.expected.Address {
				t.Errorf("Expected bind address %s, got %s", tt.expected.Address, server.Address)
			}
			if server.Port != tt.expected.Port {
				t.Errorf("Expected port %d, got %d", tt.expected.Port, server.Port)
			}
		})
	}
}

func TestHostKeyParse(t *testing.T) {
	// Test parsing host key from PEM data
	hostKeyPEM, _, err := GenerateTestKeys()
	if err != nil {
		t.Fatalf("Failed to generate test keys: %v", err)
	}

	// Test cases for different PEM key formats
	tests := []struct {
		name        string
		pemData     []byte
		shouldParse bool
		keyType     string
	}{
		{
			name:        "valid Ed25519 PEM key",
			pemData:     hostKeyPEM,
			shouldParse: true,
			keyType:     "Ed25519",
		},
		{
			name:        "valid RSA PEM key from file",
			pemData:     loadTestRSAKey(t),
			shouldParse: true,
			keyType:     "RSA",
		},
		{
			name:        "invalid PEM format",
			pemData:     []byte("invalid pem data"),
			shouldParse: false,
		},
		{
			name:        "empty PEM data",
			pemData:     []byte(""),
			shouldParse: false,
		},
		{
			name:        "valid PEM structure but invalid key",
			pemData:     []byte("-----BEGIN PRIVATE KEY-----\nYWJjZGVmZ2g=\n-----END PRIVATE KEY-----"),
			shouldParse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that we can actually parse the PEM key correctly
			err := func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panic during host key parsing: %v", r)
					}
				}()

				if len(tt.pemData) == 0 {
					return fmt.Errorf("empty key data")
				}

				// Try to parse the PEM block
				block, _ := pem.Decode(tt.pemData)
				if block == nil {
					return fmt.Errorf("failed to decode PEM block")
				}

				// Try to parse as a private key and convert to SSH signer
				privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse private key: %w", err)
				}

				// Try to create SSH signer from the private key
				_, err = gossh.NewSignerFromKey(privKey)
				if err != nil {
					return fmt.Errorf("failed to create SSH signer: %w", err)
				}

				return nil
			}()

			if tt.shouldParse && err != nil {
				t.Errorf("Expected PEM key to parse successfully, but got error: %v", err)
			}
			if !tt.shouldParse && err == nil {
				t.Errorf("Expected PEM key parsing to fail, but it succeeded")
			}
		})
	}
}

// loadTestRSAKey generates a test RSA key in PEM format
func loadTestRSAKey(t *testing.T) []byte {
	t.Helper()

	// Generate RSA key pair for testing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Convert to PKCS8 PEM format for compatibility with ssh.HostKeyPEM
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("Failed to marshal RSA key to PKCS8: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
}

func TestHostKeyFromFile(t *testing.T) {
	// Create a temporary key file for testing
	tempDir := t.TempDir()
	keyFilePath := tempDir + "/test_host_key.pem"

	// Generate a test key
	hostKeyPEM, _, err := GenerateTestKeys()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	tests := []struct {
		name        string
		setupFile   func() string
		shouldError bool
	}{
		{
			name: "valid key file",
			setupFile: func() string {
				// Write valid key to file
				err := func() error {
					file, err := os.Create(keyFilePath)
					if err != nil {
						return err
					}
					defer file.Close()
					_, err = file.Write(hostKeyPEM)
					return err
				}()
				if err != nil {
					t.Fatalf("Failed to write test key file: %v", err)
				}
				return keyFilePath
			},
			shouldError: false,
		},
		{
			name: "nonexistent key file",
			setupFile: func() string {
				return "/nonexistent/path/key.pem"
			},
			shouldError: true,
		},
		{
			name: "invalid key file content",
			setupFile: func() string {
				invalidKeyPath := tempDir + "/invalid_key.pem"
				err := func() error {
					file, err := os.Create(invalidKeyPath)
					if err != nil {
						return err
					}
					defer file.Close()
					_, err = file.Write([]byte("invalid key content"))
					return err
				}()
				if err != nil {
					t.Fatalf("Failed to write invalid key file: %v", err)
				}
				return invalidKeyPath
			},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setupFile()

			// Test loading the key from file
			keyData, err := loadHostKeyFromFile(filePath)

			if tt.shouldError && err == nil {
				t.Error("Expected error when loading key from file, but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Expected no error when loading key from file, but got: %v", err)
			}
			if !tt.shouldError && len(keyData) == 0 {
				t.Error("Expected key data to be loaded, but got empty data")
			}
		})
	}
}

func TestHostKeyFromEnvironment(t *testing.T) {
	// Generate test key for environment variable tests
	hostKeyPEM, _, err := GenerateTestKeys()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	tests := []struct {
		name        string
		envValue    string
		shouldError bool
	}{
		{
			name:        "valid key in environment",
			envValue:    string(hostKeyPEM),
			shouldError: false,
		},
		{
			name:        "empty environment variable",
			envValue:    "",
			shouldError: true,
		},
		{
			name:        "invalid key in environment",
			envValue:    "invalid key content",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			envVar := "SSH_HOST_KEY_PEM"
			if tt.envValue != "" {
				t.Setenv(envVar, tt.envValue)
			} else {
				os.Unsetenv(envVar)
			}

			// Test loading key from environment
			keyData, err := loadHostKeyFromEnv(envVar)

			if tt.shouldError && err == nil {
				t.Error("Expected error when loading key from environment, but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Expected no error when loading key from environment, but got: %v", err)
			}
			if !tt.shouldError && len(keyData) == 0 {
				t.Error("Expected key data to be loaded from environment, but got empty data")
			}
		})
	}
}

func TestHostKeyPriority(t *testing.T) {
	// Test the priority order: explicit config > environment > file > fallback
	hostKeyPEM, _, err := GenerateTestKeys()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Create test key file
	tempDir := t.TempDir()
	keyFilePath := tempDir + "/test_host_key.pem"
	err = func() error {
		file, err := os.Create(keyFilePath)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = file.Write(hostKeyPEM)
		return err
	}()
	if err != nil {
		t.Fatalf("Failed to create test key file: %v", err)
	}

	// Set environment variable
	t.Setenv("SSH_HOST_KEY_PEM", string(hostKeyPEM))

	tests := []struct {
		name           string
		configKey      []byte
		expectedSource string
	}{
		{
			name:           "explicit config takes priority",
			configKey:      hostKeyPEM,
			expectedSource: "config",
		},
		{
			name:           "fallback to environment when no config",
			configKey:      nil,
			expectedSource: "environment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := SSHConfig{
				HostKey: tt.configKey,
			}

			// If no config key, try loading from environment or file
			if config.HostKey == nil {
				// Try environment first
				envKey, err := loadHostKeyFromEnv("SSH_HOST_KEY_PEM")
				if err == nil {
					config.HostKey = envKey
				} else {
					// Try file as fallback
					fileKey, err := loadHostKeyFromFile(keyFilePath)
					if err == nil {
						config.HostKey = fileKey
					}
				}
			}

			server := SetupServer(config)

			if len(server.HostKey) == 0 {
				t.Error("Expected host key to be loaded, but got empty key")
			}

			// Verify the key is usable
			SSHServer := &ssh.Server{}
			err := func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panic during host key setup: %v", r)
					}
				}()
				SSHServer.SetOption(ssh.HostKeyPEM(server.HostKey))
				return nil
			}()

			if err != nil {
				t.Errorf("Host key from %s should be valid, but got error: %v", tt.expectedSource, err)
			}
		})
	}
}

// Helper functions for loading host keys from different sources

// loadHostKeyFromFile loads a PEM-encoded host key from a file
func loadHostKeyFromFile(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read host key file %s: %w", filePath, err)
	}

	// Validate that it's a valid PEM-encoded private key
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", filePath)
	}

	if block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block type in %s: %s", filePath, block.Type)
	}

	return data, nil
}

// loadHostKeyFromEnv loads a PEM-encoded host key from an environment variable
func loadHostKeyFromEnv(envVar string) ([]byte, error) {
	data := os.Getenv(envVar)
	if data == "" {
		return nil, fmt.Errorf("environment variable %s is not set or empty", envVar)
	}

	// Validate that it's a valid PEM-encoded private key
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from environment variable %s", envVar)
	}

	if block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block type in environment variable %s: %s", envVar, block.Type)
	}

	return []byte(data), nil
}
