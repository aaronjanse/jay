package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"os"
	"path"

	"github.com/urfave/cli"
)

func handleAddAction(c *cli.Context) error {
	// Get entry text
	var text string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		text += scanner.Text() + "\n"
	}

	addEntry(text, false)
	return nil
}

func addEntry(text string, compressed bool) {
	rsaPublicKey := readPublicKey()

	f, err := os.OpenFile(path.Join(jayPath, "jrnl.gpg"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 006)
	check(err)
	defer f.Close()

	aesKey := newEncryptionKey()

	encryptedAesKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, aesKey[:], []byte{})
	f.Write(encryptedAesKey)

	plaintextBytes := []byte(text)
	plaintextBytes = append(plaintextBytes, 0)
	copy(plaintextBytes[1:], plaintextBytes)
	if compressed {
		plaintextBytes[0] = 1
	} else {
		plaintextBytes[0] = 0
	}

	encryptedEntry, err := aesEncrypt(plaintextBytes, aesKey)
	check(err)
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(len(encryptedEntry)))
	f.Write(lenBytes)
	f.Write(encryptedEntry)
}

func readPublicKey() *rsa.PublicKey {
	block := readPEM(path.Join(jayPath, "public.pem"))

	rsaPublicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	check(err)

	return rsaPublicKey
}