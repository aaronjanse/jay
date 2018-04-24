package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"path"
	"strconv"
	"strings"

	"github.com/urfave/cli"
)

type encryptedEntry struct {
	key     []byte
	message []byte
}

const encryptedAesKeyLength = 512
const compress = true

func handleReadAction(c *cli.Context) error {
	// Get private key
	rsaPrivateKey := readPrivateKey()

	// Get ciphertext
	ciphertext, err := ioutil.ReadFile(path.Join(jayPath, "jrnl.gpg"))
	check(err)

	encryptedEntries := make([]encryptedEntry, 0)

	r := bytes.NewReader(ciphertext)
	for {
		encryptedKey := make([]byte, encryptedAesKeyLength)
		_, err := r.Read(encryptedKey)
		if err != nil && err.Error() == "EOF" {
			break
		}
		check(err)

		lenBytes := make([]byte, 4)
		_, err = r.Read(lenBytes)
		check(err)
		messageLength := binary.LittleEndian.Uint32(lenBytes)

		encryptedMessage := make([]byte, messageLength)
		_, err = r.Read(encryptedMessage)
		check(err)

		encryptedEntries = append(encryptedEntries, encryptedEntry{encryptedKey, encryptedMessage})
	}

	var decryptedEntries []string
	for _, encEntry := range encryptedEntries {
		aesKeySlice, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, encEntry.key, []byte{})
		check(err)

		aesKey := [32]byte{}
		copy(aesKey[:], aesKeySlice)

		entryBytes, err := aesDecrypt(encEntry.message, &aesKey)
		check(err)
		compressed := entryBytes[0] != 0
		entryBytes = entryBytes[1:]
		if compressed {
			r := bytes.NewReader(entryBytes)
			for {
				lenBytes := make([]byte, 4)
				_, err = r.Read(lenBytes)
				check(err)
				entryLength := binary.LittleEndian.Uint32(lenBytes)
				if entryLength == 0 { // WARNING: does not allow for empty entries
					break
				}
				entryContent := make([]byte, entryLength)
				_, err = r.Read(entryContent)
				check(err)
				decryptedEntries = append(decryptedEntries, string(entryContent))
			}
		} else {
			decryptedEntries = append(decryptedEntries, string(entryBytes))
		}
	}

	fmt.Println(strings.Join(decryptedEntries, "\n"))

	if compress {
		// wipe existing entries from disk
		err := ioutil.WriteFile(path.Join(jayPath, "jrnl.gpg"), []byte{}, 006)
		check(err)

		// re-encrypt entries all under the same key since AES is much faster than RSA
		var compressedEntry = make([]byte, 0)
		for _, entry := range decryptedEntries {
			lenBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(lenBytes, uint32(len(entry)))
			compressedEntry = append(compressedEntry, lenBytes...)

			compressedEntry = append(compressedEntry, []byte(entry)...)
		}
		// fmt.Println(decryptedEntries)
		lenBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBytes, 0)
		compressedEntry = append(compressedEntry, lenBytes...)

		addEntry(string(compressedEntry), true)
	}

	return nil
}

func readPrivateKey() *rsa.PrivateKey {
	block := readPEM(path.Join(jayPath, "private.pem"))

	passphrase := promptPassphrase()
	blockBytes, err := x509.DecryptPEMBlock(block, getKey(passphrase))
	check(err)

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(blockBytes)
	check(err)

	return rsaPrivateKey
}

func getTimesamp(str string) (int, error) {
	return strconv.Atoi(strings.Split(str, "\n")[0])
}
