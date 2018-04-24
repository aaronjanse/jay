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
	"time"

	"github.com/urfave/cli"
)

type encryptedEntry struct {
	key     []byte
	message []byte
}

type entry struct {
	timestamp uint64
	message   string
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

	var decryptedEntries []entry
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
				timestamp := binary.LittleEndian.Uint64(entryContent[:8])
				message := string(entryContent[8:])
				decryptedEntries = append(decryptedEntries, entry{timestamp, message})
			}
		} else {
			timestamp := binary.LittleEndian.Uint64(entryBytes[:8])
			message := string(entryBytes[8:])
			decryptedEntries = append(decryptedEntries, entry{timestamp, message})
		}
	}

	for _, entry := range decryptedEntries {
		timestamp := time.Unix(int64(entry.timestamp), 0)
		check(err)
		fmt.Println(timestamp.Format("2006-01-02 at 15:04:05"))
		fmt.Println(entry.message)
	}

	// fmt.Println(strings.Join(decryptedEntries, "\n"))

	if compress {
		// wipe existing entries from disk
		err := ioutil.WriteFile(path.Join(jayPath, "jrnl.gpg"), []byte{}, 006)
		check(err)

		// re-encrypt entries all under the same key since AES is much faster than RSA
		var compressedEntry = make([]byte, 0)
		for _, entry := range decryptedEntries {
			lenBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(lenBytes, uint32(8+len(entry.message)))
			compressedEntry = append(compressedEntry, lenBytes...)

			timestampBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(timestampBytes, entry.timestamp)
			compressedEntry = append(compressedEntry, timestampBytes...)

			compressedEntry = append(compressedEntry, []byte(entry.message)...)
		}
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
