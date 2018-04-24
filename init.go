package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"github.com/urfave/cli"
)

func handleInitAction(c *cli.Context) error {
	jayPathExists, err := exists(jayPath)
	check(err)
	if !jayPathExists {
		err := os.Mkdir(jayPath, 0777)
		check(err)
	} else {
		fmt.Println("This will overwrite all existing Jat keys and entires")
		confirmed := askForConfirmation("Are you sure you want to continue?")

		if !confirmed {
			return nil
		}
	}

	err = ioutil.WriteFile(path.Join(jayPath, "jrnl.gpg"), []byte{}, 006)
	check(err)

	passphrase := promptPassphrase() // prompt user before (slow) key generation

	fmt.Println("Generating key...")
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	check(err)

	fmt.Println("Saving...")
	savePrivateKey(rsaPrivKey, passphrase)
	savePublicKey(&rsaPrivKey.PublicKey)

	fmt.Println("Done")
	return nil
}

func savePublicKey(key *rsa.PublicKey) {
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(key),
	}

	pemBytes := pem.EncodeToMemory(block)
	err := ioutil.WriteFile(path.Join(jayPath, "public.pem"), pemBytes, 0644)
	check(err)
}

func savePrivateKey(key *rsa.PrivateKey, passphrase []byte) {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	block, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, getKey(passphrase), x509.PEMCipherAES256)
	check(err)

	pemBytes := pem.EncodeToMemory(block)
	err = ioutil.WriteFile(path.Join(jayPath, "private.pem"), pemBytes, 0644)
	check(err)
}

// from https://gist.github.com/r0l1/3dcbb0c8f6cfe9c66ab8008f55f8f28b
func askForConfirmation(s string) bool {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("%s [y/n]: ", s)

		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			return true
		} else if response == "n" || response == "no" {
			return false
		}
	}
}
