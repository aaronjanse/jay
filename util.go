package main

import (
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/howeyc/gopass"
	"golang.org/x/crypto/pbkdf2"
)

func promptPassphrase() []byte {
	fmt.Print("Passphrase: ")
	pass, err := gopass.GetPasswd()
	check(err)
	return pass
}

var salt = []byte("salt here")

func getKey(passphrase []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha256.New)
}

func readPEM(path string) *pem.Block {
	keyBytes, err := ioutil.ReadFile(path)
	check(err)

	block, _ := pem.Decode(keyBytes)
	return block
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
