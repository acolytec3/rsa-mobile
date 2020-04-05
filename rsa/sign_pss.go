package rsa
	"encoding/base64"
	"io"
import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"github.com/keybase/go-crypto/rsa"
)

func (r *FastRSA) SignPSSBytes(message []byte, hashName, saltLengthName, privateKey string) ([]byte, error) {

	private, err := r.readPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	hash := getHashInstance(hashName)
	_, err = hash.Write(message)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPSS(rand.Reader, private, getHashType(hashName), hash.Sum(nil), &rsa.PSSOptions{
		SaltLength: getSaltLength(saltLengthName),
		Hash:       getHashType(hashName),
	})
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (r *FastRSA) SignPSSString(message, hashName, saltLengthName, privateKey string) (string, error) {

	private, err := r.readPrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	hash := getHashInstance(hashName)
	_, err = io.WriteString(hash, message)
	if err != nil {
		return "", err
	}

	signature, err := rsa.SignPSS(rand.Reader, private, getHashType(hashName), hash.Sum(nil), &rsa.PSSOptions{
		SaltLength: getSaltLength(saltLengthName),
		Hash:       getHashType(hashName),
	})
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}