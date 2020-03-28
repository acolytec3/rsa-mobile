package rsa

import "testing"

func TestFastRSA_DecryptOAEP(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.DecryptOAEP(ciphertext_oaep, "", "sha256", privateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
