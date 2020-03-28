package rsa

import (
	"encoding/json"
	"errors"
	"testing"
)

var publicKey = "-----BEGIN PUBLIC KEY-----\nMIICCgKCAgEAt2Aa+/XFJMmAVu7dG5GoOvms9ADziMRgtnGN3Rbejk23sxS4nyOI\nngwTtP1tp5pRH8pfOmYNh2YuqK5seYlVbPJOvjrsk+tPirEMGIVsMF6Qg4J44ubs\nH00zAFAQ45Sjg6v2RczFIyU0N+tY20IE5+AHSxmydC+b3mvsBM2fYWOO4FbxGwov\n+SLp2M+oNdjvD2SKn+fufVbSSqVvZtBWjfUEcsDNfrDy1Ue8G8+gcUw+VvDmW6eP\nqFym2cod6DlqSOEsE1D8eUv+mPzKbnutp4n6/n4dnKQwByusH2+IQknLSEimadrD\nOtpLVB0KmmScAD7BclPVlC+F2V9555UIIh026HBmRHD3316TidfQnrd4ZXhAnsiC\nI259Dz+WPTq2wtYrjbCkbcyvgQ3Xztq9dfQZGbAx/2lKwTO3DBbvnaK9ZMIvulHr\nX9fKwyg5wtXtYjfXok85Zeanzj2GTZL/mpf+xXMrPRwwhA40FL1VK2+hMwhLRh92\nD3u+qGNr5pUHYGvAxnEuLppbSL7ehnkWiKou6IjQWKZARyHeuvZQYUie9wN9EzJY\n9Ex/udwSTSFiOIgriB7zimg8aLnmeSqRhqhbyPsIvGzigJV3f+wXTiXmQsWUYadK\nfhOihgwuMqqIkzxgqPmd75xqFcFf+avWCzKtW5Nc/UNsK9g+YAvRIT8CAwEAAQ==\n-----END PUBLIC KEY-----\n"
var privateKey = "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n"
var certificate = "-----BEGIN CERTIFICATE-----\nMIIFhDCCA2wCCQDN50se7x+gRDANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMC\nUEUxDzANBgNVBAgMBnNhbXBsZTEPMA0GA1UEBwwGc2FtcGxlMQ8wDQYDVQQKDAZz\nYW1wbGUxDjAMBgNVBAsMBXNhbXBsMQ8wDQYDVQQDDAZzYW1wbGUxIDAeBgkqhkiG\n9w0BCQEWEXNhbXBsZUBzYW1wbGUuY29tMB4XDTE5MTAyODE0NDAyNFoXDTIwMTAy\nNzE0NDAyNFowgYMxCzAJBgNVBAYTAlBFMQ8wDQYDVQQIDAZzYW1wbGUxDzANBgNV\nBAcMBnNhbXBsZTEPMA0GA1UECgwGc2FtcGxlMQ4wDAYDVQQLDAVzYW1wbDEPMA0G\nA1UEAwwGc2FtcGxlMSAwHgYJKoZIhvcNAQkBFhFzYW1wbGVAc2FtcGxlLmNvbTCC\nAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALdgGvv1xSTJgFbu3RuRqDr5\nrPQA84jEYLZxjd0W3o5Nt7MUuJ8jiJ4ME7T9baeaUR/KXzpmDYdmLqiubHmJVWzy\nTr467JPrT4qxDBiFbDBekIOCeOLm7B9NMwBQEOOUo4Or9kXMxSMlNDfrWNtCBOfg\nB0sZsnQvm95r7ATNn2FjjuBW8RsKL/ki6djPqDXY7w9kip/n7n1W0kqlb2bQVo31\nBHLAzX6w8tVHvBvPoHFMPlbw5lunj6hcptnKHeg5akjhLBNQ/HlL/pj8ym57raeJ\n+v5+HZykMAcrrB9viEJJy0hIpmnawzraS1QdCppknAA+wXJT1ZQvhdlfeeeVCCId\nNuhwZkRw999ek4nX0J63eGV4QJ7IgiNufQ8/lj06tsLWK42wpG3Mr4EN187avXX0\nGRmwMf9pSsEztwwW752ivWTCL7pR61/XysMoOcLV7WI316JPOWXmp849hk2S/5qX\n/sVzKz0cMIQONBS9VStvoTMIS0Yfdg97vqhja+aVB2BrwMZxLi6aW0i+3oZ5Foiq\nLuiI0FimQEch3rr2UGFInvcDfRMyWPRMf7ncEk0hYjiIK4ge84poPGi55nkqkYao\nW8j7CLxs4oCVd3/sF04l5kLFlGGnSn4TooYMLjKqiJM8YKj5ne+cahXBX/mr1gsy\nrVuTXP1DbCvYPmAL0SE/AgMBAAEwDQYJKoZIhvcNAQELBQADggIBAGinKrqx0VqC\nB1WFaJkZFcdoxrpv7V5ISbDTabOUQ2NeYHRiHfRFfu/1T5PDo0sicWae6Fq89IZF\ndZzTLe3ieOHqmNGGhPUgZIT7t+RUYvOlR1YMGXAPj4X7nJffjwOe6b8sXw3wsqSp\n+ZYJ3H/4K26led/sFx+h7B36BuW8suVPmPYnvz53Og9GG+y8ndhmPpAYoThFO3pr\n3qngySLsFITCJ51pmAtHM+v3vJgvg/ypFbbD4yVW2XkOu+8YCg93cpa3GPgmJ5ON\nIgAtrdOrhwBOM8YANePuGbln1yTKTcgwYm7fdbBZ8Gpm6+FlglK97R/duTR6yJnc\nEGr3S815l+LUHlmgzJLWfFPHA2IZKu7KWCASA3mVMhLofoXnSzitf1qXgWEmYc/L\nxTg/jaap9zG+Wjl8lxLe/QgisibVRYM8o1a6GCI3HIPEbUCmKGEt2rzqKyBuFrWA\nBOkgsG2+lxG9eZ1FtRoZ2v2zoQtuxhwrekd+ciQ1W/EIjyZfFxMO2v7ppkIxcac/\nhP19r+5IgwMO2vc91mqSxNZ8t1j8qTodAj2T5lmDKeyBrjSJFNcj04GrEzcdv7sL\nFkwuyTBQpYJGurqXP3rp/e/S4ZGxrC1qY2mWPRtJ+VtPFqunRTPEiPlTaxUVebEY\n0rcM3Y90ulmTAYJaZGJy3DbZw+hu6oCs\n-----END CERTIFICATE-----\n"

func TestFastRSA_ConvertKeyPairToPKCS12(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.ConvertKeyPairToPKCS12(privateKey, publicKey, certificate, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_ConvertKeyPairToPKCS12Complete(t *testing.T) {
	instance := NewFastRSA()
	pkcs12, err := instance.ConvertKeyPairToPKCS12(privateKey, publicKey, certificate, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	output, err := instance.ConvertPKCS12ToKeyPair(pkcs12, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	if output.PublicKey != publicKey {
		t.Fatal(errors.New("should be equal"))
	}
	if output.PrivateKey != privateKey {
		t.Fatal(errors.New("should be equal"))
	}
	if output.Certificate != certificate {
		t.Fatal(errors.New("should be equal"))
	}

	encoded, _ := json.MarshalIndent(output, "", " ")
	t.Log("output:", string(encoded))
}
