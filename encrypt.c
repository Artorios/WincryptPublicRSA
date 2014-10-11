/*
Copyright (c) 2014 Ryan Bossman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/


const char* PublicKey = 
    "-----BEGIN RSA PUBLIC KEY-----"
    "x"
    "-----END RSA PUBLIC KEY-----";

void PubRSAEncrypt(char *str)
{
    int BuffLen = 0, cbKeyBlob = 0, dwKeySize = 0, i = 0, dwParamSize = sizeof(int);
    char *Buff = NULL, *pbKeyBlob = NULL, c = 0, enc[4096] = {0};

    HCRYPTPROV hProv;
    HCRYPTKEY hKey;


    StringCbCopy(enc, 4096, str);


    if (!CryptStringToBinaryA(PublicKey, 0, 0, NULL, &BuffLen, NULL, NULL))
    {
        goto error;
    }

    Buff = calloc(1, BuffLen);

    if (!CryptStringToBinaryA(PublicKey, 0, 0, Buff, &BuffLen, NULL, NULL))
    {
        goto error;
    }

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, Buff, BuffLen, 0, NULL, NULL, &cbKeyBlob))
    {
        goto error;
    }   

    pbKeyBlob = calloc(1, cbKeyBlob);

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, Buff, BuffLen, 0, NULL, pbKeyBlob, &cbKeyBlob))
    {
        goto error;
    }

    if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        goto error;
    }

    if (!CryptImportKey(hProv, pbKeyBlob, cbKeyBlob, (HCRYPTKEY)NULL, 0, &hKey))
    {
        goto error;
    }

    if (!CryptGetKeyParam(hKey, KP_KEYLEN, (BYTE*) &dwKeySize, &dwParamSize, 0))
    {
        goto error;
    }
    
    dwKeySize /= 8; 
    BuffLen = strlen(enc) * sizeof(char);

    if(!CryptEncrypt( hKey, 0, TRUE, 0 , enc, &BuffLen, sizeof(enc)))
    {
        goto error;
    }


    for (i = 0; i < (dwKeySize / 2); i++) //endianness; we are now compatible with openssl
    {
        c = enc[i];
        enc[i] = enc[dwKeySize - 1 - i];
        enc[dwKeySize - 1 - i] = c;
    }


    printf("enc[] now containes encrypted data converted to the correct endianness\n");


error:
    if (Buff) free(Buff);
    if (pbKeyBlob) free(pbKeyBlob);
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
    return NULL;
}