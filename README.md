-RSAPublicKey_out will generate the correct public key (if using openssl)

link with crypt32 and advapi32.

__mingw users__ will have to GetProcAddress()
This is annoying and has made me switch to VS for projects involving this file.

Wincrypt also uses litle endian where openssl(and the rest of the world?) uses big  

I hope this is of use to someone somewhere. I'm not sure why someone hasn't done this before.
