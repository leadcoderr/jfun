# Crypto

How to gen RSA keys:  
```shell
openssl genrsa -out private_key.pem 2048
```

File like this:  
```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAIB8dKKXK9ls/
LCGg9yuE/nTVvyXLvg71PyO/GkoCE4blIuevsOMhvKMCrvqu64rSxVOBBxolgMoS
fRUTj7rg9gdcG4CIAJdi1OKJsKRdQgTIG7kwB184PpQjbdOLfidu0tbSwuorKggn
yCfzwp0yKM0LXVg2b6q3mHPgE+4y/q/HXjLeQMV75Z9GNivOOf7XEk+rYZVT0NU2
rfsXKPS4uscYRlKRY9+T16SPCdlVQZp6l/SiJ3WfYJNt51bBYECPuHhi6Kj3/PH+
+eOzKVnyFMqvA1nBwJ9ICmbUvZXK2iziAAnFxcdFHEw8yOJyWesfnxEKb1f1qrjE
cJk2/oUXAgMBAAECggEATzoPypT0BYXg6+SVe4zhx+aspGY+Pk4CWhTu90Puh/uo
cX4a36MIjuV8rUMeAhsEtNUFkdwtZpC9A7HMCrSHInSiZVO8BZmE1A8o2hHbPc/X
K/PuwoUPuaBos1F7Xncn6LYOO3yAV0tucIVEIGu9Ki2UHJ8iHNSgqDQ4eIuPezw/
GDe5EvtArzld2zqCa2RyA5cfVa8AtKmArt24n8458Ikh0ejTlvmGIs8aP7AV13jM
GDhMggXAkpkj64VwQp9/AsJXlxUQRiBk2i/bcWOqymaYHuCpsoPraijPozNbYEmV
0ZHlFZbxql+MBdl0iiZWxCynrVTj3asKMNx+Hok11QKBgQDwp+htLJ0DncawFZ1w
xV0Oa4LD21mYcjOtRlxbQ5v+BVz+/bWHbMKZt2om/t9ikYNwNvE5lk5oQEd6iFnZ
YcfBw3neHum3knQJi1i6tVL4tLqnwJRDIZXGxkrEcNO7A+NU/vsgKxf61alEow6U
LhwG9xDxrtWA9EaiqQL3RIPSnQKBgQDMYBQkCww/TGeDG3gpodOqmj12bOvuZDlV
/Z+5uCN3OexK5m/Vdx2glfk0gONkJopBRdwBu2ZfQOSRL9em/FXV92ceOTW+MOdf
gagH/dws4mI5zZcIic5sQQLZQBfZBzUTrQwiROGSsn5x8K5cpk13AtE8n5NBLE1s
tfJ+nBAeQwKBgQDCP5WxQbh/KcQtb1UEqJnjQM5tDsmz7kJeE5QKqnjoQiX9QIZd
CGHPN6f8T++5nSDN29s8E2G4bmIDurljaLSXZxQgQS1/WjxFU+/LzP5q915Od3h0
80/1AStqgnO02X+OpL3JCl+xvPKDD2Z+HvXKfXR00B1PmFzHgMp/EhOhVQKBgDzR
zsyXGRLxOtCyaQUCqonXkrjeWyu7WbC0ZEcRfERr0VzMzLUa2I9Ecj/kp0bTjUs1
be56BVINbreiJCwGZcjh8ib1YX/y77flTsrqCg61ZAPNocehsvNWOXHLeA1W7r2n
PrgoBXTxd12TAWCDAQSMqxW+a0T22Sej0cFJ0iYfAoGAOpZj0SOVM2FCYcc6Gm+O
MgV1S2MxgJyAJ0rn2AeUHR1S2O4nC7xn2hVWWmPXshN9jP0GMxNUUUy+Qac1pQhB
4DiBjhCNywIc2F9LuhzCcJBcg46ZpH8yceZcyurHlOiIAfvb0Ir/m4bnqi7c/TlW
FQhB2eGZGRitRdmDh42pDAg=
-----END PRIVATE KEY-----
```

And then you can extract public key from private keys:  
```shell
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

We get the pub key:  
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCAfHSilyvZbPywhoPcr
hP501b8ly74O9T8jvxpKAhOG5SLnr7DjIbyjAq76ruuK0sVTgQcaJYDKEn0VE4+6
4PYHXBuAiACXYtTiibCkXUIEyBu5MAdfOD6UI23Ti34nbtLW0sLqKyoIJ8gn88Kd
MijNC11YNm+qt5hz4BPuMv6vx14y3kDFe+WfRjYrzjn+1xJPq2GVU9DVNq37Fyj0
uLrHGEZSkWPfk9ekjwnZVUGaepf0oid1n2CTbedWwWBAj7h4Yuio9/zx/vnjsylZ
8hTKrwNZwcCfSApm1L2Vytos4gAJxcXHRRxMPMjiclnrH58RCm9X9aq4xHCZNv6F
FwIDAQAB
-----END PUBLIC KEY-----
```

So, how should it be done in Java code:
```java

```

## How to gen SSL cert ?

Gen cert request file  
```shell
openssl req -new -key private_key.pem -out csr.pem
```

Request file  
```
-----BEGIN CERTIFICATE REQUEST-----
MIIDBDCCAewCAQAwgYoxCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAlHdWFuZ2Rvbmcx
EjAQBgNVBAcMCUd1YW5nemhvdTEPMA0GA1UECgwGY2hldmlwMQswCQYDVQQLDAJJ
VDEPMA0GA1UEAwwGRGVyZWNrMSQwIgYJKoZIhvcNAQkBFhVkZXJlY2tsZWVtakBn
bWFpbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAIB8dKKXK
9ls/LCGg9yuE/nTVvyXLvg71PyO/GkoCE4blIuevsOMhvKMCrvqu64rSxVOBBxol
gMoSfRUTj7rg9gdcG4CIAJdi1OKJsKRdQgTIG7kwB184PpQjbdOLfidu0tbSwuor
KggnyCfzwp0yKM0LXVg2b6q3mHPgE+4y/q/HXjLeQMV75Z9GNivOOf7XEk+rYZVT
0NU2rfsXKPS4uscYRlKRY9+T16SPCdlVQZp6l/SiJ3WfYJNt51bBYECPuHhi6Kj3
/PH++eOzKVnyFMqvA1nBwJ9ICmbUvZXK2iziAAnFxcdFHEw8yOJyWesfnxEKb1f1
qrjEcJk2/oUXAgMBAAGgNDAVBgkqhkiG9w0BCQcxCAwGMTIzNDU2MBsGCSqGSIb3
DQEJAjEODAxpby5kZXJlY2tsZWUwDQYJKoZIhvcNAQELBQADggEBADzQB69+dQfM
C0tSYjSzA8PnJLkapbVPL3cSOEU2jXCgOzXKLnSQIFchXqo1f6OJDaxCSXkS7VaG
I2YBlXRp6VGepKkyC5bq8fkxGt03Yh9+nTfI5jvnKjMJww3Ffxvna6mTiiKz8y++
3Wj4w8+Un5fbnJoc1EOJRK4pdBrmJL9Gf5tEK87gD+SPNEQ+kj6rkduDX0yYJYsF
g31NmVD2gtHCcLXBb4on8nBAo7AQ8t/gdcYqiBrGz4zcLFBd2zw1Kd1GsvK0J//l
toWXeqges9CistGcIR7dmnJBPnLwCLTobYXZ8BECbYmyNowoT6+QqKRU0P+Kms3A
yRz08Y7Dhpw=
-----END CERTIFICATE REQUEST-----
```


```shell

openssl x509 -req -days 365 -in csr.pem -signkey private_key.pem -out certificate.pem
```