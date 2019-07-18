## __KeyAsyncClient__

### Possible Upgrades/Changes:
Track 1 supports passing in keyId to the API and it works cross vaults.
Track 2 clients are tied to vaults.
So, there is a possibility of a new 'KeyCryptographyClient' which will support passing in KeyId to the API.

~~~ java
public class KeyAsyncClient extends ServiceClient
{
    // methods 
    
    public Mono<Response<byte[]>> sign(String name, KeySignatureAlgorithm signatureAlgorithm, byte[] value);
    public Mono<Response<byte[]>> sign(KeyBase key, KeySignatureAlgorithm signatureAlgorithm, byte[] value);
    public Mono<Response<Boolean>> verify(String name, KeySignatureAlgorithm signatureAlgorithm, byte[] digest, byte[] signature);
    public Mono<Response<Boolean>> verify(KeyBase key, KeySignatureAlgorithm signatureAlgorithm, byte[] digest, byte[] signature);
    
    public Mono<Response<byte[]>> wrapKey(String name, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
    public Mono<Response<byte[]>> wrapKey(KeyBase key, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
    public Mono<Response<byte[]>> unwrapKey(String name, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
    public Mono<Response<byte[]>> unwrapKey(KeyBase key, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);

    public Mono<Response<byte[]>> encrypt(String name, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
    public Mono<Response<byte[]>> encrypt(KeyBase key, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
    public Mono<Response<byte[]>> decrypt(String name, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
    public Mono<Response<byte[]>> decrypt(KeyBase key, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
}

~~~

## __KeyClient__
~~~ java
public class KeyClient extends ServiceClient
{
    // methods
    public Response<byte[]> sign(String name, KeySignatureAlgorithm signatureAlgorithm, byte[] value);
    public Response<byte[]> sign(KeyBase key, KeySignatureAlgorithm signatureAlgorithm, byte[] value);
    public Response<Boolean> verify(String name, KeySignatureAlgorithm signatureAlgorithm, byte[] digest, byte[] signature);
    public Response<Boolean> verify(KeyBase key, KeySignatureAlgorithm signatureAlgorithm, byte[] digest, byte[] signature);
    
    public Response<byte[]> wrapKey(String name, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
    public Response<byte[]> wrapKey(KeyBase key, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
    public Response<byte[]> unwrapKey(String name, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
    public Response<byte[]> unwrapKey(KeyBase key, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);

    public Response<byte[]> encrypt(String name, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
    public Response<byte[]> encrypt(KeyBase key, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
    public Response<byte[]> decrypt(String name, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
    public Response<byte[]> decrypt(KeyBase key, KeyEncryptionAlgorithm encryptionAlgorithm, byte[] value);
    
}



~~~

## Scenarios - Sync API

### 1. Sign And Verify
```java
KeyClient keyClient = KeyClient.builder()
    .endpoint("https://myvault.vault.azure.net/")
    .credentials(new DefaultAzureCredential())
    .build();
                            
byte[] plainText = new byte[100];
new Random(0x1234567L).nextBytes(plainText);
MessageDigest md = MessageDigest.getInstance("SHA-256");
md.update(plainText);
byte[] digest = md.digest();

Key myKey = keyClient.getKey("myKey", "SDFSDFJ23948234SD");

byte[] signature = keyClient.sign(myKey, KeySignatureAlgorithm.RS256, digest).value().value();
boolean verifyStatus = keyClient.verify(myKey, KeySignatureAlgorithm.RS256, signature, digest).value();

```

### 2. Encrypt And Decrypt
```java
KeyClient keyClient = KeyClient.builder()
    .endpoint("https://myvault.vault.azure.net/")
    .credentials(new DefaultAzureCredential())
    .build();
                            
byte[] plainText = new byte[100];
new Random(0x1234567L).nextBytes(plainText);


// Encrypt in the service.
byte[] cipherText =  keyClient.encrypt("myKey", KeyEncryptionAlgorithm.RSA_OAEP, plainText).value();
cipherText = result.result();

byte[] decryptedText =  keyClient.decrypt("myKey", KeyEncryptionAlgorithm.RSA_OAEP, cipherText).value();

```

### 2. Wrap And Unwrap
```java
KeyClient keyClient = KeyClient.builder()
    .endpoint("https://myvault.vault.azure.net/")
    .credentials(new DefaultAzureCredential())
    .build();
                            
byte[] plainText = new byte[100];
new Random(0x1234567L).nextBytes(plainText);

// wrap and unwrap using kid WO version
byte[] cipherText = keyClient.wrapKey("myKey", KeyEncryptionAlgorithm.RSA_OAEP, plainText).value();

byte[] unwrappedText = keyClient.unwrapKey("myKey", KeyEncryptionAlgorithm.RSA_OAEP, cipherText).value();
```




