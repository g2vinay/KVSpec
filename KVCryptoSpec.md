## __CryptographyClient__

~~~ java
public class CryptographyClient extends ServiceClient
{
    // methods - async
    public Mono<EncryptResult> encryptAsync(EncryptionAlgorithm algorithm, byte[] plaintext);
    public Mono<EncryptResult> encryptAsync(EncryptionAlgorithm algorithm, InputStream plaintext);
    public Mono<EncryptResult> encryptAsync(EncryptionAlgorithm algorithm, byte[] plaintext, byte[] iv, byte[] authenticationData);
    public Mono<EncryptResult> encryptAsync(EncryptionAlgorithm algorithm, InputStream plaintext, byte[] iv, byte[] authenticationData);
    
    public Mono<byte[]> decryptAsync(EncryptionAlgorithm algorithm, byte[] cipherText);
    public Mono<byte[]> decryptAsync(EncryptionAlgorithm algorithm, InputStream cipherText);
    public Mono<byte[]> decryptAsync(EncryptionAlgorithm algorithm, byte[] cipherText, byte[] iv, byte[] authenticationData);
    public Mono<byte[]> decryptAsync(EncryptionAlgorithm algorithm, InputStream cipherText, byte[] iv, byte[] authenticationData);
    
    public Mono<SignResult> signAsync(SignatureAlgorithm algorithm, byte[] digest);

    public Mono<Boolean> verifyAsync(SignatureAlgorithm algorithm, byte[] digest, byte[] signature);
    
    public Mono<KeyWrapResult> wrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] key);
    
    public Mono<byte[]> unwrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] encryptedKey);
    

    public Mono<SignResult> signDataAsync(SignatureAlgorithm algorithm, byte[] data);
    public Mono<SignResult> signDataAsync(SignatureAlgorithm algorithm, InputStream data);
    
    public Mono<Boolean> verifyDataAsync(SignatureAlgorithm algorithm, byte[] data, byte[] signature);
    public Mono<Boolean> verifyDataAsync(SignatureAlgorithm algorithm, InputStream data, byte[] signature);
    
    
    
    // methods - sync
    public EncryptResult encrypt(EncryptionAlgorithm algorithm, byte[] plaintext);
    public EncryptResult encrypt(EncryptionAlgorithm algorithm, InputStream plaintext);
    public EncryptResult encrypt(EncryptionAlgorithm algorithm, byte[] plaintext, byte[] iv, byte[] authenticationData);
    public EncryptResult encrypt(EncryptionAlgorithm algorithm, InputStream plaintext, byte[] iv, byte[] authenticationData);
   
    public byte[] decrypt(EncryptionAlgorithm algorithm, byte[] cipherText);
    public byte[] decrypt(EncryptionAlgorithm algorithm, InputStream cipherText);
    public byte[] decrypt(EncryptionAlgorithm algorithm, byte[] cipherText, byte[] iv, byte[] authenticationData);
    public byte[] decrypt(EncryptionAlgorithm algorithm, InputStream cipherText, byte[] iv, byte[] authenticationData);
    
    public SignResult sign(SignatureAlgorithm algorithm, byte[] digest);
    
    public Boolean verify(SignatureAlgorithm algorithm, byte[] digest, byte[] signature);
    
    public KeyWrapResult wrapKey(KeyWrapAlgorithm algorithm, byte[] key);
    
    public byte[] unwrapKey(KeyWrapAlgorithm algorithm, byte[] encryptedKey);
    
    public SignResult signData(SignatureAlgorithm algorithm, byte[] data);
    public SignResult signDataAsync(SignatureAlgorithm algorithm, InputStream data);

    public Boolean verifyData(SignatureAlgorithm algorithm, byte[] data, byte[] signature);
    public Boolean verifyData(SignatureAlgorithm algorithm, InputStream data, byte[] signature);
   
}

~~~

### DataStructures
~~~ java
public enum EncryptionAlgorithm {

    RSA_OAEP("RSA-OAEP"),
    RSA_OAEP_256("RSA-OAEP-256"),
    RSA1_5("RSA1_5");
}

public enum KeyWrapAlgorithm {

    RSA_OAEP("RSA-OAEP"),
    RSA_OAEP_256("RSA-OAEP-256"),
    RSA1_5("RSA1_5");
}

public enum SignatureAlgorithm {

    PS256 ("PS256"), 
    PS384("PS384"), 
    PS512("PS512"), 
    RS256("RS256"),
    RS384("RS384"),
    RS512("RS512"),
    RSNULL("RSNULL"),
    ES256("ES256"),
    ES384 ("ES384"),
    ES512("ES512"),
    ES256K("ES256K");
}

/**
 * Represents the details of sign operation result.
 */
public class SignResult {

    /**
     * The signature created from the digest.
     */
    private byte[] signature;

    /**
     * The algorithm used to create the signature.
     */
    private SignatureAlgorithm algorithm;

    /**
     * Get the signature created from the digest.
     * @return The signature.
     */
    public byte[] signature() {
        return signature;
    }

    public SignResult signature(byte[] signature) {
        this.signature = signature;
        return this;
    }

    /**
     * Get the signature algorithm used to create the signature.
     * @return The signature algorithm.
     */
    public SignatureAlgorithm algorithm() {
        return algorithm;
    }

    public SignResult algorithm(SignatureAlgorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }
}

/**
 * Represents the details of encryption operation result.
 */
public class EncryptResult {

    /**
     * THe encrypted content.
     */
    private byte[] cipherText;

    /**
     * The authentication tag.
     */
    private byte[] authenticationTag;

    /**
     * The encrypyion algorithm used for the encryption operation.
     */
    private EncryptionAlgorithm algorithm;


    /**
     * Get the encrypted content.
     * @return The encrypted content.
     */
    public byte[] cipherText() {
        return cipherText;
    }

    public EncryptResult cipherText(byte[] cipherText) {
        this.cipherText = cipherText;
        return this;
    }

    /**
     * Get the authentication tag.
     * @return The authentication tag.
     */
    public byte[] authenticationTag() {
        return authenticationTag;
    }

    public EncryptResult authenticationTag(byte[] authenticationTag) {
        this.authenticationTag = authenticationTag;
        return this;
    }

    /**
     * Get the encryption algorithm used for encryption.
     * @return The encryption algorithm used.
     */
    public EncryptionAlgorithm algorithm() {
        return algorithm;
    }

    public EncryptResult algorithm(EncryptionAlgorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }
}


/**
 * Represents the details of wrap operation result.
 */
public class KeyWrapResult {

    /**
     * The encrypted key content
     */
    private byte[] encryptedKey;

    /**
     * The key wrap algorithm used to wrap the key content.
     */
    private KeyWrapAlgorithm algorithm;

    /**
     * Get the encrypted key content.
     * @return The encrypted key.
     */
    public byte[] encryptedKey() {
        return encryptedKey;
    }

    public KeyWrapResult encryptedKey(byte[] encryptedKey) {
        this.encryptedKey = encryptedKey;
        return this;
    }

    /**
     * Get the key wrap algorithm used to wrap the key content.
     * @return The key wrap algorithm.
     */
    public KeyWrapAlgorithm algorithm() {
        return algorithm;
    }

    public KeyWrapResult algorithm(KeyWrapAlgorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }
}

~~~

## Scenarios - Sync API

### 1. Sign And Verify
```java
CryptographyClient cryptoClient = new CryptographyClientBuilder("<MY-KEY>")
    .credentials(new DefaultAzureCredential())
    .buildClient();
                            
byte[] plainText = new byte[100];
new Random(0x1234567L).nextBytes(plainText);
MessageDigest md = MessageDigest.getInstance("SHA-256");
md.update(plainText);
byte[] digest = md.digest();

byte[] signature = cryptoClient.sign(SignatureAlgorithm.RS256, digest).signature();
boolean verifyStatus = cryptoClient.verify(SignatureAlgorithm.RS256, digest, signature);

```

### 2. Encrypt And Decrypt
```java
CryptographyClient cryptoClient = new CryptographyClientBuilder("<MY-KEY>")
    .credentials(new DefaultAzureCredential())
    .buildClient();
                            
byte[] plainText = new byte[100];
new Random(0x1234567L).nextBytes(plainText);


// Encrypt in the service.
byte[] cipherText =  cryptoClient.encrypt(EncryptionAlgorithm.RSA_OAEP, plainText).cipherText();

byte[] decryptedText =  cryptoClient.decrypt(EncryptionAlgorithm.RSA_OAEP, cipherText);

```

### 2. Wrap And Unwrap
```java
CryptographyClient cryptoClient = new CryptographyClientBuilder("<MY-KEY>")
    .credentials(new DefaultAzureCredential())
    .buildClient();
                            
byte[] plainText = new byte[100];
new Random(0x1234567L).nextBytes(plainText);

// wrap and unwrap using kid WO version
byte[] encryptedkey = cryptoClient.wrapKey(KeyWrapAlgorithm.RSA_OAEP, plainText).encryptedKey();

byte[] unwrappedKey = cryptoClient.unwrapKey(KeyWrapAlgorithm.RSA_OAEP, encryptedkey);
```




