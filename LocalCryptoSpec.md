## __CryptographyClient__

~~~ java
public class LocalCryptographyAsyncClient {

    public Mono<EncryptResult> encrypt(EncryptionAlgorithm algorithm, byte[] plaintext);
    public Mono<DecryptResult> decrypt(EncryptionAlgorithm algorithm, byte[] cipherText);
  
    // Do we want to support these for Symmmetric keys ? now that we have a local only client 
    public Mono<EncryptResult> encrypt(EncryptionAlgorithm algorithm, byte[] plaintext, byte[] iv, byte[] authenticationData);
    public Mono<DecryptResult> decrypt(EncryptionAlgorithm algorithm, byte[] cipherText, byte[] iv, byte[] authenticationData, byte[] authenticationTag);
    

    public Mono<SignResult> sign(SignatureAlgorithm algorithm, byte[] digest);
    public Mono<VerifyResult> verify(SignatureAlgorithm algorithm, byte[] digest, byte[] signature);
    
    public Mono<WrapResult> wrapKey(KeyWrapAlgorithm algorithm, byte[] key);
    public Mono<UnwrapResult> unwrapKey(KeyWrapAlgorithm algorithm, byte[] encryptedKey);
    

    public Mono<SignResult> signData(SignatureAlgorithm algorithm, byte[] data);
    public Mono<SignResult> signData(SignatureAlgorithm algorithm, InputStream data);
    
    public Mono<VerifyResult> verifyData(SignatureAlgorithm algorithm, byte[] data, byte[] signature);
    public Mono<VerifyResult> verifyData(SignatureAlgorithm algorithm, InputStream data, byte[] signature);
   
}

public class LocalCryptographyClient {
    
    // methods - sync
    public EncryptResult encrypt(EncryptionAlgorithm algorithm, byte[] plaintext);
    public DecryptResult decrypt(EncryptionAlgorithm algorithm, byte[] cipherText);

    // Do we want to support these for Symmmetric keys ? now that we have a local only client 
    public EncryptResult encrypt(EncryptionAlgorithm algorithm, byte[] plaintext, byte[] iv, byte[] authenticationData);
    public DecryptResult decrypt(EncryptionAlgorithm algorithm, byte[] cipherText, byte[] iv, byte[] authenticationData);
    
    public SignResult sign(SignatureAlgorithm algorithm, byte[] digest);
    public VerifyResult verify(SignatureAlgorithm algorithm, byte[] digest, byte[] signature);
    
    public WrapResult wrapKey(KeyWrapAlgorithm algorithm, byte[] key);
    public UnwrapResult unwrapKey(KeyWrapAlgorithm algorithm, byte[] encryptedKey);
    
    public SignResult signData(SignatureAlgorithm algorithm, byte[] data);
    public SignResult signDataAsync(SignatureAlgorithm algorithm, InputStream data);

    public VerifyResult verifyData(SignatureAlgorithm algorithm, byte[] data, byte[] signature);
    public VerifyResult verifyData(SignatureAlgorithm algorithm, InputStream data, byte[] signature);
}


~~~
