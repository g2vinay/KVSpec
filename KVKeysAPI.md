
## __KeyAsyncClient__
~~~ java
public class KeyAsyncClient extends ServiceClient
{
    // constructors
    private KeyAsyncClient(String vaultUrl, HttpPipeline pipeline);
    public static KeyAsyncClientBuilder builder() {
        return new KeyAsyncClientBuilder();
    }

    // methods
    public Mono<Response<Key>> getKey(String name);
    public Mono<Response<Key>> getKey(String name, String version);
    
    public Mono<Response<Key>> createKey(String name, JsonWebKeyType keyType);
    public Mono<Response<Key>> createECKey(ECKeyCreateConfig ecKeyCreateConfig);
    public Mono<Response<Key>> createRSAKey(RSAKeyCreateConfig rsaKeyCreateConfig);
    
    public Flux<KeyBase> listKeyVersions(String name);
    public Flux<KeyBase> listKeys();
    public Flux<DeletedKey> listDeletedKeys();
    
    public Mono<Response<Key>> updateKey(KeyBase key);
    
    public Mono<Response<Key>> importKey(String name, JsonWebKey key);
    public Mono<Response<Key>> importKey(KeyImportConfig keyImportConfig);

    public Mono<Response<DeletedKey>> deleteKey(String name);
    public Mono<Response<DeletedKey>> getDeletedKey(String name);
    public Mono<Response<Key>> recoverDeletedKey(String name);
    public Mono<VoidResponse> purgeDeletedKey(String name);

    public Mono<Response<byte[]>> backupKey(String name);
    public Mono<Response<Key>> restoreKey(byte[] backup);
    
}
~~~

## __KeyClient__
~~~ java
public class KeyClient extends ServiceClient
{
    // constructors
    private KeyClient(String vaultUrl, HttpPipeline pipeline);
    public static KeyClientBuilder builder() {
        return new KeyClientBuilder();
    }

    // methods
    public Response<Key> getKey(String name);
    public Response<Key> getKey(String name, String version);
    
    public Response<Key> createKey(String name, JsonWebKeyType keyType);
    public Response<Key> createECKey(ECKeyCreateConfig ecKeyCreateConfig);
    public Response<Key> createRSAKey(RSAKeyCreateConfig rsaKeyCreateConfig);
    
    public List<KeyBase> listKeyVersions(String name);
    public List<KeyBase> listKeys();
    public List<DeletedKey> listDeletedKeys();
    
    public Response<Key> updateKey(KeyBase key);
    
    public Response<Key> importKey(String name, JsonWebKey key);
    public Response<Key> importKey(KeyImportConfig keyImportConfig);

    public Response<DeletedKey> deleteKey(String name);
    public Response<DeletedKey> getDeletedKey(String name);
    public Response<Key> recoverDeletedKey(String name);
    public VoidResponse purgeDeletedKey(String name);

    public Response<byte[]> backupKey(String name);
    public Response<Key> restoreKey(byte[] backup);
    
}
~~~

## Scenarios - Sync API

### 1. Create a key with name 'firstKey' of any type in key vault.
```java

KeyClient keyClient = KeyClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

 Key key = keyClient.createKey("firstKey", JsonWebKeyType.EC).value();
 System.out.printf("Key is created with name %s and id %s \n", key.name(), key.id());

```

### 2. Create an RSA HSM key of size 2048 and ensure it expires in 1 year.
```java

KeyClient keyClient = KeyClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();
                            
Key createdKey = keyClient.createRSAKey(new RSAKeyCreateConfig("myRsaHsmKey", JsonWebKeyType.RSA_HSM)
        .expires(OffsetDateTime.now().plusYears(1))
        .keySize(2048))
        .value();
      
System.out.printf("Key is created with name %s and value %s \n", createdKey.name(), createdKey.id());

```

### 3. Given a key named "myRsaHsmKey" whose expiry got changed to 2 years from today, update it in key vault.
```java

KeyClient keyClient = KeyClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

Key keyToUpdate = keyClient.getKey("myRsaHsmKey").value();
keyToUpdate.expires(OffsetDateTime.now().plusYears(2));

Key updatedKey = keyClient.updateKey(keyToUpdate).value();
System.out.printf("Key's updated expiry time %s \n", updatedKey.expires().toString());

```

### 4. Given a key named "myTwitterECKey" which is no longer needed, delete it.
```java

KeyClient keyClient = KeyClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

DeletedKey deletedKey = keyClient.deleteKey("myTwitterECKey").value();
System.out.printf("Deleted Key's Recovery Id %s", deletedKey.recoveryId());

```

## Scenarios - Async API

### 1. Create a key with name 'firstKey' of any type in key vault.
```java

KeyAsyncClient keyAsyncClient = KeyAsyncClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

keyAsyncClient.createKey("firstKey", JsonWebKeyType.EC).subscribe(keyResponse ->
   System.out.printf("Key is created with name %s and id %s \n", keyResponse.value().name(), keyResponse.value().id()));
 

```

### 2. Create an RSA HSM key of size 2048 and ensure it expires in 1 year.
```java

KeyAsyncClient keyAsyncClient = KeyAsyncClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

RSAKeyCreateConfig rsaKeyConfig = new RSAKeyCreateConfig("myRsaHsmKey", JsonWebKeyType.RSA_HSM)
                                      .expires(OffsetDateTime.now().plusYears(1))
                                      .keySize(2048);

keyAsyncClient.createRSAKey(rsaKeyConfig).subscribe(keyResponse ->
   System.out.printf("Key is created with name %s and id %s \n", keyResponse.value().name(), keyResponse.value().id()));
 


```

### 3. Given a key named "myRsaHsmKey" whose expiry got changed to 2 years from today, update it in key vault.
```java

KeyAsyncClient keyAsyncClient = KeyAsyncClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

keyAsyncClient.getKey("myRsaHsmKey").subscribe(keyResponse -> {
    Key key = keyResponse.value();
    //Update the expiry time of the key.
    key.expires(OffsetDateTime.now().plusYears(2));
    keyAsyncClient.updateKey(key).subscribe(updatedKeyResponse ->
            System.out.printf("Key's updated expiry time %s \n", updatedKeyResponse.value().notBefore().toString()));
});

```

### 4. Given a key named "myTwitterECKey" which is no longer needed, delete it.
```java

KeyAsyncClient keyAsyncClient = SecretAsyncClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

keyAsyncClient.deleteKey("EventhubsAccountKey").subscribe(deletedKeyResponse ->
   System.out.printf("Deleted Key's Recovery Id %s \n", deletedKeyResponse.value().recoveryId()));

```
