# Azure KeyVault Secrets Java SDK

## SecretClient API
```java

public class SecretClient extends ServiceClient
{
    // constructors
    private SecretClient(String vaultUrl, HttpPipeline pipeline);
    
    public static SecretClientBuilder builder() {
        return new SecretClientBuilder();
    }

    // methods
    public Response<Secret> getSecret(String secretName);
    public Response<Secret> getSecret(String secretName, String version);

    public List<SecretBase> listSecretVersions(String name);
    public List<SecretBase> listSecrets();
    
    public Response<SecretBase> updateSecret(SecretBase secret);

    public Response<Secret> setSecret(String name, String value);
    public Response<Secret> setSecret(Secret secret);

    public Response<DeletedSecret> deleteSecret(String name);
    public Response<DeletedSecret> getDeletedSecret(String name);
    public List<DeletedSecret> listDeletedSecrets();
    public Response<Secret> recoverDeletedSecret(String name);
    public VoidResponse purgeDeletedSecret(String name);

    public Response<byte[]> backupSecret(String name);
    public Response<Secret> restoreSecret(byte[] backup);
}

```

## SecretAsyncClient API
```java

public class SecretAsyncClient extends ServiceClient
{
    // constructors
    private SecretAsyncClient(String vaultUrl, HttpPipeline pipeline);
    
    public static SecretAsyncClientBuilder builder() {
        return new SecretAsyncClientBuilder();
    }

    // methods
    public Mono<Response<Secret>> getSecret(String secretName);
    public Mono<Response<Secret>> getSecret(String secretName, String version);

    public Flux<SecretBase> listSecretVersions(String name);
    public Flux<SecretBase> listSecrets();
    
    public Mono<Response<SecretBase>> updateSecret(SecretBase secret);

    public Mono<Response<Secret>> setSecret(String name, String value);
    public Mono<Response<Secret>> setSecret(Secret secret);

    public Mono<Response<DeletedSecret>> deleteSecret(String name);
    public Mono<Response<DeletedSecret>> getDeletedSecret(String name);
    public Flux<DeletedSecret> listDeletedSecrets();
    public Mono<Response<Secret>> recoverDeletedSecret(String name);
    public Mono<VoidResponse> purgeDeletedSecret(String name);

    public Mono<Response<byte[]>> backupSecret(String name);
    public Mono<Response<Secret>> restoreSecret(byte[] backup);
}

```


## Scenarios - Sync API

### 1. Given a secret to store, create it in key vault.
```java

SecretClient secretClient = SecretClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

 Secret secret = secretClient.setSecret("secretName", "secretValue").value();
 System.out.printf("Secret is created with name %s and value %s \n", secret.name(), secret.value());

```

### 2. Given a secret which expires in 1 year, create it in key vault.
```java

SecretClient secretClient = SecretClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

 Secret createdSecret = secretClient.setSecret(new Secret("secretName", "secretValue")
            .expires(OffsetDateTime.now().plusYears(1)))
            .value();
 System.out.printf("Secret is created with name %s and value %s \n", createdSecret.name(), createdSecret.value());

```

### 3. Given a secret named "StorageAccountKey" whose expiry got changed to 2 years from today, update it in key vault.
```java

SecretClient secretClient = SecretClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

Secret secretToUpdate = secretClient.getSecret("StorageAccountKey").value();

secretToUpdate.expires(OffsetDateTime.now().plusYears(2));
                                
SecretBase updatedSecret = secretClient.updateSecret(secretToUpdate).value();
System.out.printf("Secret's updated expiry time %s \n", updatedSecret.expires().toString());

```

### 4. Given a secret named "EventhubsAccountKey" which is no longer needed, delete it.
```java

SecretClient secretClient = SecretClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

DeletedSecret deletedSecret = secretClient.deleteSecret("EventhubsAccountKey").value();
System.out.printf("Deleted Secret's Recovery Id %s", deletedSecret.recoveryId());

```

## Scenarios - Async API

### 1. Given a secret to store, create it in key vault.
```java

SecretAsyncClient secretAsyncClient = SecretAsyncClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

secretAsyncClient.setSecret("secretName", "secretValue").subscribe(secretResponse ->
   System.out.printf("Secret is created with name %s and value %s \n", secretResponse.value().name(), secretResponse.value().value()));
 


```

### 2. Given a secret which expires in 1 year, create it in key vault.
```java

SecretAsyncClient secretAsyncClient = SecretAsyncClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

Secret secret = new Secret("secretName", "secretValue")
   .expires(OffsetDateTime.now().plusYears(1));

secretAsyncClient.setSecret(secret).subscribe(secretResponse ->
   System.out.printf("Secret is created with name %s and value %s \n", secretResponse.value().name(), secretResponse.value().value()));
 


```

### 3. Given a secret named "StorageAccountKey" whose expiry got changed to 2 years from today, update it in key vault.
```java

SecretAsyncClient secretAsyncClient = SecretAsyncClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

secretAsyncClient.getSecret("StorageAccountKey").subscribe(secretResponse -> {
    Secret secret = secretResponse.value();
    //Update the expiry time of the secret.
    secret.expires(OffsetDateTime.now().plusYears(2));
    secretAsyncClient.updateSecret(secret).subscribe(updatedSecretResponse ->
         System.out.printf("Secret's updated expiry time %s \n", updatedSecretResponse.value().notBefore().toString()));
});

```

### 4. Given a secret named "EventhubsAccountKey" which is no longer needed, delete it.
```java

SecretAsyncClient secretAsyncClient = SecretAsyncClient.builder()
                            .endpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();

secretAsyncClient.deleteSecret("EventhubsAccountKey").subscribe(deletedSecretResponse ->
   System.out.printf("Deleted Secret's Recovery Id %s \n", deletedSecretResponse.value().recoveryId()));

```
