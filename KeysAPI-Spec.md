
## __KeyClient__
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

    public Flux<KeyBase> listKeyVersions(String name);
    public Flux<KeyBase> listKeys();
    public Flux<DeletedKey> listDeletedKeys();
    
    public Mono<Response<KeyBase>> updateKey(KeyBase key);

    //TODO: Investigate about createKey vs setKey, and then make a final call.
    public Mono<Response<Key>> setKey(String name, JsonWebKeyType keyType);
    public Mono<Response<Key>> setKey(Key key);
    
    public Mono<Response<Key>> importKey(String name, JsonWebKey key);
    public Mono<Response<Key>> importKey(KeyImport keyImport);

    public Mono<Response<DeletedKey>> deleteKey(String name);
    public Mono<Response<DeletedKey>> getDeletedKey(String name);
    public Mono<Response<Key>> recoverDeletedKey(String name);
    public Mono<VoidResponse> purgeDeletedKey(String name);

    public Mono<Response<byte[]>> backupKey(String name);
    public Mono<Response<Key>> restoreKey(byte[] backup);
    
}

public final class KeyAsyncClientBuilder {

    private KeyAsyncClientBuilder() {
    }

    public KeyAsyncClient build() {
       //Validate and Build the Client
    }

    public KeyAsyncClientBuilder vaultEndpoint(String vaultEndpoint) {}
    public KeyAsyncClientBuilder credentials(ServiceClientCredentials credentials) {}
    public KeyAsyncClientBuilder httpLogDetailLevel(HttpLogDetailLevel logLevel) {}
    public KeyAsyncClientBuilder addPolicy(HttpPipelinePolicy policy) {}
    public KeyAsyncClientBuilder httpClient(HttpClient client) {}
}

~~~
## Get / Set Operations
### KeyAsyncClient Set Key operations

~~~ java
public Mono<Response<Key>> setKey(String name, JsonWebKeyType keyType);
public Mono<Response<Key>> setKey(Key key);
~~~
#### Usage:
~~~ java
// TODO: Implement and Verify the usage.
KeyAsyncClient keyAsyncClient = KeyAsyncClient.builder()
                            .vaultEndpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();            

// set a simple key
Key userKey = keyAsyncClient.setKey("user1Key", JsonWebKeyType.EC_HSM).block().value();

Key key2 = new Key("user2Key", JsonWebKeyType.EC_HSM)
        .notBefore(OffsetDateTime.now().plusDays(2))
        .expires(OffsetDateTime.now().plusDays(5)));

Key retKey = keyAsyncClient.setKey(key2).block().value();

KeyImport keyImport = new KeyImport("user3Key", jsonWebKeytoBeImported)
     .hsm(true)
     .notBefore(OffsetDateTime.now().plusDays(2))
     .expires(OffsetDateTime.now().plusDays(5)));
     
Key importedKey = keyAsyncClient.importKey(keyImport).block().value();
~~~


### Replaces:
~~~ java

ServiceFuture<KeyBundle> createKeyAsync(CreateKeyRequest createKeyRequest, ServiceCallback<KeyBundle> serviceCallback);
ServiceFuture<KeyBundle> createKeyAsync(String vaultBaseUrl, String keyName, JsonWebKeyType kty, final ServiceCallback<KeyBundle> serviceCallback);
ServiceFuture<KeyBundle> createKeyAsync(String vaultBaseUrl, String keyName, JsonWebKeyType kty, Integer keySize, List<JsonWebKeyOperation> keyOps, KeyAttributes keyAttributes, Map<String, String> tags, JsonWebKeyCurveName curve, final ServiceCallback<KeyBundle> serviceCallback);
ServiceFuture<KeyBundle> createKeyAsync(String vaultBaseUrl, String keyName, JsonWebKeyType kty, Integer keySize, List<JsonWebKeyOperation> keyOps, KeyAttributes keyAttributes, Map<String, String> tags, final ServiceCallback<KeyBundle> serviceCallback);
Observable<KeyBundle> createKeyAsync(String vaultBaseUrl, String keyName, JsonWebKeyType kty, Integer keySize, List<JsonWebKeyOperation> keyOps, KeyAttributes keyAttributes, Map<String, String> tags);
Observable<ServiceResponse<KeyBundle>> createKeyWithServiceResponseAsync(String vaultBaseUrl, String keyName, JsonWebKeyType kty, Integer keySize, List<JsonWebKeyOperation> keyOps, KeyAttributes keyAttributes, Map<String, String> tags);
Observable<ServiceResponse<KeyBundle>> createKeyWithServiceResponseAsync(String vaultBaseUrl, String keyName, JsonWebKeyType kty);
Observable<ServiceResponse<KeyBundle>> createKeyWithServiceResponseAsync(String vaultBaseUrl, String keyName, JsonWebKeyType kty, Integer keySize, List<JsonWebKeyOperation> keyOps, KeyAttributes keyAttributes, Map<String, String> tags, JsonWebKeyCurveName curve);
Observable<KeyBundle> createKeyAsync(String vaultBaseUrl, String keyName, JsonWebKeyType kty);
Observable<KeyBundle> createKeyAsync(String vaultBaseUrl, String keyName, JsonWebKeyType kty, Integer keySize, List<JsonWebKeyOperation> keyOps, KeyAttributes keyAttributes, Map<String, String> tags, JsonWebKeyCurveName curve);
ServiceFuture<KeyBundle> importKeyAsync(String vaultBaseUrl, String keyName, JsonWebKey key, Boolean hsm, KeyAttributes keyAttributes, Map<String, String> tags, final ServiceCallback<KeyBundle> serviceCallback);
Observable<KeyBundle> importKeyAsync(String vaultBaseUrl, String keyName, JsonWebKey key, Boolean hsm, KeyAttributes keyAttributes, Map<String, String> tags);
Observable<ServiceResponse<KeyBundle>> importKeyWithServiceResponseAsync(String vaultBaseUrl, String keyName, JsonWebKey key, Boolean hsm, KeyAttributes keyAttributes, Map<String, String> tags);
ServiceFuture<KeyBundle> importKeyAsync(ImportKeyRequest importKeyRequest, final ServiceCallback<KeyBundle> serviceCallback);
~~~
#### Usage:
~~~ java 
// TODO: Add Track one Set Key usage examples.
~~~


### KeyClient Get Key Operations
~~~ java
public Mono<Response<Key>> getKey(String name);
public Mono<Response<Key>> getKey(String name, String version);
~~~

#### Usage:
~~~ java
// TODO: Implement and Verify the usage.
// get the latest version of a key
Key key = keyAsyncClient.getKey("user1Key").block().value();

// get a specific version of a key
Key keyWithVersion = keyAsyncClient.getKey("user1Key","6A385B124DEF4096AF1361A85B16C204").block().value();
~~~

### Replaces:
~~~ java
ServiceFuture<KeyBundle> getKeyAsync(String vaultBaseUrl, String keyName, final ServiceCallback<KeyBundle> serviceCallback);
ServiceFuture<KeyBundle> getKeyAsync(String keyIdentifier, final ServiceCallback<KeyBundle> serviceCallback);
ServiceFuture<KeyBundle> getKeyAsync(String vaultBaseUrl, String keyName, String keyVersion, final ServiceCallback<KeyBundle> serviceCallback);
Observable<KeyBundle> getKeyAsync(String vaultBaseUrl, String keyName, String keyVersion);
Observable<ServiceResponse<KeyBundle>> getKeyWithServiceResponseAsync(String vaultBaseUrl, String keyName, String keyVersion);
~~~
#### Usage:
~~~ java 
// TODO: Add Track one Get Key usage examples.
~~~

### Update Key Operation
~~~ java
public Mono<Response<KeyBase>> updateKey(KeyBase key);
~~~
#### Usage:
~~~ java
// TODO: Implement and Verify the usage.
// Update the expiration of a key
Key userKey = keyAsyncClient.getKey("user1Key").block().value();

userKey.notBefore(OffsetDateTime.now().plusDays(79));

KeyBase updatedKey = keyAsyncClient.updateKey(userKey).block().value();
~~~
### Replaces:
~~~ java
ServiceFuture<KeyBundle> updateKeyAsync(String vaultBaseUrl, String keyName, String keyVersion, final ServiceCallback<KeyBundle> serviceCallback);
Observable<KeyBundle> updateKeyAsync(String vaultBaseUrl, String keyName, String keyVersion);
Observable<ServiceResponse<KeyBundle>> updateKeyWithServiceResponseAsync(String vaultBaseUrl, String keyName, String keyVersion);
ServiceFuture<KeyBundle> updateKeyAsync(String vaultBaseUrl, String keyName, String keyVersion, List<JsonWebKeyOperation> keyOps, KeyAttributes keyAttributes, Map<String, String> tags, final ServiceCallback<KeyBundle> serviceCallback);
Observable<KeyBundle> updateKeyAsync(String vaultBaseUrl, String keyName, String keyVersion, List<JsonWebKeyOperation> keyOps, KeyAttributes keyAttributes, Map<String, String> tags);
Observable<ServiceResponse<KeyBundle>> updateKeyWithServiceResponseAsync(String vaultBaseUrl, String keyName, String keyVersion, List<JsonWebKeyOperation> keyOps, KeyAttributes keyAttributes, Map<String, String> tags);
ServiceFuture<KeyBundle> updateKeyAsync(UpdateKeyRequest updateKeyRequest, final ServiceCallback<KeyBundle> serviceCallback);
~~~
#### Usage:
~~~ java
// TODO: Add Track one Update Key usage examples.
~~~

## List Operations

### listKeys, listKeyVersions
~~~ java
public Flux<KeyBase> listKeyVersions(String name);
public Flux<KeyBase> listKeys();
~~~
#### Usage:
~~~ java
// TODO: Implement and Verify the usage.
keyAsyncClient.listKeys()
	.subscribe(key -> System.out.println(key.id()));
 
~~~

### Replaces:
~~~ java
ServiceFuture<List<KeyItem>> getKeyVersionsAsync(final String vaultBaseUrl, final String keyName, final ListOperationCallback<KeyItem> serviceCallback);
Observable<Page<KeyItem>> getKeyVersionsAsync(final String vaultBaseUrl, final String keyName);
Observable<ServiceResponse<Page<KeyItem>>> getKeyVersionsWithServiceResponseAsync(final String vaultBaseUrl, final String keyName);
PagedList<KeyItem> getKeyVersions(final String vaultBaseUrl, final String keyName, final Integer maxresults);
ServiceFuture<List<KeyItem>> getKeyVersionsAsync(final String vaultBaseUrl, final String keyName, final Integer maxresults, final ListOperationCallback<KeyItem> serviceCallback);
Observable<Page<KeyItem>> getKeyVersionsAsync(final String vaultBaseUrl, final String keyName, final Integer maxresults);
Observable<ServiceResponse<Page<KeyItem>>> getKeyVersionsWithServiceResponseAsync(final String vaultBaseUrl, final String keyName, final Integer maxresults);
ServiceFuture<List<KeyItem>> getKeysAsync(final String vaultBaseUrl, final ListOperationCallback<KeyItem> serviceCallback);
Observable<Page<KeyItem>> getKeysAsync(final String vaultBaseUrl);
Observable<ServiceResponse<Page<KeyItem>>> getKeysWithServiceResponseAsync(final String vaultBaseUrl);
PagedList<KeyItem> getKeys(final String vaultBaseUrl, final Integer maxresults);
ServiceFuture<List<KeyItem>> getKeysAsync(final String vaultBaseUrl, final Integer maxresults, final ListOperationCallback<KeyItem> serviceCallback);
Observable<Page<KeyItem>> getKeysAsync(final String vaultBaseUrl, final Integer maxresults);
Observable<ServiceResponse<Page<KeyItem>>> getKeysWithServiceResponseAsync(final String vaultBaseUrl, final Integer maxresults);
PagedList<KeyItem> getKeyVersionsNext(final String nextPageLink);
ServiceFuture<List<KeyItem>> getKeyVersionsNextAsync(final String nextPageLink, final ServiceFuture<List<KeyItem>> serviceFuture, final ListOperationCallback<KeyItem> serviceCallback);
Observable<Page<KeyItem>> getKeyVersionsNextAsync(final String nextPageLink);
Observable<ServiceResponse<Page<KeyItem>>> getKeyVersionsNextWithServiceResponseAsync(final String nextPageLink);
PagedList<KeyItem> getKeysNext(final String nextPageLink);
ServiceFuture<List<KeyItem>> getKeysNextAsync(final String nextPageLink, final ServiceFuture<List<KeyItem>> serviceFuture, final ListOperationCallback<KeyItem> serviceCallback);
Observable<Page<KeyItem>> getKeysNextAsync(final String nextPageLink);
Observable<ServiceResponse<Page<KeyItem>>> getKeysNextWithServiceResponseAsync(final String nextPageLink);


~~~
#### Usage:
~~~ java
// TODO: Add Track one List Key usage examples.
~~~

## Deleted Key Operations

### deleteKey, getDeletedKey, listDeletedKeys, recoverDeletedKey, purgeDeletedKey
~~~ java
public Mono<Response<DeletedKey>> deleteKey(String name);
public Mono<Response<DeletedKey>> getDeletedKey(String name);
public Mono<Response<Key>> recoverDeletedKey(String name);
public Mono<VoidResponse> purgeDeletedKey(String name);
public Flux<DeletedKey> listDeletedKeys();
~~~
#### Usage:
~~~ java
// TODO: Implement and Verify the usage.
// Delete a key
DeletedKey deletedkey =  keyAsyncClient.deleteKey("user1pass").block().value();

// Wait for few seconds.
Thread.sleep(5000);

// Get the details of a deleted key
 deletedKey = keyAsyncClient.getDeletedKey("user1pass").block().value();

// List all the deleted keys
keyAsyncClient.listDeletedKeys()
	.subscribe(delKey -> System.out.println(delKey.recoveryId()));

// Recover a deleted key
Key key = keyAsyncClient.recoverDeletedKey("user1pass").block().value();

// Wait for few seconds.
Thread.sleep(5000);

// Delete the key again after recovering it.
deletedKey = keyAsyncClient.deleteKey("user1pass").block().value();

// Wait for few seconds.
Thread.sleep(5000);

// Purge the deleted key -- permanenetly delete it.
keyAsyncClient.purgeDeletedKey("user1pass").block();
~~~
### Replaces:
~~~ java
ServiceFuture<DeletedKeyBundle> deleteKeyAsync(String vaultBaseUrl, String keyName, final ServiceCallback<DeletedKeyBundle> serviceCallback);
Observable<DeletedKeyBundle> deleteKeyAsync(String vaultBaseUrl, String keyName);
Observable<ServiceResponse<DeletedKeyBundle>> deleteKeyWithServiceResponseAsync(String vaultBaseUrl, String keyName);
PagedList<DeletedKeyItem> getDeletedKeys(final String vaultBaseUrl);
ServiceFuture<List<DeletedKeyItem>> getDeletedKeysAsync(final String vaultBaseUrl, final ListOperationCallback<DeletedKeyItem> serviceCallback);
Observable<Page<DeletedKeyItem>> getDeletedKeysAsync(final String vaultBaseUrl);
Observable<ServiceResponse<Page<DeletedKeyItem>>> getDeletedKeysWithServiceResponseAsync(final String vaultBaseUrl);
PagedList<DeletedKeyItem> getDeletedKeys(final String vaultBaseUrl, final Integer maxresults);
ServiceFuture<List<DeletedKeyItem>> getDeletedKeysAsync(final String vaultBaseUrl, final Integer maxresults, final ListOperationCallback<DeletedKeyItem> serviceCallback);
Observable<Page<DeletedKeyItem>> getDeletedKeysAsync(final String vaultBaseUrl, final Integer maxresults);
Observable<ServiceResponse<Page<DeletedKeyItem>>> getDeletedKeysWithServiceResponseAsync(final String vaultBaseUrl, final Integer maxresults);
DeletedKeyBundle getDeletedKey(String vaultBaseUrl, String keyName);
ServiceFuture<DeletedKeyBundle> getDeletedKeyAsync(String vaultBaseUrl, String keyName, final ServiceCallback<DeletedKeyBundle> serviceCallback);
Observable<DeletedKeyBundle> getDeletedKeyAsync(String vaultBaseUrl, String keyName);
Observable<ServiceResponse<DeletedKeyBundle>> getDeletedKeyWithServiceResponseAsync(String vaultBaseUrl, String keyName);
ServiceFuture<Void> purgeDeletedKeyAsync(String vaultBaseUrl, String keyName, final ServiceCallback<Void> serviceCallback);
Observable<Void> purgeDeletedKeyAsync(String vaultBaseUrl, String keyName);
Observable<ServiceResponse<Void>> purgeDeletedKeyWithServiceResponseAsync(String vaultBaseUrl, String keyName);
ServiceFuture<KeyBundle> recoverDeletedKeyAsync(String vaultBaseUrl, String keyName, final ServiceCallback<KeyBundle> serviceCallback);
Observable<KeyBundle> recoverDeletedKeyAsync(String vaultBaseUrl, String keyName);
Observable<ServiceResponse<KeyBundle>> recoverDeletedKeyWithServiceResponseAsync(String vaultBaseUrl, String keyName);
PagedList<DeletedKeyItem> getDeletedKeysNext(final String nextPageLink);
ServiceFuture<List<DeletedKeyItem>> getDeletedKeysNextAsync(final String nextPageLink, final ServiceFuture<List<DeletedKeyItem>> serviceFuture, final ListOperationCallback<DeletedKeyItem> serviceCallback);
Observable<Page<DeletedKeyItem>> getDeletedKeysNextAsync(final String nextPageLink);
Observable<ServiceResponse<Page<DeletedKeyItem>>> getDeletedKeysNextWithServiceResponseAsync(final String nextPageLink);
~~~
#### Usage:
~~~ java
// TODO: Add Track one Delete, Recover and Purge Key usage examples.
~~~

### backupKey, restoreKey
~~~ java
public Mono<Response<byte[]>> backupKey(String name);
public Mono<Response<Key>> restoreKey(byte[] backup);
~~~
#### Usage:
~~~ java
// TODO: Implement and Verify the usage.
// backup the key
byte[] backup = keyAsyncClient.backupKey("user1Key").block().value();

DeletedKey deletedKey =  keyAsyncClient.deleteKey("user1Key").block().value();

Thread.sleep(30000);

keyAsyncClient.purgeDeletedKey("user1Key").block();

//restore the key from backup
Key restored = keyAsyncClient.restoreKey(backup).block().value();
~~~
### Replaces:
~~~ java
ServiceFuture<BackupKeyResult> backupKeyAsync(String vaultBaseUrl, String keyName, final ServiceCallback<BackupKeyResult> serviceCallback);
Observable<BackupKeyResult> backupKeyAsync(String vaultBaseUrl, String keyName);
Observable<ServiceResponse<BackupKeyResult>> backupKeyWithServiceResponseAsync(String vaultBaseUrl, String keyName);
ServiceFuture<KeyBundle> restoreKeyAsync(String vaultBaseUrl, byte[] keyBundleBackup, final ServiceCallback<KeyBundle> serviceCallback);
Observable<KeyBundle> restoreKeyAsync(String vaultBaseUrl, byte[] keyBundleBackup);
Observable<ServiceResponse<KeyBundle>> restoreKeyWithServiceResponseAsync(String vaultBaseUrl, byte[] keyBundleBackup);
~~~
#### Usage:
~~~ java
// TODO: Add Track one Backup and Restore Key usage examples.
~~~


## DataStructures:
~~~ java
public class KeyBase {

    //TODO: Add appropriate setters for the variables
    /**
     * The Json web key.
     */
    @JsonProperty(value = "key")
    private JsonWebKey key;

    /**
     * Key identifier.
     */
    @JsonProperty(value = "id")
    private String id;

    /**
     * Type of the key.
     */
    @JsonProperty(value = "contentType")
    private String contentType;

    /**
     * Application specific metadata in the form of key-value pairs.
     */
    @JsonProperty(value = "tags")
    private Map<String, String> tags;

    /**
     * True if the key's lifetime is managed by key vault. If this is a key
     * backing a certificate, then managed will be true.
     */
    @JsonProperty(value = "managed", access = JsonProperty.Access.WRITE_ONLY)
    private Boolean managed;
		
	  /**
     * Determines whether the object is enabled.
     */
    @JsonProperty(value = "enabled")
    private Boolean enabled;

    /**
     * Not before date in UTC.
     */
    @JsonProperty(value = "nbf")
    private Long notBefore;

    /**
     * Expiry date in UTC.
     */
    @JsonProperty(value = "exp")
    private Long expires;

    /**
     * Creation time in UTC.
     */
    @JsonProperty(value = "created", access = JsonProperty.Access.WRITE_ONLY)
    private Long created;

    /**
     * Last updated time in UTC.
     */
    @JsonProperty(value = "updated", access = JsonProperty.Access.WRITE_ONLY)
    private Long updated;


    /**
     * Reflects the deletion recovery level currently in effect for keys in the
     * current vault. If it contains 'Purgeable' the key can be permanently
     * deleted by a privileged user; otherwise, only the system can purge the
     * key, at the end of the retention interval. Possible values include:
     * 'Purgeable', 'Recoverable+Purgeable', 'Recoverable',
     * 'Recoverable+ProtectedSubscription'.
     */
    @JsonProperty(value = "recoveryLevel", access = JsonProperty.Access.WRITE_ONLY)
    private DeletionRecoveryLevel recoveryLevel;

    /**
     * Get the recoveryLevel value.
     *
     * @return the recoveryLevel value
     */
    public DeletionRecoveryLevel recoveryLevel() {
        return this.recoveryLevel;
    }

}

public class Key extends KeyBase {
    private Integer keySize;
    private List<JsonWebKeyOperation> keyOperations;
    private JsonWebKeyCurveName curve;

	public Key(String name, JsonWebKeyType keyType) {}


	public Key keySize(Integer keySize){
		this.keySize = keySize;
		return this;
	}

	//Add setters in similar way for other variables

}


public class KeyImport extends KeyBase {

	private boolean hsm;

	public KeyImport(String name, JsonWebKey key) {}

	public KeyImport hsm(boolean hsm) {
		this.hsm = hsm;
	    return this;
	}

	// Add other required setters.

}


public class DeletedKey extends KeyBase {
    /**
     * The url of the recovery object, used to identify and recover the deleted
     * key.
     */
    @JsonProperty(value = "recoveryId")
    private String recoveryId;

    /**
     * The time when the key is scheduled to be purged, in UTC.
     */
    @JsonProperty(value = "scheduledPurgeDate", access = JsonProperty.Access.WRITE_ONLY)
    private Long scheduledPurgeDate;

    /**
     * The time when the key was deleted, in UTC.
     */
    @JsonProperty(value = "deletedDate", access = JsonProperty.Access.WRITE_ONLY)
    private Long deletedDate;

    /**
     * Get the recoveryId value.
     *
     * @return the recoveryId value
     */
    public String recoveryId() {
        return this.recoveryId;
    }

    // Add other required Setters

}
~~~



