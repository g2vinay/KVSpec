# Azure KeyVault Certificates API Design

Azure Key Vault is a cloud service that provides secure storage and automated management of certificates used throughout a cloud application. Multiple certificate, and multiple versions of the same certificate, can be kept in the Key Vault. Each certificate in the vault has a policy associated with it which controls the issuance and lifetime of the certificate, along with actions to be taken as certificates near expiry.

The Azure Key Vault Certificate client library enables programmatically managing certificates, offering methods to create, update, list, and delete certificates, policies, issuers, and contacts. The library also supports managing pending certificate operations and management of deleted certificates.

## Concepts
* Certificate
* Certificate Policy
* Issuer
* Contact
* Certificate Operation

## Scenario - Create CertificateClient

### API

#### .NET

```c#
public CertificateClient(Uri vaultUri, TokenCredential credential);
public CertificateClient(Uri vaultUri, TokenCredential credential, CertificateClientOptions options);

public class CertificateClientOptions : ClientOptions {
    public enum ServiceVersion {
        V7_0 = 0,
    }
    public CertificateClientOptions(ServiceVersion version = V7_0);
    public ServiceVersion Version { get; }
}
```

## Scenario - Get vault endpoint

### API

#### .NET
```c#
public virtual Uri VaultUri { get; }
```

## Scenario - Create Certificate
### Usage


### Java
```java
// Async Example
CertificatePolicy certPolicy = new CertificatePolicy("Self", "CN=SelfSignedJavaPkcs12");
certificateAsyncClient.beginCreateCertificate("certificateName", certPolicy)
    .subscribe(pollResponse -> {
        System.out.println("---------------------------------------------------------------------------------");
        System.out.println(pollResponse.getStatus());
        System.out.println(pollResponse.getValue().getStatus());
        System.out.println(pollResponse.getValue().getStatusDetails());
    });
    
// Sync example
SyncPoller<CertificateOperation, KeyVaultCertificate> certificatePoller = certificateClient
    .beginCreateCertificate("certificateName", certificatePolicy);
certificatePoller.waitUntil(LongRunningOperationStatus.SUCCESSFULLY_COMPLETED);
KeyVaultCertificate certificate = certificatePoller.getFinalResult();
System.out.printf("Certificate created with name %s", certificate.getName());

```

### .NET
```c#
var client = new CertificateClient(new Uri(keyVaultUrl), new DefaultAzureCredential());

string certName = $"defaultCert-{Guid.NewGuid()}";
CertificateOperation certOp = client.StartCreateCertificate(certName, CertificatePolicy.Default);

while (!certOp.HasCompleted)
{
    certOp.UpdateStatus();

    Thread.Sleep(TimeSpan.FromSeconds(1));
}

KeyVaultCertificateWithPolicy certificate = client.GetCertificate(certName);

Debug.WriteLine($"Certificate was returned with name {certificate.Name} which expires {certificate.Properties.ExpiresOn}");
```

### Python
```python
    credential = DefaultAzureCredential()
    client = CertificateClient(vault_url=VAULT_URL, credential=credential)
    try:
        cert_policy = CertificatePolicy(
          exportable=True,
          key_type="RSA",
          key_size=2048,
          reuse_key=False,
          content_type=SecretContentType.PKCS12,
          issuer_name=WellKnownIssuerNames.Self,
          subject_name="CN=*.microsoft.com",
          validity_in_months=24,
          san_dns_names=["sdk.azure-int.net"],
      )
      cert_name = "HelloWorldCertificate"

      # begin_create_certificate returns a poller. Calling result() on the poller will return the certificate
      # as a KeyVaultCertificate if creation is successful, and the CertificateOperation if not. The wait()
      # call on the poller will wait until the long running operation is complete.
      certificate = client.begin_create_certificate(
          certificate_name=cert_name, policy=cert_policy
      ).result()
      print("Certificate with name '{0}' created".format(certificate.name))

    except HttpResponseError as e:
    print("\nrun_sample has caught an error. {0}".format(e.message))

    finally:
        print("\nrun_sample done")
```
### JS/TS
```ts
  const client = new CertificatesClient(url, credential);

  // Creating a self-signed certificate
  const certificate = await client.createCertificate("MyCertificate", {
    issuerParameters: { name: "Self" },
    x509CertificateProperties: { subject: "cn=MyCert" }
  });

  console.log("Certificate: ", certificate);
```

### API
### Java
```java

public PollerFlux<CertificateOperation, KeyVaultCertificate> beginCreateCertificate(String name, CertificatePolicy policy, boolean enabled, Map<String, String> tags) {}
public PollerFlux<CertificateOperation, KeyVaultCertificate> beginCreateCertificate(String name, CertificatePolicy policy) {}

public SyncPoller<CertificateOperation, KeyVaultCertificate> beginCreateCertificate(String name, CertificatePolicy policy, Map<String, String> tags) {}
public SyncPoller<CertificateOperation, KeyVaultCertificate> beginCreateCertificate(String name, CertificatePolicy policy) {}
```

### .NET
```c#
public virtual CertificateOperation StartCreateCertificate(string certificateName, CertificatePolicy policy, bool? enabled = null, IDictionary<string, string> tags = null, CancellationToken cancellationToken = default);
public virtual Task<CertificateOperation> StartCreateCertificateAsync(string certificateName, CertificatePolicy policy, bool? enabled = null, IDictionary<string, string> tags = null, CancellationToken cancellationToken = default);
```

### Python
//Async
```python
    async def create_certificate(
        self,
        certificate_name,  # type: str
        policy,  # type: CertificatePolicy
        **kwargs  # type: Any
    ) -> KeyVaultCertificate
```

//Sync
```python
    def begin_create_certificate(
        self,
        certificate_name,  # type: str
        policy,  # type: CertificatePolicy
        **kwargs  # type: Any
    ) -> LROPoller[KeyVaultCertificate]
```
### JS/TS
```ts
  public async beginCreateCertificate(
    certificateName: string,
    certificatePolicy: CertificatePolicy,
    options: BeginCreateCertificateOptions = {}
  ): Promise<PollerLike<PollOperationState<KeyVaultCertificate>, KeyVaultCertificate>>
```

## Scenario - Get Certificate or certificate version
### Usage
### Java
```java
//Retrieve asynchronously
certificateAsyncClient.getCertificate("certificateName", "certificateVersion")
    .subscribe(certificateResponse ->
        System.out.printf("Certificate is returned with name %s and secretId %s %n", certificateResponse.name(),
            certificateResponse.secretId()));

// Retrieve synchronously
Certificate certificate = certificateClient.getCertificateWithPolicy("certificateName");
System.out.printf("Recevied certificate with name %s and version %s and secret id", certificate.name(),
    certificate.version(), certificate.secretId());
```

### Python
```python
//Async
# Let's get the bank certificate using its name
print("\n.. Get a Certificate by name")
bank_certificate = await client.get_certificate(cert_name)
print("Certificate with name '{0}' was found'.".format(bank_certificate.name))

//Sync
# Let's get the bank certificate using its name
print("\n.. Get a Certificate by name")
bank_certificate = client.get_certificate(cert_name)
print("Certificate with name '{0}' was found'.".format(bank_certificate.name))
```

### API
### Java
```java
// Async API
public Mono<KeyVaultCertificateWithPolicy> getCertificate(String name) {}
public Mono<Response<KeyVaultCertificateWithPolicy>> getCertificateWithResponse(String name) {}
public Mono<Response<KeyVaultCertificate>> getCertificateVersionWithResponse(String name, String version) {}
public Mono<KeyVaultCertificate> getCertificateVersion(String name, String version) {}

//Sync API    
public KeyVaultCertificateWithPolicy getCertificate(String name) {}
public Response<KeyVaultCertificateWithPolicy> getCertificateWithResponse(String name) {}
public Response<KeyVaultCertificate> getCertificateVersionWithResponse(String name, String version, Context context) {}
public KeyVaultCertificate getCertificateVersion(String name, String version) {}
```

### .NET
```c#
public virtual Response<KeyVaultCertificateWithPolicy> GetCertificate(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<Response<KeyVaultCertificateWithPolicy>> GetCertificateAsync(string certificateName, CancellationToken cancellationToken = default);
public virtual Response<KeyVaultCertificate> GetCertificateVersion(string certificateName, string version, CancellationToken cancellationToken = default);
public virtual Task<Response<KeyVaultCertificate>> GetCertificateVersionAsync(string certificateName, string version, CancellationToken cancellationToken = default);
```

### Python
```python
async def get_certificate(self, certificate_name: str, **kwargs: "**Any") -> KeyVaultCertificate:
async def get_certificate_version(
self, certificate_name: str, version: str, **kwargs: "**Any"
) -> KeyVaultCertificate:
```

### JS/TS
```javascript
  public async getCertificate(
    certificateName: string,
    options: GetCertificateOptions = {}
  ): Promise<KeyVaultCertificateWithPolicy>

  public async getCertificateVersion(
    certificateName: string,
    version: string,
    options: GetCertificateVersionOptions = {}
  ): Promise<KeyVaultCertificate>
```

## Scenario - Get Certificate Policy

### Usage
### Java
```java
//Async
certificateAsyncClient.getCertificatePolicy("certificateName")
    .subscribe(policy ->
        System.out.printf("Certificate policy is returned with issuer name %s and subject name %s %n",
            policy.issuerName(), policy.subjectName()));

//Sync
CertificatePolicy policy = certificateClient.getCertificatePolicy("certificateName");
System.out.printf("Received policy with subject name %s", policy.subjectName());
```

### JS/TS
```ts
const policy = await client.getCertificatePolicy("MyCertificate");
console.log(policy);
```

### API
### Java
```java
public Mono<CertificatePolicy> getCertificatePolicy(String name) {}
public Mono<Response<CertificatePolicy>> getCertificatePolicyWithResponse(String name) {}

public CertificatePolicy getCertificatePolicy(String certificateName) {}
public Response<CertificatePolicy> getCertificatePolicyWithResponse(String certificateName, Context context) {}
```

### .NET
```c#
public virtual Response<CertificatePolicy> GetCertificatePolicy(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<Response<CertificatePolicy>> GetCertificatePolicyAsync(string certificateName, CancellationToken cancellationToken = default);
```
### Python
```python
async def get_policy(self, certificate_name: str, **kwargs: "**Any") -> CertificatePolicy:
```

### JS/TS
```ts
  public async getCertificatePolicy(
    certificateName: string,
    options: GetCertificatePolicyOptions = {}
  ): Promise<CertificatePolicy>
```

## Scenario - Update Certificate
Question: Updating Certificate via Properties vs setting fields.

### Usage
### Java
```java

//Async
certificateAsyncClient.getCertificateWithPolicy("certificateName")
    .subscribe(certificateResponseValue -> {
        CertificateProperties certificateProps = certificateResponseValue.getProperties();
        //Update enabled status of the certificate
        certificateProps.setEnabled(false);
        certificateAsyncClient.updateCertificateProperties(certificateProps)
            .subscribe(certificateResponse ->
                System.out.printf("Certificate's enabled status %s %n",
                    certificateResponse.getProperties().getEnabled().toString()));
    });

//Sync
CertificateProperties certProps = certificateClient.getCertificateWithPolicy("certificateName").getProperties();
Map<String, String> tags = new HashMap<>();
tags.put("foo", "bar");
// Update certificate enabled status and tags
certProps.setEnabled(false);
certProps.setTags(tags);
Certificate updatedCertificate = certificateClient.updateCertificateProperties(certProps);
System.out.printf("Updated Certificate with name %s and enabled status %s", updatedCertificate.name(),
    updatedCertificate.getProperties().getEnabled());
```

### Python
```python

//Async
print("\n.. Update a Certificate by name")
tags = {"a": "b"}
updated_certificate = await client.update_certificate_properties(
    certificate_name=bank_certificate.name, tags=tags
)
print(
    "Certificate with name '{0}' was updated on date '{1}'".format(
        bank_certificate.name, updated_certificate.properties.updated_on
    )
)
print(
    "Certificate with name '{0}' was updated with tags '{1}'".format(
        bank_certificate.name, updated_certificate.properties.tags
    )
)

//Sync
print("\n.. Update a Certificate by name")
tags = {"a": "b"}
updated_certificate = client.update_certificate_properties(
    certificate_name=bank_certificate.name, tags=tags
)
print(
    "Certificate with name '{0}' was updated on date '{1}'".format(
        bank_certificate.name, updated_certificate.properties.updated_on
    )
)
print(
    "Certificate with name '{0}' was updated with tags '{1}'".format(
        bank_certificate.name, updated_certificate.properties.tags
    )
)
```

### JS/TS
```ts
await client.updateCertificate("MyCertificate", "", {
   tags: {
    customTag: "value"
   }
});
```

### API
### Java
```java

public Mono<KeyVaultCertificate> updateCertificateProperties(CertificateProperties certificateProperties) {}
public Mono<Response<KeyVaultCertificate>> updateCertificatePropertiesWithResponse(CertificateProperties certificateProperties) {}
    
    
public KeyVaultCertificate updateCertificateProperties(CertificateProperties certificateProperties) {}
public Response<KeyVaultCertificate> updateCertificatePropertiesWithResponse(CertificateProperties certificateProperties, Context context) {}
```

### .NET
```c#
public virtual Response<KeyVaultCertificate> UpdateCertificateProperties(CertificateProperties properties, CancellationToken cancellationToken = default);
public virtual Task<Response<KeyVaultCertificate>> UpdateCertificatePropertiesAsync(CertificateProperties properties, CancellationToken cancellationToken = default);
```

### Python
```python
async def update_certificate_properties(
    self, certificate_name: str, version: Optional[str] = None, **kwargs: "**Any"
) -> KeyVaultCertificate:
```

### JS/TS
```ts
  public async updateCertificate(
    certificateName: string,
    version: string,
    options: UpdateCertificateOptions = {}
  ): Promise<KeyVaultCertificate>
```

## Scenario - Update Certificate Policy
### Usage
### Java
```java
//Async
certificateAsyncClient.getCertificatePolicy("certificateName")
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(certificatePolicyResponseValue -> {
        CertificatePolicy certificatePolicy = certificatePolicyResponseValue;
        // Update validity
        certificatePolicy.setValidityInMonths(24);
        certificateAsyncClient.updateCertificatePolicy("certificateName", certificatePolicy)
            .subscribe(updatedPolicy ->
                System.out.printf("Certificate policy's updated validity %d %n",
                    updatedPolicy.getValidityInMonths()));
    });

// Sync
CertificatePolicy certificatePolicy = certificateClient.getCertificatePolicy("certificateName");
// Update the certificate policy cert transparency property.
certificatePolicy.setValidityInMonths(24);
CertificatePolicy updatedCertPolicy = certificateClient.updateCertificatePolicy("certificateName",
    certificatePolicy);
System.out.printf("Updated Certificate Policy validity %d", updatedCertPolicy.getValidityInMonths());
```

### API
### Java
```java
public Mono<CertificatePolicy> updateCertificatePolicy(String certificateName, CertificatePolicy policy) {}
public Mono<Response<CertificatePolicy>> updateCertificatePolicyWithResponse(String certificateName, CertificatePolicy policy) {}

public CertificatePolicy updateCertificatePolicy(String certificateName, CertificatePolicy policy) {}
public Response<CertificatePolicy> updateCertificatePolicyWithResponse(String certificateName, CertificatePolicy policy, Context context) {}

```

### .NET
```c#
public virtual Response<CertificatePolicy> UpdateCertificatePolicy(string certificateName, CertificatePolicy policy, CancellationToken cancellationToken = default);
public virtual Task<Response<CertificatePolicy>> UpdateCertificatePolicyAsync(string certificateName, CertificatePolicy policy, CancellationToken cancellationToken = default);
```
### Python
```python
async def update_policy(
        self, certificate_name: str, policy: CertificatePolicy, **kwargs: "**Any"
    ) -> CertificatePolicy:
```
### JS/TS
```ts
  public async updateCertificatePolicy(
    certificateName: string,
    certificatePolicy: CertificatePolicy,
    options: UpdateCertificatePolicyOptions = {}
  ): Promise<CertificatePolicy>
```


## Scenario - Delete Certificate

### Usage

### python
``` python
# Async
print("\n.. Delete Certificate")
deleted_certificate = await client.delete_certificate(bank_certificate.name)
print("Deleting Certificate..")
print("Certificate with name '{0}' was deleted.".format(deleted_certificate.name))

# Sync
print("\n.. Delete Certificate")
delete_certificate_poller = client.begin_delete_certificate(bank_certificate.name)
deleted_certificate = delete_certificate_poller.result()
print("Certificate with name '{0}' was deleted.".format(deleted_certificate.name))

# wait to ensure certificate is deleted server-side
delete_certificate_poller.wait()
```

### API
### Java
```java
public PollerFlux<DeletedCertificate, Void> beginDeleteCertificate(String name) {}

public SyncPoller<DeletedCertificate, Void> beginDeleteCertificate(String name) {}
```

### .NET
```c#
public virtual DeleteCertificateOperation StartDeleteCertificate(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<DeleteCertificateOperation> StartDeleteCertificateAsync(string certificateName, CancellationToken cancellationToken = default);

public class DeleteCertificateOperation : Operation<DeletedCertificate> {
    public override bool HasCompleted { get; }
    public override bool HasValue { get; }
    public override string Id { get; }
    public override DeletedCertificate Value { get; }
    public override Response GetRawResponse();
    public override Response UpdateStatus(CancellationToken cancellationToken = default);
    public override ValueTask<Response> UpdateStatusAsync(CancellationToken cancellationToken = default);
    public override ValueTask<Response<DeletedCertificate>> WaitForCompletionAsync(CancellationToken cancellationToken = default);
    public override ValueTask<Response<DeletedCertificate>> WaitForCompletionAsync(TimeSpan pollingInterval, CancellationToken cancellationToken);
}
```
### Python
//Async
```python
async def delete_certificate(self, certificate_name: str, **kwargs: "**Any") -> DeletedCertificate
```

//Sync
```python
# This LROPoller has a non-blocking result() call
def begin_delete_certificate(self, certificate_name, **kwargs) -> LROPoller[DeletedCertificate]
```
### JS/TS
```ts
  public async beginDeleteCertificate(
    certificateName: string,
    options: BeginDeleteCertificateOptions = {}
  ): Promise<PollerLike<PollOperationState<DeletedCertificate>, DeletedCertificate>>
```

## Scenario - Get Deleted Certificate
### Usage

### Java
```java
//Async
certificateAsyncClient.getDeletedCertificate("certificateName")
    .subscribe(deletedSecretResponse ->
        System.out.printf("Deleted Certificate's Recovery Id %s %n", deletedSecretResponse.recoveryId()));

//Sync
DeletedCertificate deletedCertificate = certificateClient.getDeletedCertificate("certificateName");
System.out.printf("Deleted certificate with name %s and recovery id %s", deletedCertificate.name(),
    deletedCertificate.recoveryId());
```
### JS/TS
 ```ts
client.getDeletedCertificate("MyDeletedCertificate");
```

### API
### Java
```java
//Async
public Mono<DeletedCertificate> getDeletedCertificate(String name) {}
public Mono<Response<DeletedCertificate>> getDeletedCertificateWithResponse(String name) {}
    
//Sync
public DeletedCertificate getDeletedCertificate(String name) {}
public Response<DeletedCertificate> getDeletedCertificateWithResponse(String name, Context context) {}
```

### .NET
```c#
public virtual Response<DeletedCertificate> GetDeletedCertificate(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<Response<DeletedCertificate>> GetDeletedCertificateAsync(string certificateName, CancellationToken cancellationToken = default);
```
### Python
```python
async def get_deleted_certificate(self, certificate_name: str, **kwargs: "**Any") -> DeletedCertificate
```
### JS/TS
```ts
  public async getDeletedCertificate(
    certificateName: string,
    options: GetDeletedCertificateOptions = {}
  ): Promise<DeletedCertificate>
```

## Scenario - Recover Deleted Certificate
### Usage
### Java
```java
//Async
certificateAsyncClient.recoverDeletedCertificate("deletedCertificateName")
    .subscribe(recoveredCert ->
        System.out.printf("Recovered Certificate with name %s %n", recoveredCert.name()));

//Sync
Certificate certificate = certificateClient.recoverDeletedCertificate("deletedCertificateName");
System.out.printf(" Recovered Deleted certificate with name %s and id %s", certificate.name(),
    certificate.id());
```
### JS/TS
 ```ts
await client.recoverDeletedCertificate("MyCertificate")
```

### API
### Java
```java
public PollerFlux<KeyVaultCertificate, Void> beginRecoverDeletedCertificate(String name) {}

public SyncPoller<KeyVaultCertificate, Void> beginRecoverDeletedCertificate(String name) {}
```

### .NET
```c#
public virtual RecoverDeletedCertificateOperation StartRecoverDeletedCertificate(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<RecoverDeletedCertificateOperation> StartRecoverDeletedCertificateAsync(string certificateName, CancellationToken cancellationToken = default);

public class RecoverDeletedCertificateOperation : Operation<KeyVaultCertificateWithPolicy> {
    public override bool HasCompleted { get; }
    public override bool HasValue { get; }
    public override string Id { get; }
    public override KeyVaultCertificateWithPolicy Value { get; }
    public override Response GetRawResponse();
    public override Response UpdateStatus(CancellationToken cancellationToken = default);
    public override ValueTask<Response> UpdateStatusAsync(CancellationToken cancellationToken = default);
    public override ValueTask<Response<KeyVaultCertificateWithPolicy>> WaitForCompletionAsync(CancellationToken cancellationToken = default);
    public override ValueTask<Response<KeyVaultCertificateWithPolicy>> WaitForCompletionAsync(TimeSpan pollingInterval, CancellationToken cancellationToken);
}
```
### Python

//Async
```python
async def recover_deleted_certificate(self, certificate_name: str, **kwargs: "**Any") -> KeyVaultCertificate:
```
//Sync
```python
def begin_recover_deleted_certificate(self, certificate_name, **kwargs) -> KeyVaultCertificate
```
### JS/TS
```ts
  public async beginRecoverDeletedCertificate(
    certificateName: string,
    options: BeginRecoverDeletedCertificateOptions = {}
  ): Promise<PollerLike<PollOperationState<KeyVaultCertificate>, KeyVaultCertificate>>
```

## Scenario - Purge Delete Certificate
### Usage
### Java
```java
//Async
certificateAsyncClient.purgeDeletedCertificate("deletedCertificateName")
    .doOnSuccess(response -> System.out.println("Successfully Purged certificate"));

//Sync
certificateClient.purgeDeletedCertificate("certificateName");
```
### python
 ```python

# async
print("\n.. Purge Deleted Certificate")
await client.purge_deleted_certificate(storage_cert_name)
print("Certificate has been permanently deleted.")

# sync
print("\n.. Purge Deleted Certificate")
client.purge_deleted_certificate(storage_cert_name)
print("Certificate has been permanently deleted.")
```

### API
### Java
```java
public Mono<Void> purgeDeletedCertificate(String name);
public Mono<Response<Void>> purgeDeletedCertificateWithResponse(String name);

public void purgeDeletedCertificate(String name) {}
public Response<Void> purgeDeletedCertificateWithResponse(String name, Context context) {}
```

### .NET
```c#
public virtual Response PurgeDeletedCertificate(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<Response> PurgeDeletedCertificateAsync(string certificateName, CancellationToken cancellationToken = default);
```
### Python
```python
async def purge_deleted_certificate(self, certificate_name: str, **kwargs: "**Any") -> None:
```
### JS/TS
```ts
  public async purgeDeletedCertificate(
    certificateName: string,
    options: PurgeDeletedCertificateOptions = {}
  ): Promise<null>
```

## Scenario - Backup Certificate
### Usage
### Java
```java
//Async
certificateAsyncClient.backupCertificate("certificateName")
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(certificateBackupResponse ->
        System.out.printf("Certificate's Backup Byte array's length %s %n", certificateBackupResponse.length));

//Sync
byte[] certificateBackup = certificateClient.backupCertificate("certificateName");
System.out.printf("Backed up certificate with back up blob length %d", certificateBackup.length);
```

### python
 ```python

# async
print("\n.. Create a backup for an existing certificate")
certificate_backup = await client.backup_certificate(cert_name)
print("Backup created for certificate with name '{0}'.".format(cert_name))

# sync
print("\n.. Create a backup for an existing certificate")
certificate_backup = client.backup_certificate(cert_name)
print("Backup created for certificate with name '{0}'.".format(cert_name))
```

### API
### Java
```java
public Mono<byte[]> backupCertificate(String name);
public Mono<Response<byte[]>> backupCertificateWithResponse(String name);


public byte[] backupCertificate(String name);
public Response<byte[]> backupCertificateWithResponse(String name, Context context);

```

### .NET
```c#
public virtual Response<byte[]> BackupCertificate(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<Response<byte[]>> BackupCertificateAsync(string certificateName, CancellationToken cancellationToken = default);
```
### Python
```python
async def backup_certificate(self, certificate_name: str, **kwargs: "**Any") -> bytes:
```
### JS/TS
```ts
  public async backupCertificate(
    certificateName: string,
    options: BackupCertificateOptions = {}
  ): Promise<BackupCertificateResult>
```

## Scenario - Restore Certificate
### Usage
### Java
```java
//Async
certificateAsyncClient.restoreCertificate(certificateBackupByteArray)
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(certificateResponse -> System.out.printf("Restored Certificate with name %s and key id %s %n",
        certificateResponse.name(), certificateResponse.keyId()));

//Sync
byte[] certificateBackupBlob = {};
Certificate certificate = certificateClient.restoreCertificate(certificateBackupBlob);
System.out.printf(" Restored certificate with name %s and id %s", certificate.name(), certificate.id());
```

### python
 ```python

# async
print("\n.. Restore the certificate using the backed up certificate bytes")
certificate = await client.restore_certificate_backup(certificate_backup)
print("Restored Certificate with name '{0}'".format(certificate.name))

# sync
print("\n.. Restore the certificate from the backup")
certificate = client.restore_certificate_backup(certificate_backup)
print("Restored Certificate with name '{0}'".format(certificate.name))
```

### API
### Java
```java
public Mono<KeyVaultCertificate> restoreCertificateBackup(byte[] backup) {}
public Mono<Response<KeyVaultCertificate>> restoreCertificateBackupWithResponse(byte[] backup) {}

public KeyVaultCertificate restoreCertificateBackup(byte[] backup) {}
public Response<KeyVaultCertificate> restoreCertificateBackupWithResponse(byte[] backup, Context context) {}
```

### .NET
```c#
public virtual Response<KeyVaultCertificateWithPolicy> RestoreCertificateBackup(byte[] backup, CancellationToken cancellationToken = default);
public virtual Task<Response<KeyVaultCertificateWithPolicy>> RestoreCertificateBackupAsync(byte[] backup, CancellationToken cancellationToken = default);
```
### Python
```python
async def restore_certificate_backup(self, backup: bytes, **kwargs: "**Any") -> KeyVaultCertificate:
```
### JS/TS
```ts
  public async restoreCertificateBackup(
    certificateBackup: Uint8Array,
    options: RestoreCertificateBackupOptions = {}
  ): Promise<KeyVaultCertificate>
```

## Scenario - List Ceriticates
### Usage

### python
 ```python
# async
print("\n.. List certificates from the Key Vault")
certificates = client.list_properties_of_certificates()
async for certificate in certificates:
    print("Certificate with name '{0}' was found.".format(certificate.name))

# sync
print("\n.. List certificates from the Key Vault")
certificates = client.list_properties_of_certificates()
for certificate in certificates:
    print("Certificate with name '{0}' was found.".format(certificate.name))
```

### API
### Java
```java
public PagedFlux<CertificateProperties> listPropertiesOfCertificates(Boolean includePending) {}
public PagedFlux<CertificateProperties> listPropertiesOfCertificates() {}

public PagedIterable<CertificateProperties> listPropertiesOfCertificates() {}
public PagedIterable<CertificateProperties> listPropertiesOfCertificates(boolean includePending, Context context) {}
```

### .NET
```c#
public virtual Pageable<CertificateProperties> GetPropertiesOfCertificates(bool includePending = false, CancellationToken cancellationToken = default);
public virtual AsyncPageable<CertificateProperties> GetPropertiesOfCertificatesAsync(bool includePending = false, CancellationToken cancellationToken = default);
```
### Python
```python
def list_properties_of_certificates(self, **kwargs: "**Any") -> AsyncIterable[CertificateProperties]:
```
### JS/TS
```ts
  public listPropertiesOfCertificates(
    options: ListPropertiesOfCertificatesOptions = {}
  ): PagedAsyncIterableIterator<CertificateProperties, CertificateProperties[]>
```

## Scenario - List Ceriticate Versions
### Usage

### python
 ```python
# async
print("\n.. List versions of the certificate using its name")
certificate_versions = client.list_properties_of_certificate_versions(bank_cert_name)
async for certificate_version in certificate_versions:
    print(
        "Bank Certificate with name '{0}' with version '{1}' has tags: '{2}'.".format(
            certificate_version.name, certificate_version.version, certificate_version.tags
        )
    )

# sync
print("\n.. List versions of the certificate using its name")
certificate_versions = client.list_properties_of_certificate_versions(bank_cert_name)
for certificate_version in certificate_versions:
    print(
        "Bank Certificate with name '{0}' with version '{1}' has tags: '{2}'.".format(
            certificate_version.name, certificate_version.version, certificate_version.tags
        )
    )
```
### API
### Java
```java
public PagedFlux<CertificateProperties> listPropertiesOfCertificateVersions(String name) {}
    
public PagedIterable<CertificateProperties> listPropertiesOfCertificateVersions(String name) {}
public PagedIterable<CertificateProperties> listPropertiesOfCertificateVersions(String name, Context context) {}
```

### .NET
```c#
public virtual Pageable<CertificateProperties> GetPropertiesOfCertificateVersions(string certificateName, CancellationToken cancellationToken = default);
public virtual AsyncPageable<CertificateProperties> GetPropertiesOfCertificateVersionsAsync(string certificateName, CancellationToken cancellationToken = default);
```
### Python
```python
def list_properties_of_certificate_versions(
    self, certificate_name: str, **kwargs: "**Any"
) -> AsyncIterable[CertificateProperties]:
```
### JS/TS
```ts
  public listPropertiesOfCertificateVersions(
    certificateName: string,
    options: ListPropertiesOfCertificateVersionsOptions = {}
  ): PagedAsyncIterableIterator<CertificateProperties, CertificateProperties[]>
```

## Scenario - List Deleted Certificates
### Usage
### python
 ```python
# async
print("\n.. List deleted certificates from the Key Vault")
deleted_certificates = client.list_deleted_certificates()
async for deleted_certificate in deleted_certificates:
    print(
        "Certificate with name '{0}' has recovery id '{1}'".format(
            deleted_certificate.name, deleted_certificate.recovery_id
        )
    )

# sync
print("\n.. List deleted certificates from the Key Vault")
deleted_certificates = client.list_deleted_certificates()
for deleted_certificate in deleted_certificates:
    print(
        "Certificate with name '{0}' has recovery id '{1}'".format(
            deleted_certificate.name, deleted_certificate.recovery_id
        )
    )
```

### API
### Java
```java
public PagedFlux<DeletedCertificate> listDeletedCertificates();

public PagedIterable<DeletedCertificate> listDeletedCertificates();
public PagedIterable<DeletedCertificate> listDeletedCertificates(Context context);
```

### .NET
```c#
public virtual Pageable<DeletedCertificate> GetDeletedCertificates(bool includePending = false, CancellationToken cancellationToken = default);
public virtual AsyncPageable<DeletedCertificate> GetDeletedCertificatesAsync(bool includePending = false, CancellationToken cancellationToken = default);
```

### Python
```python
def list_deleted_certificates(self, **kwargs: "**Any") -> AsyncIterable[DeletedCertificate]:
```

### JS/TS
```javascript
  public listDeletedCertificates(
    options: ListDeletedCertificatesOptions = {}
  ): PagedAsyncIterableIterator<DeletedCertificate, DeletedCertificate[]>
```


## Scenario - Create Certificate Issuer
Discuss - Create vs Set
### Usage
### java
```java
//Async
certificateAsyncClient.createIssuer("issuerName", "providerName")
    .subscribe(issuer -> {
        System.out.printf("Issuer created with %s and %s", issuer.name(), issuer.provider());
    });

//Sync
Issuer issuerToCreate = new Issuer("myissuer", "myProvider")
    .administrators(Arrays.asList(new Administrator("test", "name", "test@example.com")));
Issuer returnedIssuer = certificateClient.createIssuer(issuerToCreate);
System.out.printf("Created Issuer with name %s provider %s", returnedIssuer.name(), returnedIssuer.provider());
```

### python
 ```python
# async
# First we specify the AdministratorContact for our issuers.
admin_details = [
    AdministratorContact(first_name="John", last_name="Doe", email="admin@microsoft.com", phone="4255555555")
]

# Next we create an issuer with these administrator details
# The name field refers to the name you would like to get the issuer. There are also pre-set names, such as 'Self' and 'Unknown'
await client.create_issuer(
    issuer_name="issuer1", provider="Test", account_id="keyvaultuser", admin_details=admin_details, enabled=True
)

# sync
client.create_issuer(
    issuer_name="issuer1", provider="Test", account_id="keyvaultuser", admin_details=admin_details, enabled=True
)
```
### JS/TS
```ts
await client.createIssuer("IssuerName", "Provider");
```

### API
### Java
```java
public Mono<CertificateIssuer> createIssuer(String name, String provider);
public Mono<CertificateIssuer> createIssuer(CertificateIssuer issuer);
public Mono<Response<CertificateIssuer>> createIssuerWithResponse(CertificateIssuer issuer);

public CertificateIssuer createIssuer(String name, String provider);
public CertificateIssuer createIssuer(CertificateIssuer issuer);
public Response<CertificateIssuer> createIssuerWithResponse(CertificateIssuer issuer, Context context)
```

### .NET
```c#
public virtual Response<CertificateIssuer> CreateIssuer(CertificateIssuer issuer, CancellationToken cancellationToken = default);
public virtual Task<Response<CertificateIssuer>> CreateIssuerAsync(CertificateIssuer issuer, CancellationToken cancellationToken = default);
```
### Python
```python
async def create_issuer(
    self, issuer_name: str, provider: str, **kwargs: "**Any"
) -> CertificateIssuer:
```
### JS/TS
```javascript
  public async createIssuer(
    issuerName: string,
    provider: string,
    options: CreateIssuerOptions = {}
  ): Promise<CertificateIssuer>
```

## Scenario - Get Certificate Issuer
### Usage
### java
```java
//Async
certificateAsyncClient.getIssuer("issuerName")
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(issuer -> {
        System.out.printf("Issuer returned with %s and %s", issuer.name(), issuer.provider());
    });

//Sync
Response<Issuer> issuerResponse = certificateClient.getIssuerWithResponse("issuerName",
    new Context(key1, value1));
System.out.printf("Retrieved issuer with name %s and prodier %s", issuerResponse.getValue().name(),
    issuerResponse.getValue().provider());
```

### python
 ```python
# async
issuer1 = await client.get_issuer("issuer1")

print(issuer1.name)
print(issuer1.properties.provider)
print(issuer1.account_id)

# sync
issuer1 = client.get_issuer(issuer_name="issuer1")

print(issuer1.name)
print(issuer1.properties.provider)
print(issuer1.account_id)
```
### JS/TS
```ts
const certificateIssuer = await client.getIssuer("IssuerName");
console.log(certificateIssuer);
```

### API
### Java
```java
public Mono<Response<CertificateIssuer>> getIssuerWithResponse(String name);
public Mono<CertificateIssuer> getIssuer(String name);

public Response<CertificateIssuer> getIssuerWithResponse(String name, Context context);
public CertificateIssuer getIssuer(String name);
```

### .NET
```c#
public virtual Response<CertificateIssuer> GetIssuer(string issuerName, CancellationToken cancellationToken = default);
public virtual Task<Response<CertificateIssuer>> GetIssuerAsync(string issuerName, CancellationToken cancellationToken = default);
```
### Python
```python
async def get_issuer(self, issuer_name: str, **kwargs: "**Any") -> CertificateIssuer:
```
### JS/TS
```ts
  public async getIssuer(
    issuerName: string,
    options: GetIssuerOptions = {}
  ): Promise<CertificateIssuer>
```

## Scenario - Delete Certificate Issuer
### Usage
### java
```java
//Async
certificateAsyncClient.deleteCertificateIssuerWithResponse("issuerName")
    .subscribe(deletedIssuerResponse ->
        System.out.printf("Deleted issuer with name %s %n", deletedIssuerResponse.getValue().name()));

//Sync
Issuer deletedIssuer = certificateClient.deleteIssuer("certificateName");
System.out.printf("Deleted certificate issuer with name %s and provider id %s", deletedIssuer.name(),
    deletedIssuer.provider());
```

### python
 ```python
# async
await client.delete_issuer(issuer_name="issuer1")

# sync
client.delete_issuer(issuer_name="issuer1")
```
### JS/TS
```ts
await client.deleteIssuer("IssuerName");
```

### API
### Java
```java
public Mono<Response<CertificateIssuer>> deleteIssuerWithResponse(String name);
public Mono<CertificateIssuer> deleteIssuer(String name);


public Response<CertificateIssuer> deleteIssuerWithResponse(String name, Context context);
public CertificateIssuer deleteIssuer(String name);
```

### .NET
```c#
public virtual Response<CertificateIssuer> DeleteIssuer(string issuerName, CancellationToken cancellationToken = default);
public virtual Task<Response<CertificateIssuer>> DeleteIssuerAsync(string issuerName, CancellationToken cancellationToken = default);
```
### Python
```python
async def delete_issuer(self, issuer_name: str, **kwargs: "**Any") -> CertificateIssuer:

```
### JS/TS
```ts
  public async deleteIssuer(
    issuerName: string,
    options: DeleteIssuerOptions = {}
  ): Promise<CertificateIssuer>
```


## Scenario - List Certificate Issuers
### Usage
### java
```java
//Async
certificateAsyncClient.listIssuers()
    .subscribe(issuerProps -> certificateAsyncClient.getCertificateIssuer(issuerProps)
        .subscribe(issuerResponse -> System.out.printf("Received issuer with name %s and provider %s",
            issuerResponse.name(), issuerResponse.provider())));

//Sync
for (IssuerProperties issuerProps : certificateClient.listIssuers()) {
    Issuer retrievedIssuer = certificateClient.getCertificateIssuer(issuerProps);
    System.out.printf("Received issuer with name %s and provider %s", retrievedIssuer.name(),
        retrievedIssuer.provider());
}
```

### python
 ```python
# async
issuers = client.list_properties_of_issuers()

async for issuer in issuers:
    print(issuer.name)
    print(issuer.provider)
# sync
issuers = client.list_properties_of_issuers()

for issuer in issuers:
    print(issuer.name)
    print(issuer.provider)
```

### JS/TS
```ts
// All in one call
for await (const issuer of client.listIssuers()) {
 console.log(issuer);
}
```

### API
### Java
```java
public PagedFlux<IssuerProperties> listPropertiesOfIssuers() {}

public PagedIterable<IssuerProperties> listPropertiesOfIssuers() {}
public PagedIterable<IssuerProperties> listPropertiesOfIssuers(Context context) {}
```

### .NET
```c#
public virtual Pageable<IssuerProperties> GetPropertiesOfIssuers(CancellationToken cancellationToken = default);
public virtual AsyncPageable<IssuerProperties> GetPropertiesOfIssuersAsync(CancellationToken cancellationToken = default);
```
### Python
```python
def list_properties_of_issuers(self, **kwargs: "**Any") -> AsyncIterable[IssuerProperties]:
```
### JS/TS
```ts
  public listPropertiesOfIssuers(
    options: ListPropertiesOfIssuersOptions = {}
  ): PagedAsyncIterableIterator<IssuerProperties, IssuerProperties[]>
```

## Scenario - Update Certificate Issuer
### Usage
### java
```java
//Async
certificateAsyncClient.getIssuer("issuerName")
    .subscribe(issuer -> {
        issuer.setAdministrators(Arrays.asList(new Administrator("test", "name", "test@example.com")));
        certificateAsyncClient.updateCertificateIssuer(issuer)
            .subscribe(issuerResponse ->
                System.out.printf("Updated issuer with name %s, provider %s",
                    issuerResponse.name(), issuerResponse.provider()));
    });

//Sync
Issuer returnedIssuer = certificateClient.getIssuer("issuerName");
returnedIssuer.setAdministrators(Arrays.asList(new Administrator("test", "name", "test@example.com")));
Issuer updatedIssuer = certificateClient.updateIssuer(returnedIssuer);
System.out.printf("Updated issuer with name %s, provider %s and account Id %s", updatedIssuer.name(),
    updatedIssuer.provider(), updatedIssuer.accountId());
```

### JS/TS
```ts
await client.updateCertificateIssuer("IssuerName", {
    provider: "Provider2"
});
```

### API
### Java
```java
public Mono<CertificateIssuer> updateIssuer(CertificateIssuer issuer);
public Mono<Response<CertificateIssuer>> updateIssuerWithResponse(CertificateIssuer issuer);

public CertificateIssuer updateIssuer(CertificateIssuer issuer);
public Response<CertificateIssuer> updateIssuerWithResponse(CertificateIssuer issuer, Context context);
```

### .NET
```c#
public virtual Response<CertificateIssuer> UpdateIssuer(CertificateIssuer issuer, CancellationToken cancellationToken = default);
public virtual Task<Response<CertificateIssuer>> UpdateIssuerAsync(CertificateIssuer issuer, CancellationToken cancellationToken = default);
```
### Python
```python
async def update_issuer(self, issuer_name: str, **kwargs: "**Any") -> CertificateIssuer:
```
### JS/TS
```ts
  public async updateIssuer(
    issuerName: string,
    options: UpdateIssuerOptions = {}
  ): Promise<CertificateIssuer>
```



## Scenario - Get Certificate Operation

### Usage
### JS/TS
```ts
   const client = new CertificateClient(url, credentials);
   await client.beginCreateCertificate("MyCertificate", {
     issuerName: "Self",
     subject: "cn=MyCert"
   });
   const poller = await client.getCertificateOperation("MyCertificate");
   const pendingCertificate = poller.getResult();
   console.log(pendingCertificate);
   const certificateOperation = poller.getResult();
   console.log(certificateOperation);
```
### API
### Java
```java
public PollerFlux<CertificateOperation, KeyVaultCertificate> getCertificateOperation(String name) {}

public SyncPoller<CertificateOperation, KeyVaultCertificate> getCertificateOperation(String name) {}
```

### .NET
```c#
public virtual CertificateOperation GetCertificateOperation(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<CertificateOperation> GetCertificateOperationAsync(string certificateName, CancellationToken cancellationToken = default);
```
### Python
```python
async def get_certificate_operation(self, certificate_name: str, **kwargs: "**Any") -> CertificateOperation:
```
### JS/TS
```ts
  public async getCertificateOperation(
    certificateName: string,
    options: GetCertificateOperationOptions = {}
  ): Promise<PollerLike<PollOperationState<CertificateOperation>, CertificateOperation>>
```

## Scenario - Cancel Certificate Operation
### Usage
### java
```java
//Async
certificateAsyncClient.cancelCertificateOperation("certificateName")
    .subscribe(certificateOperation -> System.out.printf("Certificate operation status %s",
        certificateOperation.status()));

//Sync
CertificateOperation certificateOperation = certificateClient.cancelCertificateOperation("certificateName");
System.out.printf("Certificate Operation status %s", certificateOperation.status());
```

### JS/TS
```ts
await client.cancelCertificateOperation("MyCertificate");
```
### API
### Java
```java

--------- REMOVED------------------
public Mono<CertificateOperation> cancelCertificateOperation(String certificateName);
public Mono<Response<CertificateOperation>> cancelCertificateOperation(String certificateName);

public CertificateOperation cancelCertificateOperation(String certificateName);
public Response<CertificateOperation> cancelCertificateOperation(String certificateName);
```

### .NET
```c#
public class CertificateOperation : Operation<KeyVaultCertificateWithPolicy>
{
    public virtual void Cancel(CancellationToken cancellationToken = default);
    public virtual Task CancelAsync(CancellationToken cancellationToken = default);
}
```
### Python
```python
async def cancel_certificate_operation(self, certificate_name: str, **kwargs: "**Any") -> CertificateOperation:
```
### JS/TS
```ts
  public async cancelCertificateOperation(
    certificateName: string,
    options: CancelCertificateOperationOptions = {}
  ): Promise<CertificateOperation>
```

## Scenario - Delete Certificate Operation
### Usage
### java
```java
//Async
certificateAsyncClient.deleteCertificateOperationWithResponse("certificateName")
    .subscribe(certificateOperationResponse -> System.out.printf("Deleted Certificate operation's last"
        + " status %s", certificateOperationResponse.getValue().status()));

//Sync
CertificateOperation deletedCertificateOperation = certificateClient.deleteCertificateOperation("certificateName");
System.out.printf("Deleted Certificate Operation's last status %s", deletedCertificateOperation.status());
```

### JS/TS
```ts
await client.deleteCertificateOperation("MyCertificate");
```

### API
### Java
```java
public Mono<CertificateOperation> deleteCertificateOperation(String certificateName);
public Mono<Response<CertificateOperation>> deleteCertificateOperation(String certificateName);

public CertificateOperation deleteCertificateOperation(String certificateName);
public Response<CertificateOperation> deleteCertificateOperation(String certificateName);
```

### .NET
```c#
public class CertificateOperation : Operation<KeyVaultCertificateWithPolicy>
{
    public virtual void Delete(CancellationToken cancellationToken = default);
    public virtual Task DeleteAsync(CancellationToken cancellationToken = default);
}
```
### Python
```python
async def delete_certificate_operation(self, certificate_name: str, **kwargs: "**Any") -> CertificateOperation:
```
### JS/TS
```ts
 public async deleteCertificateOperation(
    name: string,
    options?: RequestOptionsBase
  ): Promise<CertificateOperation>
```



## Scenario - Set Certificate Contacts
### Usage
### java
```java
//Async
Contact contactToAdd = new Contact("user", "useremail@exmaple.com");
certificateAsyncClient.setContacts(Arrays.asList(contactToAdd)).subscribe(contact ->
    System.out.printf("Contact name %s and email %s", contact.name(), contact.emailAddress())
);

//Sync
Contact contactToAdd = new Contact("user", "useremail@exmaple.com");
for (Contact contact : certificateClient.setContacts(Arrays.asList(contactToAdd))) {
    System.out.printf("Added contact with name %s and email %s to key vault", contact.name(),
        contact.emailAddress());
}
```

### JS/TS
 ```ts
   let client = new CertificateClient(url, credentials);
   await client.setContacts([{
     emailAddress: "b@b.com",
     name: "b",
     phone: "222222222222"
   }]);
```

### API
### Java
```java
public PagedFlux<CertificateContact> setContacts(List<CertificateContact> contacts);

public PagedIterable<CertificateContact> setContacts(List<CertificateContact> contacts);
public PagedIterable<CertificateContact> setContacts(List<CertificateContact> contacts, Context context);
```

### .NET
```c#
public virtual Response<IList<CertificateContact>> SetContacts(IEnumerable<CertificateContact> contacts, CancellationToken cancellationToken = default);
public virtual Task<Response<IList<CertificateContact>>> SetContactsAsync(IEnumerable<CertificateContact> contacts, CancellationToken cancellationToken = default);
```
### Python
```python
async def create_contacts(
    self, contacts: Iterable[CertificateContact], **kwargs: "**Any"
) -> List[CertificateContact]:
```
### JS/TS
```ts
  public async setContacts(
    contacts: Contact[],
    options: SetContactsOptions = {}
  ): Promise<CertificateContacts>
```

## Scenario - List Certificate Contacts
### Usage
### java
```java
//Async
certificateAsyncClient.listContacts().subscribe(contact ->
    System.out.printf("Contact name %s and email %s", contact.name(), contact.emailAddress())
);

//Sync
for (Contact contact : certificateClient.listContacts()) {
    System.out.printf("Added contact with name %s and email %s to key vault", contact.name(),
        contact.emailAddress());
}
```

### JS/TS
 ```ts
const getResponse = await client.getContacts();
console.log(getResponse.contactList!);
```

### API
### Java
```java
public PagedFlux<CertificateContact> listContacts();

public PagedIterable<CertificateContact> listContacts();
public PagedIterable<CertificateContact> listContacts(Context context);
```

### .NET
```c#
public virtual Response<IList<CertificateContact>> GetContacts(CancellationToken cancellationToken = default);
public virtual Task<Response<IList<CertificateContact>>> GetContactsAsync(CancellationToken cancellationToken = default);
```
### Python
```python
async def get_contacts(self, **kwargs: "**Any") -> List[CertificateContact]:
```
### JS/TS
```ts
public async getContacts(options?: RequestOptionsBase): Promise<Contacts>
```

## Scenario - Delete Certificate Contacts
### Usage
### java
```java
//Async
certificateAsyncClient.deleteContacts().subscribe(contact ->
    System.out.printf("Deleted Contact name %s and email %s", contact.name(), contact.emailAddress())
);

//Sync
for (CertificateContact contact : certificateClient.deleteContacts()) {
    System.out.printf("Deleted contact with name %s and email %s from key vault", contact.name(),
        contact.emailAddress());
}
```

### JS/TS
 ```ts
await client.deleteContacts();
```

### API

### Java
```java
public PagedFlux<CertificateContact> deleteContacts();

public PagedIterable<CertificateContact> deleteContacts();
public PagedIterable<CertificateContact> deleteContacts(Context context);
```

### .NET
```c#
public virtual Response<IList<CertificateContact>> DeleteContacts(CancellationToken cancellationToken = default);
public virtual Task<Response<IList<CertificateContact>>> DeleteContactsAsync(CancellationToken cancellationToken = default);
```
### Python
```python
async def delete_contacts(self, **kwargs: "**Any") -> List[CertificateContact]:
```
### JS/TS
```ts
public async deleteContacts(options: DeleteContactsOptions = {}): Promise<CertificateContacts>
```

## ~Scenario - Get Certificate Signing Request~

## Scenario - Merge Certificate
### Usage
### java
 ```java
 ```

### JS/TS
 ```ts
const client = new CertificatesClient(url, credentials);
await client.createCertificate("MyCertificate", {
  issuerParameters: {
    name: "Unknown",
    certificateTransparency: false
   },
   x509CertificateProperties: { subject: "cn=MyCert" }
 });
const { csr } = await client.getCertificateOperation(certificateName);
const base64Csr = Buffer.from(csr!).toString("base64");
const wrappedCsr = ["-----BEGIN CERTIFICATE REQUEST-----", base64Csr, "-----END CERTIFICATE REQUEST-----"].join("\n");
fs.writeFileSync("test.csr", wrappedCsr);

// Certificate available locally made using:
// openssl genrsa -out ca.key 2048
// openssl req -new -x509 -key ca.key -out ca.crt
// You can read more about how to create a fake certificate authority here: https://gist.github.com/Soarez/9688998
childProcess.execSync("openssl x509 -req -in test.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out test.crt");
const base64Crt = fs.readFileSync("test.crt").toString().split("\n").slice(1, -1).join("");

await client.mergeCertificate(certificateName, [Buffer.from(base64Crt)]);
```
### API
### Java
```java
public Mono<KeyVaultCertificate> mergeCertificate(MergeCertificateOptions mergeCertificateOptions);
public Mono<Response<KeyVaultCertificate>> mergeCertificateWithResponse(MergeCertificateOptions mergeCertificateOptions);

public KeyVaultCertificate mergeCertificate(MergeCertificateOptions mergeCertificateOptions) {}
public Response<KeyVaultCertificate> mergeCertificateWithResponse(MergeCertificateOptions mergeCertificateOptions, Context context) {}
```

### .NET
```c#
public virtual Response<KeyVaultCertificateWithPolicy> MergeCertificate(MergeCertificateOptions mergeCertificateOptions, CancellationToken cancellationToken = default);
public virtual Task<Response<KeyVaultCertificateWithPolicy>> MergeCertificateAsync(MergeCertificateOptions mergeCertificateOptions, CancellationToken cancellationToken = default);
```
### Python
```python
async def merge_certificate(
    self, certificate_name: str, x509_certificates: List[bytearray], **kwargs: "**Any"
) -> KeyVaultCertificate:
```
### JS/TS
```ts
  public async mergeCertificate(
    certificateName: string,
    x509Certificates: Uint8Array[],
    options: MergeCertificateOptions = {}
  ): Promise<KeyVaultCertificate>
```

## Scenario - Import Certificate
### Usage
```ts
const client = new CertificatesClient(url, credentials);
const certificateSecret = await secretsClient.getSecret("MyCertificate");
const base64EncodedCertificate = certificateSecret.value!;
await client.importCertificate("MyCertificate", base64EncodedCertificate);
```

### Java
```java
public Mono<KeyVaultCertificate> importCertificate(CertificateImportOptions importOptions) {}
public Mono<Response<KeyVaultCertificate>> importCertificateWithResponse(CertificateImportOptions importOptions) {}

public KeyVaultCertificate importCertificate(CertificateImportOptions importOptions) {}
public Response<KeyVaultCertificate> importCertificateWithResponse(CertificateImportOptions importOptions, Context context) {}
```

### .NET
```c#
public virtual Response<KeyVaultCertificateWithPolicy> ImportCertificate(ImportCertificateOptions importCertificateOptions, CancellationToken cancellationToken = default);
public virtual Task<Response<KeyVaultCertificateWithPolicy>> ImportCertificateAsync(ImportCertificateOptions importCertificateOptions, CancellationToken cancellationToken = default);
```

### Python
```python
async def import_certificate(
        self, certificate_name: str, certificate_bytes: bytes, **kwargs: "**Any"
    ) -> KeyVaultCertificate:
```
### JS/TS
```ts
  public async importCertificate(
    certificateName: string,
    base64EncodedCertificate: string,
    options: ImportCertificateOptions = {}
  ): Promise<KeyVaultCertificate>
```

## Certifciates Datastructures Design
## KeyVaultCertificate
### .NET
```c#
public class KeyVaultCertificate : IJsonDeserializable {
    public byte[] Cer { get; }
    public CertificateContentType ContentType { get; }
    public Uri Id { get; }
    public Uri KeyId { get; }
    public string Name { get; }
    public CertificateProperties Properties { get; }
    public Uri SecretId { get; }
}
```

### Java
```java
public class KeyVaultCertificate {
    public CertificateProperties getProperties() {}
    public KeyVaultCertificate setProperties(CertificateProperties properties) {}
    public String getId() {}
    public String getName() {}
    public String getKeyId() {}
    public String getSecretId() {}
    public byte[] getCer() {}
}
```

### Python
```python
def __init__(
    self,
    policy,  # type: CertificatePolicy
    properties=None,  # type: Optional[CertificateProperties]
    cer=None,  # type: Optional[bytes]
    **kwargs  # type: Any
):
    # type: (...) -> None
    self._properties = properties
    self._key_id = kwargs.get("key_id", None)
    self._secret_id = kwargs.get("secret_id")
    self._policy = policy
    self._cer = cer
```
### JS/TS
```ts

```

## KeyVaultCertificateWithPolicy
### .NET
```c#
public class KeyVaultCertificateWithPolicy : KeyVaultCertificate {
    public CertificatePolicy Policy { get; }
}
```

### Java
```java
public class KeyVaultCertificateWithPolicy extends KeyVaultCertificate {
    public CertificateProperties getProperties() {}
    public KeyVaultCertificateWithPolicy setProperties(CertificateProperties properties) {}
    public CertificatePolicy getCertificatePolicy() {}
    public KeyVaultCertificateWithPolicy setCertificatePolicy(CertificatePolicy certificatePolicy) {}
}
```

### Python
```python
N/A

```
### JS/TS
```ts

```

## CertificateProperties
### .NET
```c#
public class CertificateProperties : IJsonDeserializable {
    public CertificateProperties(string name);
    public CertificateProperties(Uri id);
    public DateTimeOffset? CreatedOn { get; }
    public bool? Enabled { get; set; }
    public DateTimeOffset? ExpiresOn { get; }
    public Uri Id { get; }
    public string Name { get; }
    public DateTimeOffset? NotBefore { get; }
    public string RecoveryLevel { get; }
    public IDictionary<string, string> Tags { get; }
    public DateTimeOffset? UpdatedOn { get; }
    public Uri VaultUri { get; }
    public string Version { get; }
    public byte[] X509Thumbprint { get; }
}
```

### Java
```java
public class CertificateProperties {
    public String getId() {}
    public OffsetDateTime getNotBefore() {}
    public OffsetDateTime getExpiresOn() {}
    public OffsetDateTime getCreatedOn() {}
    public OffsetDateTime getUpdatedOn() {}
    public Map<String, String> getTags() {}
    public CertificateProperties setTags(Map<String, String> tags) {}
    public String getVersion() {}
    public String getName() {}
    public String getRecoveryLevel() {}
    public Boolean isEnabled() {}
    public CertificateProperties setEnabled(Boolean enabled) {}
    public byte[] getX509Thumbprint() {}
}
```

### Python
```python
def __init__(self, **kwargs):
    # type: (**Any) -> None
    self._attributes = kwargs.get("attributes", None)
    self._id = kwargs.get("cert_id", None)
    self._vault_id = parse_vault_id(self._id)
    self._thumbprint = kwargs.get("thumbprint", None)
    self._tags = kwargs.get("tags", None)
```
### JS/TS
```ts

```

## CertificateOperation
### .NET
```c#
public class CertificateOperation : Operation<KeyVaultCertificateWithPolicy> {
    public override bool HasCompleted { get; }
    public override bool HasValue { get; }
    public override string Id { get; }
    public CertificateOperationProperties Properties { get; }
    public override KeyVaultCertificateWithPolicy Value { get; }
    public virtual void Cancel(CancellationToken cancellationToken = default);
    public virtual Task CancelAsync(CancellationToken cancellationToken = default);
    public virtual void Delete(CancellationToken cancellationToken = default);
    public virtual Task DeleteAsync(CancellationToken cancellationToken = default);
    public override Response GetRawResponse();
    public override Response UpdateStatus(CancellationToken cancellationToken = default);
    public override ValueTask<Response> UpdateStatusAsync(CancellationToken cancellationToken = default);
    public override ValueTask<Response<KeyVaultCertificateWithPolicy>> WaitForCompletionAsync(CancellationToken cancellationToken = default);
    public override ValueTask<Response<KeyVaultCertificateWithPolicy>> WaitForCompletionAsync(TimeSpan pollingInterval, CancellationToken cancellationToken);
}

public class CertificateOperationProperties : IJsonDeserializable {
    public bool CancellationRequested { get; }
    public string CertificateSigningRequest { get; }
    public CertificateOperationError Error { get; }
    public Uri Id { get; }
    public string IssuerName { get; }
    public string Name { get; }
    public string RequestId { get; }
    public string Status { get; }
    public string StatusDetails { get; }
    public string Target { get; }
    public Uri VaultUri { get; }
}
```

### Java
```java
public final class CertificateOperation {
    public String getId() {}
    public String getIssuerName() {}
    public String getCertificateType() {}
    public Boolean getCertificateTransparency() {}
    public byte[] getCsr() {}
    public Boolean getCancellationRequested() {}
    public String getStatus() {}
    public String getStatusDetails() {}
    public CertificateOperationError getError() {}
    public String getTarget() {}
    public String getRequestId() {}
}
```

### Python
```python
def __init__(
    self,
    cert_operation_id=None,  # type: Optional[str]
    issuer_name=None,  # type: Optional[str]
    certificate_type=None,  # type: Optional[str]
    certificate_transparency=False,  # type: Optional[bool]
    csr=None,  # type: Optional[bytes]
    cancellation_requested=False,  # type: Optional[bool]
    status=None,  # type: Optional[str]
    status_details=None,  # type: Optional[str]
    error=None,  # type: Optional[models.Error]
    target=None,  # type: Optional[str]
    request_id=None,  # type: Optional[str]
):
    # type: (...) -> None
    self._id = cert_operation_id
    self._vault_id = parse_vault_id(cert_operation_id)
    self._issuer_name = issuer_name
    self._certificate_type = certificate_type
    self._certificate_transparency = certificate_transparency
    self._csr = csr
    self._cancellation_requested = cancellation_requested
    self._status = status
    self._status_details = status_details
    self._error = error
    self._target = target
    self._request_id = request_id
```
### JS/TS
```ts

```


## CertificateOperationError
### .NET
```c#
public class CertificateOperationError : IJsonDeserializable {
    public string Code { get; }
    public CertificateOperationError InnerError { get; }
    public string Message { get; }
}
```

### Java
```java
public class CertificateOperationError {
    public String getCode() {}
    public String getMessage() {}
    public CertificateOperationError getInnerError() {}
}
```

### Python
```python
def __init__(self, code, message, inner_error):
    # type: (str, str, models.Error, **Any) -> None
    self._code = code
    self._message = message
    self._inner_error = inner_error
```
### JS/TS
```ts

```


## DeletedCertificate
### .NET
```c#
public class DeletedCertificate : KeyVaultCertificateWithPolicy {
    public DateTimeOffset? DeletedOn { get; }
    public Uri RecoveryId { get; }
    public DateTimeOffset? ScheduledPurgeDate { get; }
}
```

### Java
```java
public final class DeletedCertificate extends KeyVaultCertificate {
    public String getRecoveryId() {}
    public OffsetDateTime getScheduledPurgeDate() {}
    public OffsetDateTime getDeletedOn() {}
}
```

### Python
```python
def __init__(
    self,
    properties=None,  # type: Optional[CertificateProperties]
    policy=None,  # type: Optional[CertificatePolicy]
    cer=None,  # type: Optional[bytes]
    **kwargs  # type: **Any
):
    # type: (...) -> None
    super(DeletedCertificate, self).__init__(properties=properties, policy=policy, cer=cer, **kwargs)
    self._deleted_date = kwargs.get("deleted_date", None)
    self._recovery_id = kwargs.get("recovery_id", None)
    self._scheduled_purge_date = kwargs.get("scheduled_purge_date", None)
```
### JS/TS
```ts

```

## CertificatePolicy
### .NET
```c#
public class CertificatePolicy : IJsonSerializable, IJsonDeserializable {
    public CertificatePolicy(string subject, string issuerName);
    public CertificatePolicy(SubjectAlternativeNames subjectAlternativeNames, string issuerName);
    public bool? CertificateTransparency { get; set; }
    public string CertificateType { get; set; }
    public CertificateContentType? ContentType { get; set; }
    public DateTimeOffset? CreatedOn { get; }
    public static CertificatePolicy Default { get; }
    public bool? Enabled { get; set; }
    public IList<string> EnhancedKeyUsage { get; }
    public bool? Exportable { get; set; }
    public string IssuerName { get; }
    public CertificateKeyCurveName? KeyCurveName { get; set; }
    public int? KeySize { get; set; }
    public CertificateKeyType? KeyType { get; set; }
    public IList<CertificateKeyUsage> KeyUsage { get; }
    public IList<LifetimeAction> LifetimeActions { get; }
    public bool? ReuseKey { get; set; }
    public string Subject { get; }
    public SubjectAlternativeNames SubjectAlternativeNames { get; }
    public DateTimeOffset? UpdatedOn { get; }
    public int? ValidityInMonths { get; set; }
}
```

### Java
```java
public final class CertificatePolicy {
    public CertificatePolicy(String issuerName, String subjectName) {}
    public CertificatePolicy(String issuerName, SubjectAlternativeNames subjectAlternativeNames) {}
    public List<CertificateKeyUsage> getKeyUsage() {}
    public CertificatePolicy setKeyUsage(CertificateKeyUsage... keyUsage) {}
    public List<String> getEnhancedKeyUsage() {}
    public CertificatePolicy setEnhancedKeyUsage(List<String> ekus) {}
    public Boolean isExportable() {}
    public CertificatePolicy setExportable(Boolean exportable) {}
    public CertificateKeyType getKeyType() {}
    public CertificatePolicy setKeyType(CertificateKeyType keyType) {}
    public Integer getKeySize() {}
    public Boolean isReuseKey() {}
    public CertificatePolicy setReuseKey(Boolean reuseKey) {}
    public CertificateKeyCurveName getKeyCurveName() {}
    public OffsetDateTime getCreatedOn() {}
    public OffsetDateTime getUpdatedOn() {}
    public Boolean isEnabled() {}
    public CertificatePolicy setEnabled(Boolean enabled) {}
    public CertificateContentType getContentType() {}
    public CertificatePolicy setContentType(CertificateContentType contentType) {}
    public CertificatePolicy getSubjectName(String subjectName) {}
    public SubjectAlternativeNames getSubjectAlternativeNames() {}
    public CertificatePolicy setSubjectAlternativeNames(SubjectAlternativeNames subjectAlternativeNames) {}
    public CertificatePolicy setValidityInMonths(Integer validityInMonths) {}
    public CertificatePolicy setKeySize(Integer keySize) {}
    public CertificatePolicy setKeyCurveName(CertificateKeyCurveName keyCurveName) {}
    public CertificatePolicy setIssuerName(String issuerName) {}
    public CertificatePolicy setCertificateType(String certificateType) {}
    public CertificatePolicy setCertificateTransparency(Boolean certificateTransparency) {}
    public String getSubjectName() {}
    public Integer getValidityInMonths() {}
    public String getIssuerName() {}
    public String getCertificateType() {}
    public Boolean isCertificateTransparency() {}
    public CertificatePolicy setLifeTimeActions(LifeTimeAction... actions) {}
    public List<LifeTimeAction> getLifeTimeActions() {}
    public static CertificatePolicy getDefaultPolicy() {}
}
```

### Python
```python
def __init__(
    self,
    issuer_name,  # type: str
    **kwargs  # type: **Any
):
    # type: (...) -> None
    self._issuer_name = issuer_name
    self._subject_name = kwargs.pop("subject_name", None)
    self._subject_alternative_names = kwargs.pop("subject_alternative_names", None) or None
    self._attributes = kwargs.pop("attributes", None)
    self._id = kwargs.pop("cert_policy_id", None)
    self._exportable = kwargs.pop("exportable", None)
    self._key_type = kwargs.pop("key_type", None)
    self._key_size = kwargs.pop("key_size", None)
    self._reuse_key = kwargs.pop("reuse_key", None)
    self._curve = kwargs.pop("curve", None)
    self._ekus = kwargs.pop("ekus", None)
    self._key_usage = kwargs.pop("key_usage", None)
    self._content_type = kwargs.pop("content_type", None)
    self._validity_in_months = kwargs.pop("validity_in_months", None)
    self._lifetime_actions = kwargs.pop("lifetime_actions", None)
    self._certificate_type = kwargs.pop("certificate_type", None)
    self._certificate_transparency = kwargs.pop("certificate_transparency", None)
```
### JS/TS
```ts

```


## CertificateContentType
### .NET
```c#
public struct CertificateContentType : IEquatable<CertificateContentType> {
    public CertificateContentType(string value);
    public static CertificateContentType Pem { get; }
    public static CertificateContentType Pkcs12 { get; }
    public static bool operator ==(CertificateContentType left, CertificateContentType right);
    public static implicit operator CertificateContentType(string value);
    public static bool operator !=(CertificateContentType left, CertificateContentType right);
    public bool Equals(CertificateContentType other);
    public override bool Equals(object obj);
    public override int GetHashCode();
    public override string ToString();
}
```

### Java
```java
public final class CertificateContentType extends ExpandableStringEnum<CertificateContentType> {
    public static final CertificateContentType PKCS12 = fromString("application/x-pkcs12");
    public static final CertificateContentType PEM = fromString("application/x-pem-file");
    public static CertificateContentType fromString(String name) {}
    public static Collection<CertificateContentType> values() {}
}
```

### Python
```python
class SecretContentType(str, Enum):
    """Content type of the secrets as specified in Certificate Policy"""

    PKCS12 = "application/x-pkcs12"
    PEM = "application/x-pem-file"
    ```
### JS/TS
```ts

```


## CertificateKeyUsage
### .NET
```c#
public struct CertificateKeyUsage : IEquatable<CertificateKeyUsage> {
    public CertificateKeyUsage(string value);
    public static CertificateKeyUsage CrlSign { get; }
    public static CertificateKeyUsage DataEncipherment { get; }
    public static CertificateKeyUsage DecipherOnly { get; }
    public static CertificateKeyUsage DigitalSignature { get; }
    public static CertificateKeyUsage EncipherOnly { get; }
    public static CertificateKeyUsage KeyAgreement { get; }
    public static CertificateKeyUsage KeyCertSign { get; }
    public static CertificateKeyUsage KeyEncipherment { get; }
    public static CertificateKeyUsage NonRepudiation { get; }
    public static bool operator ==(CertificateKeyUsage left, CertificateKeyUsage right);
    public static implicit operator CertificateKeyUsage(string value);
    public static bool operator !=(CertificateKeyUsage left, CertificateKeyUsage right);
    public bool Equals(CertificateKeyUsage other);
    public override bool Equals(object obj);
    public override int GetHashCode();
    public override string ToString();
}
```

### Java
```java
public final class CertificateKeyUsage extends ExpandableStringEnum<CertificateKeyUsage> {
    public static final CertificateKeyUsage DIGITAL_SIGNATURE = fromString("digitalSignature");
    public static final CertificateKeyUsage NON_REPUDIATION = fromString("nonRepudiation");
    public static final CertificateKeyUsage KEY_ENCIPHERMENT = fromString("keyEncipherment");
    public static final CertificateKeyUsage DATA_ENCIPHERMENT = fromString("dataEncipherment");
    public static final CertificateKeyUsage KEY_AGREEMENT = fromString("keyAgreement");
    public static final CertificateKeyUsage KEY_CERT_SIGN = fromString("keyCertSign");
    public static final CertificateKeyUsage CRL_SIGN = fromString("cRLSign");
    public static final CertificateKeyUsage ENCIPHER_ONLY = fromString("encipherOnly");
    public static final CertificateKeyUsage DECIPHER_ONLY = fromString("decipherOnly");
    public static CertificateKeyUsage fromString(String name) {}
    public static Collection<CertificateKeyUsage> values() {}
}
```

### Python
```python
class KeyUsageType(str, Enum):
    """The supported types of key usages"""

    digital_signature = "digitalSignature"
    non_repudiation = "nonRepudiation"
    key_encipherment = "keyEncipherment"
    data_encipherment = "dataEncipherment"
    key_agreement = "keyAgreement"
    key_cert_sign = "keyCertSign"
    crl_sign = "cRLSign"
    encipher_only = "encipherOnly"
    decipher_only = "decipherOnly"
```
### JS/TS
```ts

```


## CertificatePolicyAction
### .NET
```c#
public struct CertificatePolicyAction : IEquatable<CertificatePolicyAction> {
    public CertificatePolicyAction(string value);
    public static CertificatePolicyAction AutoRenew { get; }
    public static CertificatePolicyAction EmailContacts { get; }
    public static bool operator ==(CertificatePolicyAction left, CertificatePolicyAction right);
    public static implicit operator CertificatePolicyAction(string value);
    public static bool operator !=(CertificatePolicyAction left, CertificatePolicyAction right);
    public bool Equals(CertificatePolicyAction other);
    public override bool Equals(object obj);
    public override int GetHashCode();
    public override string ToString();
}
```

### Java
```java
public enum CertificatePolicyAction {
    EMAIL_CONTACTS("EmailContacts"),
    AUTO_RENEW("AutoRenew");
    public static CertificatePolicyAction fromString(String value) {}
    public String toString() {}
}
```

### Python
```python
class CertificatePolicyAction(str, Enum):
    """The supported action types for the lifetime of a certificate"""

    email_contacts = "EmailContacts"
    auto_renew = "AutoRenew"
```
### JS/TS
```ts

```


## LifeTimeAction
### .NET
```c#
public class LifetimeAction : IJsonSerializable, IJsonDeserializable {
    public LifetimeAction();
    public CertificatePolicyAction Action { get; set; }
    public int? DaysBeforeExpiry { get; set; }
    public int? LifetimePercentage { get; set; }
}
```

### Java
```java
public final class LifeTimeAction {
    public LifeTimeAction(CertificatePolicyAction certificatePolicyAction) {}
    public Integer getLifetimePercentage() {}
    public LifeTimeAction setLifetimePercentage(Integer lifetimePercentage) {}
    public Integer getDaysBeforeExpiry() {}
    public LifeTimeAction setDaysBeforeExpiry(Integer daysBeforeExpiry) {}
    public CertificatePolicyAction getActionType() {}
}
```

### Python
```python
def __init__(self, action, lifetime_percentage=None, days_before_expiry=None):
    # type: (CertificatePolicyAction, Optional[int], Optional[int]) -> None
    self._lifetime_percentage = lifetime_percentage
    self._days_before_expiry = days_before_expiry
    self._action = action
```
### JS/TS
```ts

```


## SubjectAlternativeNames
### .NET
```c#
public class SubjectAlternativeNames : IEnumerable<string>, IEnumerable, IJsonSerializable, IJsonDeserializable {
    public static SubjectAlternativeNames FromDns(params string[] names);
    public static SubjectAlternativeNames FromDns(IEnumerable<string> names);
    public static SubjectAlternativeNames FromEmail(params string[] names);
    public static SubjectAlternativeNames FromEmail(IEnumerable<string> names);
    public static SubjectAlternativeNames FromUpn(params string[] names);
    public static SubjectAlternativeNames FromUpn(IEnumerable<string> names);
    public IEnumerator<string> GetEnumerator();
}
```

### Java
```java
public final class SubjectAlternativeNames {
    public List<String> getEmails() {}
    public static SubjectAlternativeNames fromEmails(List<String> emails) {}
    public List<String> getDnsNames() {}
    public static SubjectAlternativeNames fromDnsNames(List<String> dnsNames) {}
    public List<String> getUserPrincipalNames() {}
    public static SubjectAlternativeNames fromUserPrincipalNames(List<String> upns) {}
}
```

### Python
```python
# Might end up having it, might not. If we do, this is the implementation
def __init__(self, subject_type, subject_values):
    self._subject_type = subject_type
    self._subject_values = subject_values
```
### JS/TS
```ts

```


## CertificateKeyCurveName
### .NET
```c#
public struct CertificateKeyCurveName : IEquatable<CertificateKeyCurveName> {
    public CertificateKeyCurveName(string value);
    public static CertificateKeyCurveName P256 { get; }
    public static CertificateKeyCurveName P256K { get; }
    public static CertificateKeyCurveName P384 { get; }
    public static CertificateKeyCurveName P521 { get; }
    public static bool operator ==(CertificateKeyCurveName left, CertificateKeyCurveName right);
    public static implicit operator CertificateKeyCurveName(string value);
    public static bool operator !=(CertificateKeyCurveName left, CertificateKeyCurveName right);
    public bool Equals(CertificateKeyCurveName other);
    public override bool Equals(object obj);
    public override int GetHashCode();
    public override string ToString();
}
```

### Java
```java
public final class CertificateKeyCurveName extends ExpandableStringEnum<CertificateKeyCurveName> {
    public static final CertificateKeyCurveName P_256 = fromString("P-256");
    public static final CertificateKeyCurveName P_384 = fromString("P-384");
    public static final CertificateKeyCurveName P_521 = fromString("P-521");
    public static final CertificateKeyCurveName P_256K = fromString("P-256K");
    public static CertificateKeyCurveName fromString(String name) {}
    public static Collection<CertificateKeyCurveName> values() {}
}
```

### Python
```python
class KeyCurveName(str, Enum):
    """Supported elliptic curves"""

    p_256 = "P-256"  #: The NIST P-256 elliptic curve, AKA SECG curve SECP256R1.
    p_384 = "P-384"  #: The NIST P-384 elliptic curve, AKA SECG curve SECP384R1.
    p_521 = "P-521"  #: The NIST P-521 elliptic curve, AKA SECG curve SECP521R1.
    p_256_k = "P-256K"  #: The SECG SECP256K1 elliptic curve.
```
### JS/TS
```ts

```


## CertificateKeyType
### .NET
```c#
public struct CertificateKeyType : IEquatable<CertificateKeyType> {
    public CertificateKeyType(string value);
    public static CertificateKeyType Ec { get; }
    public static CertificateKeyType EcHsm { get; }
    public static CertificateKeyType Oct { get; }
    public static CertificateKeyType Rsa { get; }
    public static CertificateKeyType RsaHsm { get; }
    public static bool operator ==(CertificateKeyType left, CertificateKeyType right);
    public static implicit operator CertificateKeyType(string value);
    public static bool operator !=(CertificateKeyType left, CertificateKeyType right);
    public bool Equals(CertificateKeyType other);
    public override bool Equals(object obj);
    public override int GetHashCode();
    public override string ToString();
}
```

### Java
```java
public final class CertificateKeyType extends ExpandableStringEnum<CertificateKeyType> {
    public static final CertificateKeyType EC = fromString("EC");
    public static final CertificateKeyType EC_HSM = fromString("EC-HSM");
    public static final CertificateKeyType RSA = fromString("RSA");
    public static final CertificateKeyType RSA_HSM = fromString("RSA-HSM");
    public static final CertificateKeyType OCT = fromString("oct");
    public static CertificateKeyType fromString(String name) {}
    public static Collection<CertificateKeyType> values() {}
}
```

### Python
```python
class KeyUsageType(str, Enum):
    """The supported types of key usages"""

    digital_signature = "digitalSignature"
    non_repudiation = "nonRepudiation"
    key_encipherment = "keyEncipherment"
    data_encipherment = "dataEncipherment"
    key_agreement = "keyAgreement"
    key_cert_sign = "keyCertSign"
    crl_sign = "cRLSign"
    encipher_only = "encipherOnly"
    decipher_only = "decipherOnly"
```
### JS/TS
```ts

```


## MergeCertificateOptions
### .NET
```c#
public class MergeCertificateOptions : IJsonSerializable {
    public MergeCertificateOptions(string name, IEnumerable<byte[]> x509certificates);
    public bool? Enabled { get; set; }
    public string Name { get; }
    public IDictionary<string, string> Tags { get; }
    public IEnumerable<byte[]> X509Certificates { get; }
}
```

### Java
```java
public class MergeCertificateOptions {
    public MergeCertificateOptions(String certificateName, List<byte[]> x509Certificates) {}
    public MergeCertificateOptions setTags(Map<String, String> tags) {}
    public Map<String, String> getTags() {}
    public MergeCertificateOptions setEnabled(Boolean enabled) {}
    public Boolean isEnabled() {}
    public String getName() {}
    public List<byte[]> getX509Certificates() {}
}
```

### Python
```python
N/A
```
### JS/TS
```ts

```


## ImportCertificateOptions
### .NET
```c#
public class ImportCertificateOptions : IJsonSerializable {
    public ImportCertificateOptions(string name, byte[] value, CertificatePolicy policy);
    public bool? Enabled { get; set; }
    public string Name { get; }
    public string Password { get; set; }
    public CertificatePolicy Policy { get; }
    public IDictionary<string, string> Tags { get; }
    public byte[] Value { get; }
}
```

### Java
```java
public final class ImportCertificateOptions {
    public ImportCertificateOptions(String name, byte[] value) {}
    public ImportCertificateOptions setEnabled(Boolean enabled) {}
    public Boolean isEnabled() {}
    public CertificatePolicy getCertificatePolicy() {}
    public ImportCertificateOptions setCertificatePolicy(CertificatePolicy certificatePolicy) {}
    public ImportCertificateOptions setTags(Map<String, String> tags) {}
    public Map<String, String> getTags() {}
    public ImportCertificateOptions setPassword(String password) {}
    public String getPassword() {}
    public String getName() {}
    public byte[] getValue() {}
}
```

### Python
```python
N/A
```
### JS/TS
```ts

```


## WellKnownIssuerNames
### .NET
```c#
public static class WellKnownIssuerNames {
    public const string Self = "Self";
    public const string Unknown = "Unknown";
}
```

### Java
```java
public class WellKnownIssuerNames {
    public static final String SELF = "Self";
    public static final String UNKNOWN = "Unknown";
}
```

### Python
```python
class WellKnownIssuerNames(str, Enum):
    """Collection of well-known issuer names"""

    Self = "Self"  #: Use this issuer for a self-signed certificate
    Unknown = "Unknown"
```
### JS/TS
```ts

```



## AdministratorContact
### .NET
```c#
public class AdministratorContact {
    public AdministratorContact();
    public string Email { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Phone { get; set; }
}
```

### Java
```java
public final class AdministratorContact {
    public AdministratorContact(String firstName, String lastName, String email) {}
    public AdministratorContact(String firstName, String lastName, String email, String contact) {}
    public String getFirstName() {}
    public String getLastName() {}
    public String getEmail() {}
    public String getContact() {}
}
```

### Python
```python
def __init__(self, first_name=None, last_name=None, email=None, phone=None):
    # type: (Optional[str], Optional[str], Optional[str], Optional[str]) -> None
    self._first_name = first_name
    self._last_name = last_name
    self._phone = phone
    self._email = email
```
### JS/TS
```ts

```


## CertificateContact
### .NET
```c#
public class CertificateContact : IJsonDeserializable, IJsonSerializable {
    public CertificateContact();
    public string Email { get; set; }
    public string Name { get; set; }
    public string Phone { get; set; }
}
```

### Java
```java
public final class CertificateContact {
    public CertificateContact(String name, String emailAddress, String phone) {}
    public CertificateContact(String name, String emailAddress) {}
    public String getEmailAddress() {}
    public String getName() {}
    public String getPhone() {}
}
```

### Python
```python
def __init__(self, email=None, name=None, phone=None):
    # type: (Optional[str], Optional[str], Optional[str]) -> None
    self._email = email
    self._name = name
    self._phone = phone
```
### JS/TS
```ts

```

## CertificateIssuer
### .NET
```c#
public class CertificateIssuer : IJsonDeserializable, IJsonSerializable {
    public CertificateIssuer(string name);
    public string AccountId { get; set; }
    public IList<AdministratorContact> Administrators { get; }
    public DateTimeOffset? CreatedOn { get; }
    public bool? Enabled { get; set; }
    public Uri Id { get; }
    public string Name { get; }
    public string OrganizationId { get; set; }
    public string Password { get; set; }
    public IssuerProperties Properties { get; }
    public DateTimeOffset? UpdatedOn { get; }
}
```

### Java
```java
public final class CertificateIssuer {
    public CertificateIssuer(String name, String provider) {}
    public IssuerProperties getProperties() {}
    public String getId() {}
    public String getName() {}
    public String getAccountId() {}
    public CertificateIssuer setAccountId(String accountId) {}
    public String getPassword() {}
    public CertificateIssuer setPassword(String password) {}
    public String getOrganizationId() {}
    public CertificateIssuer setOrganizationId(String organizationId) {}
    public List<AdministratorContact> getAdministratorContacts() {}
    public CertificateIssuer setAdministratorContacts(List<AdministratorContact> administratorContacts) {}
    public Boolean isEnabled() {}
    public CertificateIssuer setEnabled(Boolean enabled) {}
    public OffsetDateTime getCreated() {}
    public OffsetDateTime getUpdated() {}
}
```

### Python
```python
def __init__(
    self,
    properties=None,  # type: Optional[IssuerProperties]
    attributes=None,  # type: Optional[models.IssuerAttributes]
    account_id=None,  # type: Optional[str]
    password=None,  # type: Optional[str]
    organization_id=None,  # type: Optional[str]
    admin_details=None,  # type: Optional[List[AdministratorContact]]
):
    # type: (...) -> None
    self._properties = properties
    self._attributes = attributes
    self._account_id = account_id
    self._password = password
    self._organization_id = organization_id
    self._admin_details = admin_details
```
### JS/TS
```ts

```

## IssuerProperties
### .NET
```c#
public class IssuerProperties : IJsonDeserializable, IJsonSerializable {
    public Uri Id { get; }
    public string Name { get; }
    public string Provider { get; set; }
}
```

### Java
```java
public class IssuerProperties {
    public IssuerProperties(String name, String provider) {}
    public String getId() {}
    public String getProvider() {}
    public String getName() {}
}
```

### Python
```python
def __init__(self, provider=None, **kwargs):
    # type: (Optional[str], **Any) -> None
    self._id = kwargs.get("issuer_id", None)
    self._vault_id = parse_vault_id(self._id)
    self._provider = provider
```
### JS/TS
```ts

```

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign4.png)

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign5.png)

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign6.png)
