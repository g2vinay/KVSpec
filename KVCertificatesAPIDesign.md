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

#### Java
```java
CertificateAsyncClient certificateAsyncClient = new CertificateClientBuilder()
    .credential(new DefaultAzureCredentialBuilder().build())
    .vaultUrl("https://myvault.vault.azure.net/")
    .serviceVersion(CertificateServiceVersion.V7_0) .  // This parameter is optional, accepted but not used currently.
    .buildAsyncClient();
```

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

### Python

```python
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient, CertificatePolicy

credential = DefaultAzureCredential()

certificate_client = CertificateClient(vault_url="https://my-key-vault.vault.azure.net/", credential=credential)
```

### JS/TS

```ts
  /**
   * Creates an instance of CertificateClient.
   * @param {string} vaultUrl the base URL to the vault.
   * @param {TokenCredential} credential An object that implements the `TokenCredential` interface used to authenticate requests to the service. Use the @azure/identity package to create a credential that suits your needs.
   * @param {PipelineOptions} [pipelineOptions={}] Optional. Pipeline options used to configure Key Vault API requests.
   *                                                         Omit this parameter to use the default pipeline configuration.
   * @memberof CertificateClient
   */
  constructor(
    vaultUrl: string,
    credential: TokenCredential,
    pipelineOptions: PipelineOptions = {}
  )
```

## Scenario - Get vault endpoint

### API

#### Java
```java
public String getVaultUrl();
```

#### .NET
```c#
public virtual Uri VaultUri { get; }
```

#### Python
```python
certificate_client.vault_url
```

#### JS/TS

```ts
n/a
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
  const client = new CertificateClient(url, credential);

  // Creating a self-signed certificate
  const poller = await client.beginCreateCertificate("MyCertificate", {
    issuerName: "Self",
    subject: "cn=MyCert"
  });
  const certificate = await poller.pollUntilDone();

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
certificateAsyncClient.getCertificateVersion("certificateName", "certificateVersion")
    .subscribe(certificateResponse ->
        System.out.printf("Certificate is returned with name %s and secretId %s %n", certificateResponse.name(),
            certificateResponse.secretId()));

// Retrieve synchronously
KeyVaultCertificateWithPolicy certificate = certificateClient.getCertificate("certificateName");
System.out.printf("Recevied certificate with name %s and version %s and secret id",
    certificate.getProperties().getName(),
    certificate.getProperties().getVersion(), certificate.getSecretId());
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
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(policy ->
        System.out.printf("Certificate policy is returned with issuer name %s and subject name %s %n",
            policy.getIssuerName(), policy.getSubjectName()));

//Sync
CertificatePolicy policy = certificateClient.getCertificatePolicy("certificateName");
System.out.printf("Received policy with subject name %s", policy.getSubjectName());
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
certificateAsyncClient.getCertificate("certificateName")
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(certificateResponseValue -> {
        KeyVaultCertificate certificate = certificateResponseValue;
        //Update enabled status of the certificate
        certificate.getProperties().setEnabled(false);
        certificateAsyncClient.updateCertificateProperties(certificate.getProperties())
            .subscribe(certificateResponse ->
                System.out.printf("Certificate's enabled status %s %n",
                    certificateResponse.getProperties().isEnabled().toString()));
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
const version = "";
await client.updateCertificate("MyCertificate", version, {
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
// Update the certificate policy cert validity property.
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

### JS/TS

```ts
const deletePoller = await client.beginDeleteCertificate(certificateName);
const deletedCertificate = await deletePoller.pollUntilDone();
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
certificateAsyncClient.beginRecoverDeletedCertificate("deletedCertificateName")
    .subscribe(pollResponse -> {
        System.out.println("Recovery Status: " + pollResponse.getStatus().toString());
        System.out.println("Recover Certificate Name: " + pollResponse.getValue().getName());
        System.out.println("Recover Certificate Id: " + pollResponse.getValue().getId());
    });

//Sync
SyncPoller<KeyVaultCertificate, Void> recoverCertPoller = certificateClient
    .beginRecoverDeletedCertificate("deletedCertificateName");
// Recovered certificate is accessible as soon as polling beings
PollResponse<KeyVaultCertificate> pollResponse = recoverCertPoller.poll();
System.out.printf(" Recovered Deleted certificate with name %s and id %s", pollResponse.getValue()
        .getProperties().getName(), pollResponse.getValue().getProperties().getId());
recoverCertPoller.waitForCompletion();
```
### JS/TS
 ```ts
const recoverPoller = await client.beginRecoverDeletedCertificate("MyCertificate");
const certificateWithPolicy = await recoverPoller.pollUntilDone();
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

### JS/TS

```ts
await client.purgeDeletedCertificate("MyCertificate");
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

### JS/TS

```ts
const backup = await client.backupCertificate("MyCertificate");
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
certificateAsyncClient.restoreCertificateBackup(certificateBackupByteArray)
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(certificateResponse -> System.out.printf("Restored Certificate with name %s and key id %s %n",
        certificateResponse.getName(), certificateResponse.getKeyId()));

//Sync
byte[] certificateBackupBlob = {};
KeyVaultCertificate certificate = certificateClient.restoreCertificateBackup(certificateBackupBlob);
System.out.printf(" Restored certificate with name %s and id %s", certificate.getName(), certificate.getId());
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

### JS/TS

```ts
const backup = await client.backupCertificate("MyCertificate");
// Needs to be deleted and purged before it's restored
await client.restoreCertificateBackup(backup.value!);
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

```ts
// Note: includePending is optional. It's false by default.

// Listing all the available certificates in a single call.
// The certificates we just created are still pending at this point.
for await (const certificate of client.listPropertiesOfCertificates({ includePending: true })) {
  console.log("Certificate from a single call: ", certificate);
}

// Listing all the available certificates by pages.
let pageCount = 0;
for await (const page of client.listPropertiesOfCertificates({ includePending: true }).byPage()) {
  for (const certificate of page) {
    console.log(`Certificate from page ${pageCount}: `, certificate);
  }
  pageCount++;
}
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

### JS/TS

```ts
for await (const properties of client.listPropertiesOfCertificateVersions(certificateName, {
  includePending: true
})) {
  console.log(properties.name, properties.version!);
}

for await (const page of client.listPropertiesOfCertificateVersions(certificateName).byPage()) {
  for (const properties of page) {
    console.log(properties.name, properties.version!);
  }
}
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

```ts
for await (const deletedCertificate of client.listDeletedCertificates({ includePending: true })) {
}

for await (const page of client.listDeletedCertificates({ includePending: true }).byPage()) {
  for (const deleteCertificate of page) {
  }
}
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
CertificateIssuer issuerToCreate = new CertificateIssuer("myissuer", "myProvider")
    .setAccountId("testAccount")
    .setAdministratorContacts(Arrays.asList(new AdministratorContact("test", "name",
        "test@example.com")));
CertificateIssuer returnedIssuer = certificateClient.createIssuer(issuerToCreate);
System.out.printf("Created Issuer with name %s provider %s", returnedIssuer.getName(),
    returnedIssuer.getProperties().getProvider());
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
Response<CertificateIssuer> issuerResponse = certificateClient.getIssuerWithResponse("issuerName",
    new Context(key1, value1));
System.out.printf("Retrieved issuer with name %s and prodier %s", issuerResponse.getValue().getName(),
    issuerResponse.getValue().getProperties().getProvider());
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
certificateAsyncClient.deleteIssuerWithResponse("issuerName")
    .subscribe(deletedIssuerResponse ->
        System.out.printf("Deleted issuer with name %s %n", deletedIssuerResponse.getValue().name()));

//Sync
CertificateIssuer deletedIssuer = certificateClient.deleteIssuer("certificateName");
System.out.printf("Deleted certificate issuer with name %s and provider id %s", deletedIssuer.getName(),
    deletedIssuer.getProperties().getProvider());
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
certificateAsyncClient.listPropertiesOfIssuers()
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(issuerProperties -> certificateAsyncClient.getIssuer(issuerProperties.getName())
        .subscribe(issuerResponse -> System.out.printf("Received issuer with name %s and provider %s",
            issuerResponse.getName(), issuerResponse.getProperties().getProvider())));

//Sync
for (IssuerProperties issuer : certificateClient.listPropertiesOfIssuers()) {
    CertificateIssuer retrievedIssuer = certificateClient.getIssuer(issuer.getName());
    System.out.printf("Received issuer with name %s and provider %s", retrievedIssuer.getName(),
        retrievedIssuer.getProperties().getProvider());
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
for await (const issuerProperties of client.listPropertiesOfIssuers()) {
  console.log(issuerProperties);
}
// By pages
for await (const page of client.listPropertiesOfIssuers().byPage()) {
  for (const issuerProperties of page) {
    console.log(issuerProperties);
  }
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
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(issuerResponseValue -> {
        CertificateIssuer issuer = issuerResponseValue;
        //Update the enabled status of the issuer.
        issuer.setEnabled(false);
        certificateAsyncClient.updateIssuer(issuer)
            .subscribe(issuerResponse ->
                System.out.printf("Issuer's enabled status %s %n",
                    issuerResponse.isEnabled().toString()));
    });

//Sync
CertificateIssuer returnedIssuer = certificateClient.getIssuer("issuerName");
returnedIssuer.setAccountId("newAccountId");
CertificateIssuer updatedIssuer = certificateClient.updateIssuer(returnedIssuer);
System.out.printf("Updated issuer with name %s, provider %s and account Id %s", updatedIssuer.getName(),
    updatedIssuer.getProperties().getProvider(), updatedIssuer.getAccountId());
```

### JS/TS
```ts
await client.updateIssuer("IssuerName", {
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
const createPoller = await client.beginCreateCertificate("MyCertificate", {
  issuerName: "Self",
  subject: "cn=MyCert"
});
const pendingCertificate = createPoller.getResult();
console.log(pendingCertificate);
const poller = await client.getCertificateOperation("MyCertificate");
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

### JS/TS
```ts
// Directly
await client.cancelCertificateOperation("MyCertificate");

// The poller cancel methods use client.cancelCertificateOperation in the background.

// Through the create poller
const client = new CertificateClient(url, credentials);
const createPoller = await client.beginCreateCertificate("MyCertificate", {
  issuerName: "Self",
  subject: "cn=MyCert"
});
await createPoller.cancel();

// Through the operation poller
const operationPoller = await client.getCertificateOperation("MyCertificate");
await operationPoller.cancel();
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
  // The poller cancel methods use client.cancelCertificateOperation in the background.
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
CertificateContact contactToAdd = new CertificateContact("user", "useremail@exmaple.com");
certificateAsyncClient.setContacts(Arrays.asList(oontactToAdd)).subscribe(contact ->
    System.out.printf("Contact name %s and email %s", contact.getName(), contact.getEmailAddress())
);

//Sync
CertificateContact contactToAdd = new CertificateContact("user", "useremail@exmaple.com");
for (CertificateContact contact : certificateClient.setContacts(Arrays.asList(contactToAdd))) {
    System.out.printf("Added contact with name %s and email %s to key vault", contact.getName(),
        contact.getEmailAddress());
}
```

### JS/TS
 ```ts
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
    System.out.printf("Contact name %s and email %s", contact.getName(), contact.getEmailAddress())
);

//Sync
for (CertificateContact contact : certificateClient.listContacts(new Context(key1, value1))) {
    System.out.printf("Added contact with name %s and email %s to key vault", contact.getName(),
        contact.getEmailAddress());
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
public async getContacts(options: GetContactsOptions = {}): Promise<CertificateContacts>
```

## Scenario - Delete Certificate Contacts
### Usage
### java
```java
//Async
certificateAsyncClient.deleteContacts().subscribe(contact ->
    System.out.printf("Deleted Contact name %s and email %s", contact.getName(), contact.getEmailAddress())
);

//Sync
for (CertificateContact contact : certificateClient.deleteContacts()) {
    System.out.printf("Deleted contact with name %s and email %s from key vault", contact.getName(),
        contact.getEmailAddress());
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
await client.beginCreateCertificate("MyCertificate", {
  issuerName: "Unknown",
  certificateTransparency: false,
  subject: "cn=MyCert"
});
const operationPoller = await client.getCertificateOperation(certificateName);
const { csr } = operationPoller.getResult();
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
/**
 * An interface representing a certificate without the certificate's policy
 */
export interface KeyVaultCertificate {
  /**
   * CER contents of x509 certificate.
   */
  cer?: Uint8Array;
  /**
   * The content type of the secret.
   */
  certificateContentType?: CertificateContentType;
  /**
   * Certificate identifier.
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
  id?: string;
  /**
   * The key id.
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
  readonly keyId?: string;
  /**
   * The secret id.
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
  readonly secretId?: string;
  /**
   * The name of certificate.
   */
  name: string;
  /**
   * The properties of the certificate
   */
  properties: CertificateProperties;
}

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
/**
 * An interface representing a certificate with its policy
 */
export interface KeyVaultCertificateWithPolicy extends KeyVaultCertificate {
  /**
   * The management policy.
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
  readonly policy?: CertificatePolicy;
}
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
/**
 * An interface representing the properties of a certificate
 */
export interface CertificateProperties {
  /**
   * When the certificate was created.
   */
  readonly createdOn?: Date;
  /**
   * Determines whether the object is enabled.
   */
  enabled?: boolean;
  /**
   * Expiry date in UTC.
   */
  readonly expiresOn?: Date;
  /**
   * Certificate identifier.
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
  id?: string;
  /**
   * The name of certificate.
   */
  name?: string;
  /**
   * Not before date in UTC.
   */
  notBefore?: Date;
  /**
   * Reflects the deletion recovery level currently in effect for certificates in the current
   * vault. If it contains 'Purgeable', the certificate can be permanently deleted by a privileged
   * user; otherwise, only the system can purge the certificate, at the end of the retention
   * interval. Possible values include: 'Purgeable', 'Recoverable+Purgeable', 'Recoverable',
   * 'Recoverable+ProtectedSubscription'
   * **NOTE: This property will not be serialized. It can only be populated by the server.**
   */
  readonly recoveryLevel?: DeletionRecoveryLevel;
  /**
   * Application specific
   * metadata in the form of key-value pairs.
   */
  tags?: CertificateTags;
  /**
   * When the issuer was updated.
   */
  updatedOn?: Date;
  /**
   * The vault URI.
   */
  vaultUrl?: string;
  /**
   * The version of certificate. May be undefined.
   */
  version?: string;
  /**
   * Thumbprint of the certificate.
   */
  readonly x509Thumbprint?: Uint8Array;
}

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
/**
 * A certificate operation is returned in case of asynchronous requests.
 */
export interface CertificateOperation {
  /**
   * The certificate id.
   * **NOTE: This property will not be serialized. It can only be populated by the server.**
   */
  readonly id?: string;
  /**
   * Parameters for the issuer of the X509 component of a certificate.
   */
  issuerParameters?: IssuerParameters;
  /**
   * The certificate signing request (CSR) that is being used in the certificate operation.
   */
  csr?: Uint8Array;
  /**
   * Indicates if cancellation was requested on the certificate operation.
   */
  cancellationRequested?: boolean;
  /**
   * Status of the certificate operation.
   */
  status?: string;
  /**
   * The status details of the certificate operation.
   */
  statusDetails?: string;
  /**
   * Error encountered, if any, during the certificate operation.
   */
  error?: ErrorModel;
  /**
   * Location which contains the result of the certificate operation.
   */
  target?: string;
  /**
   * Identifier for the certificate operation.
   */
  requestId?: string;
}
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
n/a
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
/**
 * An interface representing a deleted certificate
 */
export interface DeletedCertificate extends KeyVaultCertificateWithPolicy {
  /**
   * The time when the certificate was deleted, in UTC
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
  readonly deletedOn?: Date;
  /**
   * The url of the recovery object, used to
   * identify and recover the deleted certificate.
   */
  recoveryId?: string;
  /**
   * The time when the certificate is scheduled
   * to be purged, in UTC
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
  readonly scheduledPurgeDate?: Date;
}

```

## CertificatePolicy
### .NET
```c#
public class CertificatePolicy : IJsonSerializable, IJsonDeserializable {
    public CertificatePolicy(string issuerName, string subject);
    public CertificatePolicy(string issuerName, SubjectAlternativeNames subjectAlternativeNames);
    public CertificatePolicy(string issuerName, string subject, SubjectAlternativeNames subjectAlternativeNames);
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
/**
 * An interface representing a certificate's policy
 */
export interface CertificatePolicy {
  /**
   * Indicates if the certificates generated under this policy should be published to certificate
   * transparency logs.
   */
  certificateTransparency?: boolean;
  /**
   * The media type (MIME type).
   */
  contentType?: string;
  /**
   * Type of certificate to be requested from the issuer provider.
   */
  certificateType?: CertificateContentType;
  /**
   * When the certificate was created.
   */
  readonly createdOn?: Date;
  /**
   * Determines whether the object is enabled.
   */
  enabled?: boolean;
  /**
   * The enhanced key usage.
   */
  enhancedKeyUsage?: string[];
  /**
   * Name of the referenced issuer object or reserved names; for example, 'Self' or 'Unknown'.
   */
  issuerName?: WellKnownIssuer | string;
  /**
   * Elliptic curve name. Possible values include: 'P-256', 'P-384', 'P-521', 'P-256K'
   */
  keyCurveName?: KeyCurveName;
  /**
   * The key size in bits. For example: 2048, 3072, or 4096 for RSA.
   */
  keySize?: number;
  /**
   * The type of key pair to be used for the certificate. Possible values include: 'EC', 'EC-HSM',
   * 'RSA', 'RSA-HSM', 'oct'
   */
  keyType?: KeyType;
  /**
   * List of key usages.
   */
  keyUsage?: KeyUsageType[];
  /**
   * Actions that will be performed by Key Vault over the lifetime of a certificate.
   */
  lifetimeActions?: LifetimeAction[];
  /**
   * Indicates if the same key pair will be used on certificate renewal.
   */
  reuseKey?: boolean;
  /**
   * The subject name. Should be a valid X509 distinguished Name.
   */
  subject?: string;
  /**
   * The subject alternative names.
   */
  subjectAlternativeNames?: SubjectAlternativeNames;
  /**
   * When the object was updated.
   */
  readonly updatedOn?: Date;
  /**
   * The duration that the certificate is valid in months.
   */
  validityInMonths?: number;
}

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
export type CertificateContentType = "application/pem" | "application/x-pkcs12" | undefined;
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
/**
 * Defines values for KeyUsageType.
 * Possible values include: 'digitalSignature', 'nonRepudiation', 'keyEncipherment',
 * 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'
 * @readonly
 * @enum {string}
 */
export type KeyUsageType =
  | "digitalSignature"
  | "nonRepudiation"
  | "keyEncipherment"
  | "dataEncipherment"
  | "keyAgreement"
  | "keyCertSign"
  | "cRLSign"
  | "encipherOnly"
  | "decipherOnly";
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
n/a
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
/**
 * Action and its trigger that will be performed by Key Vault over the lifetime of a certificate.
 */
export interface LifetimeAction {
  /**
   * The condition that will execute the action.
   */
  trigger?: Trigger;
  /**
   * The action that will be executed.
   */
  action?: Action;
}
```


## SubjectAlternativeNames
### .NET
```c#
public class SubjectAlternativeNames : {
    public SubjectAlternativeNames();
    public IList<string> DnsNames { get; }
    public IList<string> Emails { get; }
    public IList<string> UserPrincipalNames { get; }
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
/**
 * An interface representing the alternative names of the subject of a certificate policy.
 */
export interface SubjectAlternativeNamesAll {
  /**
   * Email addresses.
   */
  emails: ArrayOneOrMore<string>;
  /**
   * Domain names.
   */
  dnsNames: ArrayOneOrMore<string>;
  /**
   * User principal names.
   */
  userPrincipalNames: ArrayOneOrMore<string>;
}

/**
 * Alternatives to the subject property.
 * If present, it should at least have one of the properties of SubjectAlternativeNamesAll.
 */
export type SubjectAlternativeNames = RequireAtLeastOne<SubjectAlternativeNamesAll>;

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
/**
 * Defines values for JsonWebKeyCurveName.
 * Possible values include: 'P-256', 'P-384', 'P-521', 'P-256K'
 * @readonly
 * @enum {string}
 */
export type JsonWebKeyCurveName = "P-256" | "P-384" | "P-521" | "P-256K";
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
class KeyType(str, Enum):
  """Supported key types"""

  ec = "EC"  #: Elliptic Curve
  ec_hsm = "EC-HSM"  #: Elliptic Curve with a private key which is not exportable from the HSM
  rsa = "RSA"  #: RSA (https://tools.ietf.org/html/rfc3447)
  rsa_hsm = "RSA-HSM"  #: RSA with a private key which is not exportable from the HSM
  oct = "oct"  #: Octet sequence (used to represent symmetric keys)
```
### JS/TS
```ts
/**
 * Defines values for JsonWebKeyType.
 * Possible values include: 'EC', 'EC-HSM', 'RSA', 'RSA-HSM', 'oct'
 * @readonly
 * @enum {string}
 */
export type JsonWebKeyType = "EC" | "EC-HSM" | "RSA" | "RSA-HSM" | "oct";
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
/**
 * An interface representing optional parameters for {@link mergeCertificate}.
 */
export interface MergeCertificateOptions extends coreHttp.OperationOptions {}
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
/**
 * Options for {@link importCertificate}.
 */
export interface ImportCertificateOptions extends CertificateProperties, coreHttp.OperationOptions {
  /**
   * If the private key in base64EncodedCertificate is encrypted, the password used for encryption.
   */
  password?: string;
}
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
/**
 * Well known issuers for choosing a default
 */
export enum WellKnownIssuer {
  /**
   * For self signed certificates
   */
  Self = "Self",
  /**
   * For certificates whose issuer will be defined later
   */
  Unknown = "Unknown",
}
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
/**
 * Details of the organization administrator of the certificate issuer.
 */
export interface AdministratorContact {
  /**
   * First name.
   */
  firstName?: string;
  /**
   * Last name.
   */
  lastName?: string;
  /**
   * Email address.
   */
  emailAddress?: string;
  /**
   * Phone number.
   */
  phone?: string;
}
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
/**
 * The contact information for the vault certificates.
 * Each contact will have at least just one of the properties of CertificateContactAll,
 * which are: emailAddress, name or phone.
 */
export type CertificateContact = RequireAtLeastOne<CertificateContactAll> | undefined;
```

## CertificateIssuer
### .NET
```c#
public class CertificateIssuer : IJsonDeserializable, IJsonSerializable {
    public CertificateIssuer(string name);
    public string AccountId { get; set; }
    public IList<AdministratorContact> AdministratorContacts { get; }
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
/**
 * An interface representing the properties of an issuer
 */
export interface CertificateIssuer {
  /**
   * Certificate Identifier.
   */
  id?: string;
  /**
   * The issuer provider.
   */
  provider?: string;
  /**
   * Determines whether the object is enabled.
   */
  enabled?: boolean;
  /**
   * When the issuer was created.
   */
  createdOn?: Date;
  /**
   * When the issuer was updated.
   */
  updatedOn?: Date;
  /**
   * Name of the issuer
   */
  name?: string;
}

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
/**
 * An interface representing the issuer of a certificate
 */
export interface IssuerProperties {
  /**
   * Certificate Identifier.
   */
  id?: string;
  /**
   * The issuer provider.
   */
  provider?: string;
}

```

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign4.png)

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign5.png)

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign6.png)
