# Azure KeyVault Certificates API Design

Azure Key Vault is a cloud service that provides secure storage and automated management of certificates used throughout a cloud application. Multiple certificate, and multiple versions of the same certificate, can be kept in the Key Vault. Each certificate in the vault has a policy associated with it which controls the issuance and lifetime of the certificate, along with actions to be taken as certificates near expiry.

The Azure Key Vault Certificate client library enables programmatically managing certificates, offering methods to create, update, list, and delete certificates, policies, issuers, and contacts. The library also supports managing pending certificate operations and management of deleted certificates.

## Concepts
* Certificate
* Certificate Policy
* Issuer
* Contact
* Certificate Operation


## Scenario - Create Certificate
### Usage


### Java
```java
// Async Example
CertificateClientBuilder builder = new CertificateClientBuilder()
        .endpoint(<your-vault-url>)
        .credential(new DefaultAzureCredentialBuilder().build());

CertificateClient certificateClient = builder.buildClient();
CertificateAsyncClient certificateAsyncClient = builder.buildAsyncClient();

CertificatePolicy policy = new CertificatePolicy("Self", "CN=SelfSignedJavaPkcs12")
                                .setValidityInMonths(24)
                                .subjectAlternativeNames(SubjectAlternativeNames.fromEmails(Arrays.asList("wow@gmail.com")));

//Creates a certificate and polls on its progress.
Poller<CertificateOperation, Certificate> createCertPoller = certificateAsyncClient.createCertificate("certificateName", policy);

createCertPoller
    .getObserver()
    .subscribe(pollResponse -> {
        System.out.println("---------------------------------------------------------------------------------");
        System.out.println(pollResponse.getStatus());
        System.out.println(pollResponse.getValue().status());
        System.out.println(pollResponse.getValue().statusDetails());
    });

    // Do other ops ....
    // Cannot move forward without cert at this point
    Mono<Certificate> certificate = createCertPoller.block();


// Sync example
// Blocks until the cert is created.
Certificate myCertificate = certificateClient.createCertificate(String name);

//By default blocks until certificate is created, unless a timeout is specified as an optional parameter.
try {
    myCertificate = certificateClient.createCertificate("certificateName",
    policy, Duration.ofSeconds(60));
} catch (IllegalStateException e) {
    // Certificate wasn't created in the specified duration.
    // Log / Handle here
}
```

### .NET
```c#

var client = new CertificateClient(new Uri(keyVaultUrl), new DefaultAzureCredential());

// Let's create a self signed certifiate using the default policy. If the certificiate
// already exists in the Key Vault, then a new version of the key is created.
string certName = $"defaultCert-{Guid.NewGuid()}";

CertificateOperation certOp = await client.StartCreateCertificateAsync(certName);

// Next let's wait on the certificate operation to complete. Note that certificate creation can last an indeterministic
// amount of time, so applications should only wait on the operation to complete in the case the issuance time is well
// known and within the scope of the application lifetime. In this case we are creating a self-signed certificate which
// should be issued in a relatively short amount of time.
CertificateWithPolicy certificate = await certOp.WaitCompletionAsync();

// At some time later we could get the created certificate along with it's policy from the Key Vault.
certificate = await client.GetCertificateWithPolicyAsync(certName);

Debug.WriteLine($"Certificate was returned with name {certificate.Name} which expires {certificate.Properties.Expires}");


// Create Cert Synchronously
CertificateOperation certOp = client.StartCreateCertificate(certName);

// Next let's wait on the certificate operation to complete. Note that certificate creation can last an indeterministic
// amount of time, so applications should only wait on the operation to complete in the case the issuance time is well
// known and within the scope of the application lifetime. In this case we are creating a self-signed certificate which
// should be issued in a relatively short amount of time.
while (!certOp.HasCompleted)
{
    certOp.UpdateStatus();

    Thread.Sleep(certOp.PollingInterval);
}

// Let's get the created certificate along with it's policy from the Key Vault.
CertificateWithPolicy certificate = client.GetCertificateWithPolicy(certName);

Debug.WriteLine($"Certificate was returned with name {certificate.Name} which expires {certificate.Properties.Expires}");
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
Poller<CertificateOperation, Certificate> createCertificate(String name);
Poller<CertificateOperation, Certificate> createCertificate(String name, CertificatePolicy policy);
Poller<CertificateOperation, Certificate> createCertificate(String name, CertificatePolicy policy, boolean enabled, Map<String, String> tags);


Certificate createCertificate(String name);
Certificate createCertificate(String name, Duration timeout);
Certificate createCertificate(String name, CertificatePolicy policy);
Certificate createCertificate(String name, CertificatePolicy policy, Duration timeout);
Certificate createCertificate(String name, CertificatePolicy policy, Map<String, String> tags);
Certificate createCertificate(String name, CertificatePolicy policy, Map<String, String> tags, Duration timeout);
```

### .NET
```c#
public virtual CertificateOperation StartCreateCertificate(string name, CancellationToken cancellationToken = default);
public virtual CertificateOperation StartCreateCertificate(string name, CertificatePolicy policy, bool? enabled = default, IDictionary<string, string> tags = default, CancellationToken cancellationToken = default);

public virtual async Task<CertificateOperation> StartCreateCertificateAsync(string name, CancellationToken cancellationToken = default);
public virtual async Task<CertificateOperation> StartCreateCertificateAsync(string name, CertificatePolicy policy, bool? enabled = default, IDictionary<string, string> tags = default, CancellationToken cancellationToken = default)

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

## Scenario - Get Certificate
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
public Mono<Certificate> getCertificateWithPolicy(String name);
public Mono<Certificate> getCertificate(String name, String version);
public Mono<Response<Certificate>> getCertificateWithResponse(String name, String version);
public Mono<Certificate> getCertificate(CertificateProperties certificateProperties);

//Sync API
public Certificate getCertificateWithPolicy(String name);
public Certificate getCertificate(CertificateProperties certificateProperties);
public Certificate getCertificate(String name, String version);
public Response<Certificate> getCertificateWithResponse(String name, String version, Context context);
```

### .NET
```c#
public virtual Response<CertificateWithPolicy> GetCertificateWithPolicy(string name, CancellationToken cancellationToken = default);
public virtual async Task<Response<CertificateWithPolicy>> GetCertificateWithPolicyAsync(string name, CancellationToken cancellationToken = default);
public virtual Response<Certificate> GetCertificate(string name, string version, CancellationToken cancellationToken = default);
public virtual async Task<Response<Certificate>> GetCertificateAsync(string name, string version, CancellationToken cancellationToken = default)
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
public Mono<CertificatePolicy> getCertificatePolicy(String name);
public Mono<Response<CertificatePolicy>> getCertificatePolicyWithResponse(String name);


public CertificatePolicy getCertificatePolicy(String name);
public Response<CertificatePolicy> getCertificatePolicyWithResponse(String name, Context context);
```

### .NET
```c#
public virtual Response<CertificatePolicy> GetCertificatePolicy(string certificateName, CancellationToken cancellationToken = default)
public virtual async Task<Response<CertificatePolicy>> GetCertificatePolicyAsync(string certificateName, CancellationToken cancellationToken = default)

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

### NET
```c#
//Async
CertificateProperties certificateProperties = certificate.Properties;
certificateProperties.Enabled = false;

Certificate updatedCert = await client.UpdateCertificatePropertiesAsync(certificateProperties);

Debug.WriteLine($"Certificate enabled set to '{updatedCert.Properties.Enabled}'");


//Sync
CertificateProperties certificateProperties = certificate.Properties;
certificateProperties.Enabled = false;

Certificate updatedCert = client.UpdateCertificateProperties(certificateProperties);

Debug.WriteLine($"Certificate enabled set to '{updatedCert.Properties.Enabled}'");
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
public Mono<Certificate> updateCertificateProperties(CertificateProperties properties);
public Mono<Response<Certificate>> updateCertificatePropertiesWithResponse(CertificateProperties certificateProperties);

public Certificate updateCertificateProperties(CertificateProperties properties);
public Response<Certificate> updateCertificatePropertiesWithResponse(CertificateBase certificate, Context context);
```

### .NET
```c#
public virtual Response<Certificate> UpdateCertificateProperties(CertificateProperties certificateProperties, CancellationToken cancellationToken = default);

public virtual async Task<Response<Certificate>> UpdateCertificatePropertiesAsync(CertificateProperties certificateProperties, CancellationToken cancellationToken = default);
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
Mono<CertificatePolicy> updateCertificatePolicy(String certificateName, CertificatePolicy policy);
public Mono<Response<CertificatePolicy>> updateCertificatePolicyWithResponse(String certificateName, CertificatePolicy policy);

public CertificatePolicy updateCertificatePolicy(String certificateName, CertificatePolicy policy);
public Response<CertificatePolicy> updateCertificatePolicyWithResponse(String certificateName, CertificatePolicy policy, Context context);

```

### .NET
```c#
public virtual Response<CertificatePolicy> UpdateCertificatePolicy(string certificateName, CertificatePolicy policy, CancellationToken cancellationToken = default)
public virtual async Task<Response<CertificatePolicy>> UpdateCertificatePolicyAsync(string certificateName, CertificatePolicy policy, CancellationToken cancellationToken = default)


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

### .NET
```c#
//Async
await client.DeleteCertificateAsync(certName);

//Sync
client.DeleteCertificate(certName);
```

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
public Mono<DeletedCertificate> deleteCertificate(String name);
public Mono<Response<DeletedCertificate>> deleteCertificateWithResponse(String name);


public DeletedCertificate deleteCertificate(String name);
public Response<DeletedCertificate> deleteCertificateWithResponse(String name, Context context);

```

### .NET
```c#
public virtual Response<DeletedCertificate> DeleteCertificate(string name, CancellationToken cancellationToken = default);
public virtual async Task<Response<DeletedCertificate>> DeleteCertificateAsync(string name, CancellationToken cancellationToken = default);


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
public Mono<DeletedCertificate> getDeletedCertificate(String name);
public Mono<Response<DeletedCertificate>> getDeletedCertificateWithResponse(String name);

public DeletedCertificate getDeletedCertificate(String name);
public Response<DeletedCertificate> getDeletedCertificateWithResponse(String name, Context context);
```

### .NET
```c#
public virtual Response<DeletedCertificate> GetDeletedCertificate(string name, CancellationToken cancellationToken = default)
public virtual async Task<Response<DeletedCertificate>> GetDeletedCertificateAsync(string name, CancellationToken cancellationToken = default)


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
public Mono<Certificate> recoverDeletedCertificate(String name);
public Mono<Response<Certificate>> recoverDeletedCertificate(String name);

public Certificate recoverDeletedCertificate(String name);
public Response<Certificate> recoverDeletedCertificate(String name);
```

### .NET
```c#
public virtual Response<CertificateWithPolicy> RecoverDeletedCertificate(string name, CancellationToken cancellationToken = default);
public virtual async Task<Response<CertificateWithPolicy>> RecoverDeletedCertificateAsync(string name, CancellationToken cancellationToken = default);
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

public void purgeDeletedCertificate(String name);
public Response<Void> purgeDeletedCertificateWithResponse(String name, Context context);
```

### .NET
```c#
public virtual Response PurgeDeletedCertificate(string name, CancellationToken cancellationToken = default)
public virtual async Task<Response> PurgeDeletedCertificateAsync(string name, CancellationToken cancellationToken = default)

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
public virtual Response<byte[]> BackupCertificate(string name, CancellationToken cancellationToken = default)
public virtual async Task<Response<byte[]>> BackupCertificateAsync(string name, CancellationToken cancellationToken = default)
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
public Mono<Certificate> restoreCertificate(byte[] backup);
public Mono<Response<Certificate>> restoreCertificateWithResponse(byte[] backup);


public Certificate restoreCertificate(byte[] backup);
public Response<Certificate> restoreCertificateWithResponse(byte[] backup, Context context)
```

### .NET
```c#
public virtual Response<CertificateWithPolicy> RestoreCertificate(byte[] backup, CancellationToken cancellationToken = default);

public virtual async Task<Response<CertificateWithPolicy>> RestoreCertificateAsync(byte[] backup, CancellationToken cancellationToken = default)
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
### .NET
```c#
//Async
// Let's list the certificates which exist in the vault along with their thumbprints
await foreach (CertificateProperties cert in client.GetCertificatesAsync())
{
    Debug.WriteLine($"Certificate is returned with name {cert.Name} and thumbprint {BitConverter.ToString(cert.X509Thumbprint)}");
}

//Sync
// Let's list the certificates which exist in the vault along with their thumbprints
foreach (CertificateProperties cert in client.GetCertificates())
{
    Debug.WriteLine($"Certificate is returned with name {cert.Name} and thumbprint {BitConverter.ToString(cert.X509Thumbprint)}");
}
```

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
public PagedFlux<CertificateProperties> listCertificates(Boolean includePending);
public PagedFlux<CertificateProperties> listCertificates();

public PagedIterable<CertificateProperties> listCertificates();
public PagedIterable<CertificateProperties> listCertificates(boolean includePending, Context context);
```

### .NET
```c#
public virtual IEnumerable<Response<CertificateProperties>> GetCertificates(bool? includePending = default, CancellationToken cancellationToken = default)
public virtual IAsyncEnumerable<Response<CertificateProperties>> GetCertificatesAsync(bool? includePending = default, CancellationToken cancellationToken = default)
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
### .NET
```c#
//Async
// Let's print all the versions of this certificate
await foreach (CertificateProperties cert in client.GetCertificateVersionsAsync(certName1))
{
    Debug.WriteLine($"Certificate {cert.Name} with name {cert.Version}");
}

//Sync
// Let's print all the versions of this certificate
foreach (CertificateProperties cert in client.GetCertificateVersions(certName1))
{
    Debug.WriteLine($"Certificate {cert.Name} with name {cert.Version}");
}
```

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
public PagedFlux<CertificateProperties> listCertificateVersions(String name);

public PagedIterable<CertificateProperties> listCertificateVersions(String name);
public PagedIterable<CertificateProperties> listCertificateVersions(String name, Context context);
```

### .NET
```c#
public virtual IEnumerable<Response<CertificateProperties>> GetCertificateVersions(string name, CancellationToken cancellationToken = default);

public virtual IAsyncEnumerable<Response<CertificateProperties>> GetCertificateVersionsAsync(string name, CancellationToken cancellationToken = default);
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
### .NET
```c#
//Async
// Let's print all the versions of this certificate
await foreach (CertificateProperties cert in client.GetCertificateVersionsAsync(certName1))
{
    Debug.WriteLine($"Certificate {cert.Name} with name {cert.Version}");
}

//Sync
// You can list all the deleted and non-purged certificates, assuming Key Vault is soft-delete enabled.
foreach (DeletedCertificate deletedCert in client.GetDeletedCertificates())
{
    Debug.WriteLine($"Deleted certificate's recovery Id {deletedCert.RecoveryId}");
}
```

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
public virtual IEnumerable<Response<DeletedCertificate>> GetDeletedCertificates(CancellationToken cancellationToken = default)
public virtual IAsyncEnumerable<Response<DeletedCertificate>> GetDeletedCertificatesAsync(CancellationToken cancellationToken = default)
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
public Mono<Issuer> createIssuer(String name, String provider);
public Mono<Issuer> createIssuer(Issuer issuer);
public Mono<Response<Issuer>> createIssuerWithResponse(Issuer issuer);

public Issuer createIssuer(String name, String provider);
public Issuer createIssuer(Issuer issuer);
public Response<Issuer> createIssuerWithResponse(Issuer issuer, Context context)
```

### .NET
```c#
public virtual Response<Issuer> CreateIssuer(Issuer issuer, CancellationToken cancellationToken = default)
public virtual async Task<Response<Issuer>> CreateIssuerAsync(Issuer issuer, CancellationToken cancellationToken = default)
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
public Mono<Response<Issuer>> getIssuerWithResponse(String name);
public Mono<Issuer> getIssuer(String name);
public Mono<Issuer> getIssuer(IssuerProperties issuerProperties);

public Response<Issuer> getIssuerWithResponse(String name, Context context);
public Issuer getIssuer(String name);
public Issuer getIssuer(IssuerProperties issuerProperties);
```

### .NET
```c#
public virtual Response<Issuer> GetIssuer(string name, CancellationToken cancellationToken = default)
public virtual async Task<Response<Issuer>> GetIssuerAsync(string name, CancellationToken cancellationToken = default)
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
public Mono<Response<Issuer>> deleteIssuerWithResponse(String name);
public Mono<Issuer> deleteIssuer(String name);


public Response<Issuer> deleteIssuerWithResponse(String name, Context context);
public Issuer deleteIssuer(String name);
```

### .NET
```c#
public virtual Response<Issuer> DeleteIssuer(string name, CancellationToken cancellationToken = default)
public virtual async Task<Response<Issuer>> DeleteIssuerAsync(string name, CancellationToken cancellationToken = default)
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
public PagedFlux<IssuerProperties> listIssuers();

public PagedIterable<IssuerProperties> listIssuers();
public PagedIterable<IssuerPropeties> listIssuers(Context context);
```

### .NET
```c#
public virtual IEnumerable<Response<IssuerProperties>> GetIssuers(CancellationToken cancellationToken = default)
public virtual IAsyncEnumerable<Response<IssuerProperties>> GetIssuersAsync(CancellationToken cancellationToken = default)
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
public Mono<Issuer> updateIssuer(Issuer issuer);
public Mono<Response<Issuer>> updateIssuerWithResponse(Issuer issuer);

public Issuer updateIssuer(Issuer issuer);
public Response<Issuer> updateIssuerWithResponse(Issuer issuer, Context context);
```

### .NET
```c#
public virtual Response<Issuer> UpdateIssuer(Issuer issuer, CancellationToken cancellationToken = default)
public virtual async Task<Response<Issuer>> UpdateIssuerAsync(Issuer issuer, CancellationToken cancellationToken = default)
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
Question: Do we need this, if we have LRO/Poller support ?

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

### Java
```java

```

### .NET
```c#
public virtual CertificateOperation GetCertificateOperation(string certificateName, CancellationToken cancellationToken = default)
public virtual async Task<CertificateOperation> GetCertificateOperationAsync(string certificateName, CancellationToken cancellationToken = default)
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
public Mono<CertificateOperation> cancelCertificateOperation(String certificateName);
public Mono<Response<CertificateOperation>> cancelCertificateOperation(String certificateName);

public CertificateOperation cancelCertificateOperation(String certificateName);
public Response<CertificateOperation> cancelCertificateOperation(String certificateName);
```

### .NET
```c#
public virtual CertificateOperation CancelCertificateOperation(string certificateName, CancellationToken cancellationToken = default)
public virtual async Task<CertificateOperation> CancelCertificateOperationAsync(string certificateName, CancellationToken cancellationToken = default)

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
public virtual CertificateOperation DeleteCertificateOperation(string certificateName, CancellationToken cancellationToken = default)
public virtual async Task<CertificateOperation> DeleteCertificateOperationAsync(string certificateName, CancellationToken cancellationToken = default)
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
public PagedFlux<Contact> setContacts(List<Contact> contacts);

public PagedIterable<Contact> setContacts(List<Contact> contacts);
public PagedIterable<Contact> setContacts(List<Contact> contacts, Context context);
```

### .NET
```c#
public virtual Response<IList<Contact>> SetContacts(IEnumerable<Contact> contacts, CancellationToken cancellationToken = default)
public virtual async Task<Response<IList<Contact>>> SetContactsAsync(IEnumerable<Contact> contacts, CancellationToken cancellationToken = default)
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
public PagedFlux<Contact> listContacts();

public PagedIterable<Contact> listContacts();
public PagedIterable<Contact> listContacts(Context context);
```

### .NET
```c#
public virtual Response<IList<Contact>> GetContacts(CancellationToken cancellationToken = default)
public virtual async Task<Response<IList<Contact>>> GetContactsAsync(CancellationToken cancellationToken = default)
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
for (Contact contact : certificateClient.deleteContacts()) {
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
public PagedFlux<Contact> deleteContacts();

public PagedIterable<Contact> deleteContacts();
public PagedIterable<Contact> deleteContacts(Context context);
```

### .NET
```c#
public virtual Response<IList<Contact>> DeleteContacts(CancellationToken cancellationToken = default)
public virtual async Task<Response<IList<Contact>>> DeleteContactsAsync(CancellationToken cancellationToken = default)
```
### Python
```python
async def delete_contacts(self, **kwargs: "**Any") -> List[CertificateContact]:
```
### JS/TS
```ts
public async deleteContacts(options: DeleteContactsOptions = {}): Promise<CertificateContacts>
```

## Scenario - Get Certificate Signing Request
### Usage
### java
```java
//Async
certificateAsyncClient.getPendingCertificateSigningRequest("certificateName")
    .subscribe(signingRequest -> System.out.printf("Received Signing request blob of length %s",
        signingRequest.length));

//Sync
byte[] signingRequest = certificateClient.getPendingCertificateSigningRequest("certificateName");
System.out.printf("Received Signing request blob of length %s", signingRequest.length);
```
### API
### Java
```java
public Mono<byte[]> getPendingCertificateSigningRequest(String certificateName);
public Mono<Response<byte[]>> getPendingCertificateSigningRequestWithResponse(String certificateName);

public byte[] getPendingCertificateSigningRequest(String certificateName);
public Response<byte[]> getPendingCertificateSigningRequestWithResponse(String certificateName, Context context);
```

### .NET
```c#
Not in 
.
```
### Python
removed get_pending_certificate_signing_request
```
### JS/TS
```ts
Not in Master
```


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

### Java
```java
public Mono<Certificate> mergeCertificate(String name, List<byte[]> x509Certificates);
public Mono<Response<Certificate>> mergeCertificateWithResponse(String name, List<byte[]> x509Certificates);
public Mono<Certificate> mergeCertificate(MergeCertificateOptions mergeCertificateConfig);
public Mono<Response<Certificate>> mergeCertificateWithResponse(MergeCertificateOptions mergeCertificateConfig);


public Certificate mergeCertificate(String name, List<byte[]> x509Certificates);
public Response<Certificate> mergeCertificateWithResponse(String name, List<byte[]> x509Certificates, Context context);
public Certificate mergeCertificate(MergeCertificateOptions mergeCertificateConfig);
public Response<Certificate> mergeCertificateWithResponse(MergeCertificateOptions mergeCertificateConfig, Context context)
```

### .NET
```c#
public virtual Response<CertificateWithPolicy> MergeCertificate(CertificateMergeOptions certificateMergeOptions, CancellationToken cancellationToken = default);

public virtual async Task<Response<CertificateWithPolicy>> MergeCertificateAsync(CertificateMergeOptions certificateMergeOptions, CancellationToken cancellationToken = default);
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
public Mono<Response<Certificate>> importCertificate(CertificateImport certificateImport);
public Response<Certificate> importCertificate(CertificateImport certificateImport);
```

### .NET
```c#
public virtual Response<CertificateWithPolicy> ImportCertificate(CertificateImport import, CancellationToken cancellationToken = default)
public virtual async Task<Response<CertificateWithPolicy>> ImportCertificateAsync(CertificateImport import, CancellationToken cancellationToken = default)
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

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign4.png)

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign5.png)

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign6.png)
