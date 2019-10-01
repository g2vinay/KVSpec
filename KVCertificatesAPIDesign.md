# Azure KeyVault Certificates API Design

Azure Key Vault is a cloud service that provides secure storage and automated management of certificates used throughout a cloud application. Multiple certificate, and multiple versions of the same certificate, can be kept in the Key Vault. Each certificate in the vault has a policy associated with it which controls the issuance and lifetime of the certificate, along with actions to be taken as certificates near expiry.

The Azure Key Vault Certificate client library enables programmatically managing certificates, offering methods to create, update, list, and delete certificates, policies, issuers, and contacts. The library also supports managing pending certificate operations and management of deleted certificates.

## Certifciates Datastructures Design

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign4.png)

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign5.png)

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign6.png)



## Scenario - Create Certificate
Question: Do All languages return Certificate when operation completes?
### Java
```java
Poller<CertificateOperation, Certificate> createCertificate(String name, CertificatePolicy policy);
Poller<CertificateOperation, Certificate> createCertificate(String name, CertificatePolicy policy, Map<String, String> tags);
Poller<CertificateOperation, Certificate> createCertificate(String name, CertificatePolicy policy, boolean enabled, Map<String, String> tags);

```

### .NET
```c#
public virtual CertificateOperation StartCreateCertificate(string name, CancellationToken cancellationToken = default);
public virtual CertificateOperation StartCreateCertificate(string name, CertificatePolicy policy, bool? enabled = default, IDictionary<string, string> tags = default, CancellationToken cancellationToken = default);

public virtual async Task<CertificateOperation> StartCreateCertificateAsync(string name, CancellationToken cancellationToken = default);
public virtual async Task<CertificateOperation> StartCreateCertificateAsync(string name, CertificatePolicy policy, bool? enabled = default, IDictionary<string, string> tags = default, CancellationToken cancellationToken = default)

```
### Python
```python
    def create_certificate(
            self,
            name,  # type: str
            policy=None,  # type: Optional[CertificatePolicy]
            enabled=None,  # type: Optional[bool]
            tags=None,  # type: Optional[Dict[str, str]]
            **kwargs  # type: Any
    )
```
### JS/TS
```ts
  public async createCertificate(
    name: string,
    certificatePolicy: CertificatePolicy,
    enabled?: boolean,
    tags?: CertificateTags,
    options?: RequestOptionsBase
  ): Promise<Certificate> 
```

## Scenario - Get Certificate

### Java
```java
// Async API
public Mono<Certificate> getCertificateWithPolicy(String name);
public Mono<Certificate> getCertificate(CertificateProperties certificateProperties);
public Mono<Certificate> getCertificate(String name, String version);
public Mono<Response<Certificate>> getCertificateWithResponse(String name, String version);


//Sync API
public Certificate getCertificateWithPolicy(String name);
public Certificate getCertificate(CertificateProperties certificateProperties);
public Certificate getCertificate(String name, String version);
public Response<Certificate> getCertificateWithResponse(String name, String version, Context context);
```

### .NET
```c#
public virtual Response<CertificateWithPolicy> GetCertificateWithPolicy(string name, CancellationToken cancellationToken = default)
public virtual async Task<Response<CertificateWithPolicy>> GetCertificateWithPolicyAsync(string name, CancellationToken cancellationToken = default)
public virtual Response<Certificate> GetCertificate(string name, string version, CancellationToken cancellationToken = default)
public virtual async Task<Response<Certificate>> GetCertificateAsync(string name, string version, CancellationToken cancellationToken = default)
```
### Python
```python
def get_certificate(self, name, version, **kwargs):
def get_certificate_with_policy(self, name, **kwargs)
```
### JS/TS
```javascript
  public async getCertificate(
    name: string,
    version: string,
    options?: RequestOptionsBase
  ): Promise<Certificate>
  
    public async getCertificateWithPolicy(
    name: string,
    options?: RequestOptionsBase
  ): Promise<CertificateWithPolicy>
```

## Scenario - Get Certificate Policy

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
        def get_policy(self, name, **kwargs):
```
### JS/TS
```ts
  public async getCertificatePolicy(
    name: string,
    options?: RequestOptionsBase
  ): Promise<CertificatePolicy>
```

## Scenario - Update Certificate
Question: Updating Certificate via Properties vs setting fields.
### Java
```java
public Mono<Certificate> updateCertificate(String name, Boolean enabled, Map<String, String> tags);
public Mono<Certificate> updateCertificate(String name, Map<String, String> tags);
public Mono<Certificate> updateCertificate(String name, Boolean enabled);
public Mono<Certificate> updateCertificate(String name, String version, Boolean enabled, Map<String, String> tags);
public Mono<Certificate> updateCertificate(String name, String version, Map<String, String> tags);
public Mono<Certificate> updateCertificate(String name, String version, Boolean enabled, Map<String, String> tags);
public Mono<Response<Certificate>> updateCertificate(String name, String version, Boolean enabled, Map<String, String> tags);


public Mono<Certificate> updateCertificateProperties(CertificateProperties certificateProperties);
public Mono<Response<Certificate>> updateCertificatePropertiesWithResponse(CertificateProperties certificateProperties);
    
public Certificate updateCertificate(CertificateBase certificate);
public Response<Certificate> updateCertificateWithResponse(CertificateBase certificate, Context context);

```

### .NET
```c#
public virtual Response<Certificate> UpdateCertificate(string name, string version = default, bool enabled = default, IDictionary<string, string> tags = default, CancellationToken cancellationToken = default);

public virtual async Task<Response<Certificate>> UpdateCertificateAsync(string name, string version = default, bool enabled = default, IDictionary<string, string> tags = default, CancellationToken cancellationToken = default);

```
### Python
```python
        def update_certificate(
            self,
            name,  # type: str
            version=None,   # type: Optional[str]
            enabled=None,  # type: Optional[bool]
            tags=None,  # type: Optional[Dict[str, str]]
            **kwargs  # type: **Any
    ):

```
### JS/TS
```ts
  public async updateCertificate(
    name: string,
    version: string,
    options?: KeyVaultClientUpdateCertificateOptionalParams
  ): Promise<Certificate>
```

## Scenario - Update Certificate Policy

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
    def update_policy(self, name, policy, **kwargs):
```
### JS/TS
```ts
  public async updateCertificatePolicy(
    name: string,
    policy: CertificatePolicy,
    options?: RequestOptionsBase
  ): Promise<CertificatePolicy> 
```


## Scenario - Delete Certificate

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
```python
    def delete_certificate(self, name, **kwargs):

```
### JS/TS
```ts
  public async deleteCertificate(
    certificateName: string,
    options?: RequestOptionsBase
  ): Promise<DeletedCertificate>
```

## Scenario - Get Deleted Certificate

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
    def get_deleted_certificate(self, name, **kwargs):

```
### JS/TS
```ts
  public async getDeletedCertificate(
    name: string,
    options?: RequestOptionsBase
  ): Promise<DeletedCertificate>
```

## Scenario - Recover Deleted Certificate

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
```python
    def recover_deleted_certificate(self, name, **kwargs):
```
### JS/TS
```ts
  public async recoverDeletedCertificate(
    name: string,
    options?: RequestOptionsBase
  ): Promise<Certificate>
```

## Scenario - Purge Delete Certificate

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
    def purge_deleted_certificate(self, name, **kwargs):
```
### JS/TS
```ts
public async purgeDeletedCertificate(name: string, options?: RequestOptionsBase): Promise<null>
```

## Scenario - Backup Certificate

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
def backup_certificate(self, name, **kwargs):
```
### JS/TS
```ts
  public async backupCertificate(
    name: string,
    options?: RequestOptionsBase
  ): Promise<BackupCertificateResult>
```

## Scenario - Restore Certificate

### Java
```java
public Mono<Certificate> restoreCertificate(byte[] backup);
public Mono<Response<Certificate>> restoreCertificateWithResponse(byte[] backup);
        
     
        
public Certificate restoreCertificate(byte[] backup);
public Response<Certificate> restoreCertificateWithResponse(byte[] backup, Context context)
```

### .NET
```c#
public virtual Response<CertificateWithPolicy> RestoreCertificate(byte[] backup, CancellationToken cancellationToken = default)
public virtual async Task<Response<CertificateWithPolicy>> RestoreCertificateAsync(byte[] backup, CancellationToken cancellationToken = default)

```
### Python
```python
    def restore_certificate(self, backup, **kwargs):
```
### JS/TS
```ts
  public async restoreCertificate(
    certificateBackup: Uint8Array,
    options?: RequestOptionsBase
  ): Promise<Certificate>
```

## Scenario - List Ceriticates

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
    def list_certificates(self, include_pending=None, **kwargs):
```
### JS/TS
```ts
  public listCertificates(
    options?: RequestOptionsBase
  ): PagedAsyncIterableIterator<CertificateAttributes, CertificateAttributes[]>
```

## Scenario - List Ceriticate Versions

### Java
```java
public PagedFlux<CertificateProperties> listCertificateVersions(String name);

public PagedIterable<CertificateProperties> listCertificateVersions(String name);
public PagedIterable<CertificateProperties> listCertificateVersions(String name, Context context);
```

### .NET
```c#
public virtual IEnumerable<Response<CertificateProperties>> GetCertificateVersions(string name, CancellationToken cancellationToken = default)
public virtual IAsyncEnumerable<Response<CertificateProperties>> GetCertificateVersionsAsync(string name, CancellationToken cancellationToken = default)
```
### Python
```python
    def list_certificate_versions(self, name, **kwargs):
```
### JS/TS
```ts
  public listCertificateVersions(
    name: string,
    options?: RequestOptionsBase
  ): PagedAsyncIterableIterator<CertificateAttributes, CertificateAttributes[]>
```

## Scenario - List Deleted Certificates

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
    def list_deleted_certificates(self, include_pending=None, **kwargs):
```
### JS/TS
```javascript
  public listDeletedCertificates(
    options?: KeyVaultClientGetDeletedCertificatesOptionalParams
  ): PagedAsyncIterableIterator<DeletedCertificate, DeletedCertificate[]> 
```


## Scenario - Create Certificate Issuer
Question: JS calls it set Certificate Issuer.
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
    def create_issuer(
        self,
        name,  # type: str,
        provider,  # type: str,
        account_id=None,  # type: Optional[str]
        password=None,  # type: Optional[str]
        organization_id=None,  # type: Optional[str]
        admin_details=None,  # type: Optional[List[AdministratorDetails]]
        enabled=None,  # type: Optional[bool]
        **kwargs  # type: **Any
    ):
```
### JS/TS
```javascript
  public async setCertificateIssuer(
    issuerName: string,
    provider: string,
    options?: KeyVaultClientSetCertificateIssuerOptionalParams
  ): Promise<CertificateIssuer>
```

## Scenario - Get Certificate Issuer
Question: JS uses Get Certificate
### Java
```java
public Mono<Response<Issuer>> getIssuerWithResponse(String name);
public Mono<Issuer> getIssuer(String name);
public Mono<Issuer> getIssuer(IssuerBase issuerBase);
                
public Response<Issuer> getIssuerWithResponse(String name, Context context);
public Issuer getIssuer(String name);
public Issuer getIssuer(IssuerBase issuerBase);
```

### .NET
```c#
public virtual Response<Issuer> GetIssuer(string name, CancellationToken cancellationToken = default)
public virtual async Task<Response<Issuer>> GetIssuerAsync(string name, CancellationToken cancellationToken = default)
```
### Python
```python
    def get_issuer(self, name, **kwargs):
```
### JS/TS
```ts
  public async getCertificateIssuer(
    issuerName: string,
    options?: RequestOptionsBase
  ): Promise<CertificateIssuer>
```

## Scenario - Delete Certificate Issuer
Question: JS uses Delete Certificate
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
    def delete_issuer(self, name, **kwargs):

```
### JS/TS
```ts
  public async deleteCertificateIssuer(
    issuerName: string,
    options?: RequestOptionsBase
  ): Promise<CertificateIssuer>
```


## Scenario - List Certificate Issuers
Question: JS uses List Certificate
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
    def list_issuers(self, **kwargs):

```
### JS/TS
```ts
  public listCertificateIssuers(
    options?: KeyVaultClientGetCertificateIssuersOptionalParams
  ): PagedAsyncIterableIterator<CertificateIssuer, CertificateIssuer[]> 
```

## Scenario - Update Certificate Issuer
Question: jS uses Certificate in middle
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
    def update_issuer(
        self,
        name,  # type: str,
        provider=None,  # type: Optional[str],
        account_id=None,  # type: Optional[str]
        password=None,  # type: Optional[str]
        organization_id=None,  # type: Optional[str]
        admin_details=None,  # type: Optional[List[AdministratorDetails]]
        enabled=None,  # type: Optional[bool]
        **kwargs  # type: **Any
    ):
```
### JS/TS
```ts
  public async updateCertificateIssuer(
    issuerName: string,
    options?: KeyVaultClientUpdateCertificateIssuerOptionalParams
  ): Promise<CertificateIssuer> 
```



## Scenario - Get Certificate Operation
Question: Do we need this, if we have LRO/Poller support ?
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
    def get_certificate_operation(self, name, **kwargs):
```
### JS/TS
```ts
  public async getCertificateOperation(
    name: string,
    options?: RequestOptionsBase
  ): Promise<CertificateOperation>
```

## Scenario - Cancel Certificate Operation
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
    def cancel_certificate_operation(self, name, **kwargs):
```
### JS/TS
```ts
  public async cancelCertificateOperation(
    name: string,
    options?: RequestOptionsBase
  ): Promise<CertificateOperation> 
```

## Scenario - Delete Certificate Operation

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
    def delete_certificate_operation(self, name, **kwargs):
```
### JS/TS
```ts
 public async deleteCertificateOperation(
    name: string,
    options?: RequestOptionsBase
  ): Promise<CertificateOperation>
```



## Scenario - Set Certificate Contacts
Question: JS uses Certificate in middle ?
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
    def create_contacts(self, contacts, **kwargs):
```
### JS/TS
```ts
  public async setCertificateContacts(
    contacts: Contact[],
    options?: RequestOptionsBase
  ): Promise<Contacts>
```

## Scenario - List Certificate Contacts

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
def get_contacts(self, **kwargs):
```
### JS/TS
```ts
public async getCertificateContacts(options?: RequestOptionsBase): Promise<Contacts>
```

## Scenario - Delete Certificate Contacts
Question: JS uses 'Certificate'
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
    def delete_contacts(self, **kwargs):
```
### JS/TS
```ts
  public async deleteCertificateContacts(options?: RequestOptionsBase): Promise<Contacts>
```

## Scenario - Get Certificate Signing Request

### Java
```java
public Mono<byte[]> getPendingCertificateSigningRequest(String certificateName);
public Mono<Response<byte[]>> getPendingCertificateSigningRequestWithResponse(String certificateName);

public byte[] getPendingCertificateSigningRequest(String certificateName);
public Response<byte[]> getPendingCertificateSigningRequestWithResponse(String certificateName, Context context);
```

### .NET
```c#
Not in Master.
```
### Python
```python
    def get_pending_certificate_signing_request(
        self,
        name,  # type: str
        **kwargs  # type: **Any
    ):
```
### JS/TS
```ts
Not in Master
```


## Scenario - Merge Certificate

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
Not in master.

```
### Python
```python
    def merge_certificate(
        self,
        name,  # type: str
        x509_certificates,  # type: List[bytearray]
        enabled=None,  # type: Optional[bool]
        tags=None,  # type: Optional[Dict[str, str]]
        **kwargs  # type: **Any
    ):
```
### JS/TS
```ts
  public async mergeCertificate(
    name: string,
    x509Certificates: Uint8Array[],
    options?: RequestOptionsBase
  ): Promise<Certificate>
```

## Scenario - Import Certificate
Question: Should we support reading from PEM cert file directly ?
### Java
```java
public Mono<Certificate> importCertificate( String certificateName, String certificateFilePath);
public Mono<Response<Certificate>> importCertificate(CertificateImport certificateImport);
    
public Certificate importCertificate( String certificateName, String certificateFilePath);
public Response<Certificate> importCertificate(CertificateImport certificateImport);
```

### .NET
```c#
public virtual Response<CertificateWithPolicy> ImportCertificate(CertificateImport import, CancellationToken cancellationToken = default)
public virtual async Task<Response<CertificateWithPolicy>> ImportCertificateAsync(CertificateImport import, CancellationToken cancellationToken = default)

```
### Python
```python
    def import_certificate(
            self,
            name,  # type: str
            certificate_bytes,  # type: bytes
            password=None,  # type: Optional[str]
            policy=None,  # type: Optional[CertificatePolicy]
            enabled=None,  # type: Optional[bool]
            tags=None,  # type: Optional[Dict[str, str]]
            **kwargs  # type: **Any
    ):
```
### JS/TS
```ts
  public async importCertificate(
    name: string,
    base64EncodedCertificate: string,
    options?: KeyVaultClientImportCertificateOptionalParams
  ): Promise<Certificate>
```


