# Azure KeyVault Certificates API Design

## Scenario - Create Certificate

### Java
```java
Poller<CertificateOperation> createCertificate(String name, CertificatePolicy policy, Map<String, String> tags);
Poller<CertificateOperation> createCertificate(String name, CertificatePolicy policy);

CertificatePolicy policy = new CertificatePolicy("Self", "CN=SelfSignedJavaPkcs12");
Map<String, String> tags = new HashMap<>();
tags.put("foo", "bar");
//Creates a certificate and polls on its progress.
certificateAsyncClient.createCertificate("certificateName", policy, tags)
    .getObserver()
    .subscribe(pollResponse -> {
        System.out.println("---------------------------------------------------------------------------------");
        System.out.println(pollResponse.getStatus());
        System.out.println(pollResponse.getValue().status());
        System.out.println(pollResponse.getValue().statusDetails());
    });

```

### .NET
```net
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
public Mono<Certificate> getCertificate(CertificateBase certificateBase);
public Mono<Certificate> getCertificate(String name, String version);
public Mono<Response<Certificate>> getCertificateWithResponse(String name, String version);

certificateAsyncClient.getCertificateWithPolicy("certificateName")
    .subscribe(certificateResponse ->
        System.out.printf("Certificate is returned with name %s and secretId %s %n", certificateResponse.name(),
            certificateResponse.secretId()));

//Sync API
public Certificate getCertificateWithPolicy(String name);
public Certificate getCertificate(CertificateProperties certificateProperties);
public Certificate getCertificate(String name, String version);
public Response<Certificate> getCertificateWithResponse(String name, String version, Context context);

Certificate certificate = certificateClient.getCertificateWithPolicy("certificateName");
System.out.printf("Recevied certificate with name %s and version %s and secret id", certificate.name(),
    certificate.version(), certificate.secretId());


```

### .NET
```net
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

certificateAsyncClient.getCertificatePolicy("certificateName")
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(policy ->
        System.out.printf("Certificate policy is returned with issuer name %s and subject name %s %n",
            policy.issuerName(), policy.subjectName()));
            
public CertificatePolicy getCertificatePolicy(String name);
public Response<CertificatePolicy> getCertificatePolicyWithResponse(String name, Context context);

Response<CertificatePolicy> returnedPolicyWithResponse = certificateClient.getCertificatePolicyWithResponse(
    "certificateName", new Context(key1, value1));
System.out.printf("Received policy with subject name %s", returnedPolicyWithResponse.getValue().subjectName());
```

### .NET
```net

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

### Java
```java
public Mono<Certificate> updateCertificate(CertificateBase certificate);
public Mono<Response<Certificate>> updateCertificateWithResponse(CertificateBase certificate);

certificateAsyncClient.getCertificateWithPolicy("certificateName")
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(certificateResponseValue -> {
        Certificate certificate = certificateResponseValue;
        //Update enabled status of the certificate
        certificate.enabled(false);
        certificateAsyncClient.updateCertificate(certificate)
            .subscribe(certificateResponse ->
                System.out.printf("Certificate's enabled status %s %n",
                    certificateResponse.enabled().toString()));
    });
    
public Certificate updateCertificate(CertificateBase certificate);
public Response<Certificate> updateCertificateWithResponse(CertificateBase certificate, Context context);

Certificate certificate = certificateClient.getCertificateWithPolicy("certificateName");
Map<String, String> tags = new HashMap<>();
tags.put("foo", "bar");
// Update certificate enabled status
certificate.enabled(false);
Certificate updatedCertificate = certificateClient.updateCertificate(certificate);
System.out.printf("Updated Certificate with name %s and enabled status %s", updatedCertificate.name(),
    updatedCertificate.enabled());

```

### .NET
```net
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

certificateAsyncClient.getCertificatePolicy("certificateName")
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(certificatePolicyResponseValue -> {
        CertificatePolicy certificatePolicy = certificatePolicyResponseValue;
        // Update transparency
        certificatePolicy.certificateTransparency(true);
        certificateAsyncClient.updateCertificatePolicy("certificateName", certificatePolicy)
            .subscribe(updatedPolicy ->
                System.out.printf("Certificate policy's updated transparency status %s %n",
                    updatedPolicy.certificateTransparency().toString()));
    });

public CertificatePolicy updateCertificatePolicy(String certificateName, CertificatePolicy policy);
public Response<CertificatePolicy> updateCertificatePolicyWithResponse(String certificateName, CertificatePolicy policy, Context context);

CertificatePolicy certificatePolicyToUpdate = certificateClient.getCertificatePolicy("certificateName");
//Update the certificate policy cert transparency property.
certificatePolicyToUpdate.certificateTransparency(true);
Response<CertificatePolicy> updatedCertPolicyWithResponse = certificateClient
    .updateCertificatePolicyWithResponse("certificateName", certificatePolicyToUpdate,
        new Context(key1, value1));
System.out.printf("Updated Certificate Policy transparency status %s", updatedCertPolicyWithResponse
    .getValue().certificateTransparency());
```

### .NET
```net
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
```net
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
```net
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



```

### .NET
```net
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
```net
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
```net
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
```net
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
public PagedFlux<CertificateBase> listCertificates(Boolean includePending);
public PagedFlux<CertificateBase> listCertificates();



public PagedIterable<CertificateBase> listCertificates();
public PagedIterable<CertificateBase> listCertificates(boolean includePending, Context context);

```

### .NET
```net
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
public PagedFlux<CertificateBase> listCertificateVersions(String name);

public PagedIterable<CertificateBase> listCertificateVersions(String name);
public PagedIterable<CertificateBase> listCertificateVersions(String name, Context context);

```

### .NET
```net
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
```net
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

### Java
```java
public Mono<Issuer> createCertificateIssuer(String name, String provider);
public Mono<Issuer> createCertificateIssuer(Issuer issuer);
public Mono<Response<Issuer>> createCertificateIssuerWithResponse(Issuer issuer);
            
public Issuer createCertificateIssuer(String name, String provider);
public Issuer createCertificateIssuer(Issuer issuer);
public Response<Issuer> createCertificateIssuerWithResponse(Issuer issuer, Context context)
```

### .NET
```net
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

### Java
```java
public Mono<Response<Issuer>> getCertificateIssuerWithResponse(String name);
public Mono<Issuer> getCertificateIssuer(String name);
public Mono<Issuer> getCertificateIssuer(IssuerBase issuerBase);
                
public Response<Issuer> getCertificateIssuerWithResponse(String name, Context context);
public Issuer getCertificateIssuer(String name);
public Issuer getCertificateIssuer(IssuerBase issuerBase);
```

### .NET
```net
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

### Java
```java
public Mono<Response<Issuer>> deleteCertificateIssuerWithResponse(String name);
public Mono<Issuer> deleteCertificateIssuer(String name);


public Response<Issuer> deleteCertificateIssuerWithResponse(String name, Context context);
public Issuer deleteCertificateIssuer(String name);
```

### .NET
```net
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

### Java
```java
public PagedFlux<IssuerBase> listCertificateIssuers();


public PagedIterable<IssuerBase> listCertificateIssuers();
public PagedIterable<IssuerBase> listCertificateIssuers(Context context);
```

### .NET
```net
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

### Java
```java
public Mono<Issuer> updateCertificateIssuer(Issuer issuer);
public Mono<Response<Issuer>> updateCertificateIssuerWithResponse(Issuer issuer);



public Issuer updateCertificateIssuer(Issuer issuer);
public Response<Issuer> updateCertificateIssuerWithResponse(Issuer issuer, Context context);
```

### .NET
```net
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

### Java
```java


```

### .NET
```net
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
    def cancel_certificate_operation(self, name, **kwargs):

```

### .NET
```net
        public virtual CertificateOperation CancelCertificateOperation(string certificateName, CancellationToken cancellationToken = default)

        public virtual async Task<CertificateOperation> CancelCertificateOperationAsync(string certificateName, CancellationToken cancellationToken = default)

```
### Python
```python

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
  public async deleteCertificateOperation(
    name: string,
    options?: RequestOptionsBase
  ): Promise<CertificateOperation>
```

### .NET
```net
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

### Java
```java
public PagedFlux<Contact> setCertificateContacts(List<Contact> contacts);



public PagedIterable<Contact> setCertificateContacts(List<Contact> contacts);
public PagedIterable<Contact> setCertificateContacts(List<Contact> contacts, Context context);
```

### .NET
```net
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
public PagedFlux<Contact> listCertificateContacts();
    
public PagedIterable<Contact> listCertificateContacts();
public PagedIterable<Contact> listCertificateContacts(Context context);
```

### .NET
```net
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

### Java
```java
public PagedFlux<Contact> deleteCertificateContacts();


public PagedIterable<Contact> deleteCertificateContacts();
public PagedIterable<Contact> deleteCertificateContacts(Context context);
```

### .NET
```net
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
```net

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
```net

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

### Java
```java


```

### .NET
```net
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


