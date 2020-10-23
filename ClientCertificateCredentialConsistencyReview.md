## Client Certificate Credential Review

In Python, its called Certificate Credential.

### Input Parameters

**AuthorityHost**
Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `AuthorityHost` | No | "https://login.microsoftonline.com/" | Must be a valid Uri, validation done by URI constructor | N/A 
 | Java | `authorityHost` | No | "https://login.microsoftonline.com/" | 1. Valid URI <br>2.Follow `HTTPS` protocol | 1. "Must provide a valid URI for authority host." <br>2."Authority host must use `HTTPS` scheme."
 | JS/TS | `authorityHost` | No | "https://login.microsoftonline.com/" | Follow `HTTPS` protocol | "The authorityHost address must use the 'https' protocol." 
 | Python | `authority` | No | "https://login.microsoftonline.com/" | Follow `HTTPS` protocol | "'{}' is an invalid authority. The value must be a TLS protected (https) URL."
 | Go | `AuthorityHost` | No | "https://login.microsoftonline.com/" | None | N/A
 
 
 **ClientId**
Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `clientId` or `ClientId` | Yes | No | must be non-null |  ArgumentNullException "clientId"
 | Java | `clientId` | Yes | N/A | 1. Must be non-null, 2.Character range validated | 1. "Must provide non-null values for clientId property in DeviceCodeCredentialBuilder."<br> 2."Client id must have characters in the range of [A-Z], [0-9], [a-z], '-'"
 | JS/TS | `clientId` | Yes | N/A | None | N/A 
 | Python | `client_id` | Yes | N/A | None | N/A 
 | Go | `clientID` | Yes | N/A | None | N/A 
 
 
 **TenantId**
Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `tenantId` or `TenantId` | Yes | N/A | None | N/A 
 | Java | `tenantId` | Yes | N/A | 1. Must be non-null, 2.Character range validated | 1. "Must provide non-null values for tenantId property in DeviceCodeCredentialBuilder."<br> 2."Tenant id must have characters in the range of [A-Z], [0-9], [a-z], '-', '.'"
 | JS/TS | `tenantId` | Yes | N/A | N/A 
 | Python | `tenant_id` | Yes | N/A | None | N/A
 | Go | `tenantID` | Yes | N/A | None | N/A 
 
 
**Certificate (X509)**
Language | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- |---  
 | .NET | `certificate` | Yes | No | Must be non-null |  ArgumentNullException "Certificate"
 | Java | N/A | N/A | N/A | N/A 
 | JS/TS | N/A | N/A | N/A | N/A 
 | Python | N/A | N/A | N/A | N/A 
 | Go | ? | ? | ? | ? 
 
 
**Certificate Path**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- | ---
 | .NET | `clientCertificatePath` | Yes | No | Must be non-null |  ArgumentNullException "certificatePath"
 | Java | `pemCertificate` / `pfxCertificate`| Yes | No | 1. Must be non-null, 2.File Path validation | 1. "Must provide non-null values for clientCertificate property in ClientCertificateCredentialBuilder."<br> 2."<PATH> is not valid. The path contains invalid characters `.` or `..`"
 | JS/TS | `certificatePath` | Yes | No | No | N/A
 | Python | `certificate_path` | Yes | No | Must not be None |  "'certificate_path' must be the path to a PEM file containing an x509 certificate and its private key"
 | Go | ? | ? | ? | ? | ?
 
 **Password**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- | ---
 | .NET | Not available | N/A | N/A | N/A | N/A
 | Java | Not available | N/A | N/A | N/A | N/A
 | JS/TS | Not available | N/A | N/A | N/A | N/A 
 | Python | `password` | No | None | No |  N/A
 | Go | ? | ? | ? | ? 
 
 
 
 **Send Certificate Chain**
Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- | ---
 | .NET | `IncludeX5CClaimHeader` | No | false | No | N/A 
 | Java | `includeX5c` | No | false | No | N/A 
 | JS/TS | `includeX5c` | No | false | No | N/A
 | Python | `send_certificate` | No | false | No | N/A 
 | Go | ? | ? | ? | ? 
 
 
  **Unencrypted Cache**
Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `AllowUnencryptedCache` | No | false | None | N/A 
 | Java | `allowUnencryptedCache` | No | false | None | N/A
 | JS/TS | N/A | N/A | N/A | N/A 
 | Python | `allow_unencrypted_cache` | No | False | None | N/A 
 | Go | N/A | N/A | N/A | N/A  
 
 
 **Persistent Cache**
Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `EnablePersistentCache` | No | false | None | N/A 
 | Java | `enablePersistentCache` | No | false | None | N/A
 | JS/TS | N/A | N/A | N/A | N/A 
 | Python | `enable_persistent_cache` | No | False | None | N/A 
 | Go | N/A | N/A | N/A | N/A 
 
 
 #### Language Specific Input parameters

  **Executor Service** (Java only)
  
Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- |--- |---  
 | Java | `executorService` | No | null | None | N/A 
 
 //TODO: Add and Discuss Language specific input parameters (which can be potentially applied across the board)
 
 </br>
 </br>
 </br>
 
 ### Environment Variables

**AUTHORITY HOST**
 Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- |--- |--- 
 | .NET | `AZURE_AUTHORITY_HOST` | No | "https://login.microsoftonline.com/" |Must be a valid Uri, validation done by URI constructor | N/A 
 | Java |  `AZURE_AUTHORITY_HOST` | No | "https://login.microsoftonline.com/" | 1. Valid URI,  2.Follow `HTTPS` protocol | 1. "Must provide a valid URI for authority host."<br> 2."Authority host must use `HTTPS` scheme."
 | JS/TS | `AZURE_AUTHORITY_HOST` | No | "https://login.microsoftonline.com/" | Follow `HTTPS` protocol | "The authorityHost address must use the 'https' protocol." 
 | Python | `AZURE_AUTHORITY_HOST` | No | "https://login.microsoftonline.com/" | Follow `HTTPS` protocol | "'{}' is an invalid authority. The value must be a TLS protected (https) URL."
 | Go | `AZURE_AUTHORITY_HOST` | No | "https://login.microsoftonline.com/" | None | N/A
 
 </br>
 </br>
 </br>
 
### User Scenarios

#### Minimal Credential Config needed by user

**Java**
```
ClientCertificateCredential certificateCredential = new ClientCertificateCredentialBuilder()
        .pemCertificate("Certificate-Path")
        .clientId("xxxx-xxxxxx-xxxxxx-xxxx")
        .tenantId("xxxx-xxxxxx-xxxxxx-xxxx")
        .build();
        
        OR
        
ClientCertificateCredential certificateCredential = new ClientCertificateCredentialBuilder()
        .pfxCertificate("Certificate-Path", "<Cert-Password>")
        .clientId("xxxx-xxxxxx-xxxxxx-xxxx")
        .tenantId("xxxx-xxxxxx-xxxxxx-xxxx")
        .build();
```

**.NET**
```
??
```

**Python**
```
??
```

**JS/TS**
```
??
```

#### Maximum Credential Config possible by user

**Java**
```java
 ClientCertificateCredential certificateCredential = new ClientCertificateCredentialBuilder()
         .pemCertificate("Certificate-Path")
         .pfxCertificate("Certificate-Path", "Cert-password")
         .clientId("xxxx-xxxxxx-xxxxxx-xxxx")
         .tenantId("yyyy-yyyyyy-yyyyyy-yyyy")
         .authorityHost(AzureAuthorityHosts.AZURE_PUBLIC_CLOUD)
         .includeX5c(true)
         .allowUnencryptedCache()
         .enablePersistentCache()
         .executorService(Executors.newSingleThreadExecutor())
         .httpClient(HttpClient.createDefault())
         .httpPipeline(new HttpPipelineBuilder().build())
         .build();
```

**.NET**
```
??
```

**Python**
```
??
```

**JS/TS**
```
??
```
 </br>
 </br>
 </br>
 
### Messages (Success + Failure) displayed to user.

**Authentication Failure Message**

**.NET**
 Scenario | Exception/Error Type | Message | 
--- | --- | --- |
 | CertPath File doesn't have .pem or .pfx suffix | `CredentialUnavailableException` | Only .pfx and .pem files are supported. |
 | Certificate File Reading Issue | `CredentialUnavailableException` | "Could not load certificate file"
 | Failure due to unhandled exception | `AuthenticationFailedException` | ClientCertificateCredential authentication failed: {inner exception message}| 
 
 **Java**
 Scenario | Exception/Error Type | Message | 
--- | --- | --- |
 | Authentication issue on MSAL end | <MSAL Exception Type> | <MSAL Failure Message> |
 
 **Python**
 Scenario | Exception/Error Type | Message | 
--- | --- | --- |
 | Issue Extracting Cert Chain | `ValueError` | Found no PEM encoded certificate in "<Cert-Path>" |
 | MSAL Authentication issue | `ClientAuthenticationError` | "Authentication failed: {MSAL error details/description}"" |
 | Scope cannot be determined for authority host in authenticate method. | `CredentialUnavailableError` | "Authenticating in this environment requires a value for the 'scopes' keyword argument." | 
 | Automatic Authentication disabled and Get Token is called without calling authenticate first  | `AuthenticationRequiredError` | "Interactive authentication is required to get a token. Call 'authenticate' to begin. |
 | No Scope passed in Get Token | ValueError | "'get_token' requires at least one scope" | 


 **JS/TS**
 Scenario | Exception/Error Type | Message | 
--- | --- | --- |
 | PEM file doesn't contain PEM cert | Error |"The file at the specified path does not contain a PEM-encoded certificate. 
 | Auth Issue| `AuthenticationError` | <Rest Response Error Message & Response Status> | 


**GO**
 Scenario | Exception/Error Type | Message | 
--- | --- | --- |
 | ? | ? | ? |

//TODO: Add and Discuss Language specific error messages (which can be potentially applied across the board)

 </br>
 </br>
 </br>

### Logging Scenarios 
Key Scenarios:
1. Token Fetch Success
2. Token Fetch Failure

**.NET**
 Scenario | Log Level | Log Message | 
--- | --- | --- |
 | GetToken Called | INFO | ClientCertificateCredential invoked. Scopes: {1} ParentRequestId: {2} |
 | GetToken Success | INFO | ClientCertificateCredential succeeded. Scopes: {1} ParentRequestId: {2} ExpiresOn: {3} |
 | GetToken Failure | INFO |  ClientCertificateCredential was unable to retrieve an access token. Scopes: {1} ParentRequestId: {2} | 
 | Unandled Exception | INFO | ClientCertificateCredential was unable to retrieve an access token. Scopes: {1} ParentRequestId: {2} Exception: {3} | 
 
 **Java**
 Scenario | Log Level | Log Message | 
--- | --- | --- |
 | Token Fetch Success | INFO | Azure Identity => getToken() result for scopes [{}]: SUCCESS|
 | Token Fetch Failure | ERROR | Azure Identity => ERROR in getToken() call for scopes [{}]: {} | 
 | Any Exception | ERROR | Error Message in the Exception | 
 
 **Python**
 Scenario | Log Level | Log Message | 
--- | --- | --- |
 | No Scenarios found | N/A | N/A |
 
 **JS/TS**
 Scenario | Log Level | Log Message | 
--- | --- | --- |
 | Auth Error / Validation Error | INFO | "ERROR: <ErrorMessage>" |
 | Token Fetch Success | INFO | "SUCCESS: <Scopes>"|

 
 **GO**
  Scenario | Log Level | Log Message | 
--- | --- | --- |
 | ? | ? | ? |
 | ?| ? | ? | 


//TODO: Add and Discuss Language specific logging scenarios (which can be potentially applied across the board)
