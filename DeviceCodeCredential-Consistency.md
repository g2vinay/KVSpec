## Device Code Credential Review

### Input Parameters

**AuthorityHost**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `AuthorityHost` | No | "https://login.microsoftonline.com/" | Must be a valid Uri, validation done by URI constructor | N/A 
 | Java | `authorityHost` | No | "https://login.microsoftonline.com/" | 1. Valid URI <br>2.Follow `HTTPS` protocol | 1. "Must provide a valid URI for authority host." <br>2."Authority host must use `HTTPS` scheme."
 | JS/TS | `AZURE_AUTHORITY_HOST` | No | "https://login.microsoftonline.com/" | Follow `HTTPS` protocol | "The authorityHost address must use the 'https' protocol." 
 | Python | `authority` | No | "https://login.microsoftonline.com/ | Follow `HTTPS` protocol | "'{}' is an invalid authority. The value must be a TLS protected (https) URL."
 | Go | ? | ? | ? | ? | ? 
 
 
 **ClientId**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `clientId` or `ClientId` | No | "04b07795-8ddb-461a-bbee-02f9e1bf7b46" | If specified, must be non-null |  ArgumentNullException "clientId"
 | Java | `clientId` | Yes | N/A | 1. Must be non-null, 2.Character range validated | 1. "Must provide non-null values for clientId property in DeviceCodeCredentialBuilder."<br> 2."Client id must have characters in the range of [A-Z], [0-9], [a-z], '-'"
 | JS/TS | `clientId` | Yes | N/A | None | N/A 
 | Python | `client_id` | Yes | N/A | None | N/A 
 | Go | ? | ? | ? | ? 
 
 
  **TenantId**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `tenantId` or `TenantId` | No | "organizations" | None | N/A 
 | Java | `tenantId` | No | "organizations" | None | N/A 
 | JS/TS | `tenantId` | No | "organizations" | None | N/A 
 | Python | `tenantId` | No | "organizations" | None | N/A
 | Go | ? | ? | ? | ? 
 
  **Callback / Challenge**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `deviceCodeCallback` | No | Default implementation writes message to console | If specified must be non-null | ArgumentNullException "deviceCodeCallback"
 | Java | `challengeConsumer` | No | Default implementation writes message to console | If specified must be non-null | "Must provide non-null values for challengeConsumer property in DeviceCodeCredentialBuilder."
 | JS/TS | `userPromptCallback` | No | Default implementation writes message to console | None | N/A 
 | Python | `prompt_callback` | No | Default implementation writes message to console | None | N/A 
 | Go | ? | ? | ? | ? 
 
 
  **Authentication Record**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `AuthenticationRecord` | No | null | None | N/A 
 | Java | `authenticationRecord` | No | null | None | N/A 
 | JS/TS | N/A | N/A | N/A | N/A 
 | Python | `authentication_record` | No | None | None | N/A 
 | Go | ? | ? | ? | ? 
 
 
  **Automatic Authentication**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `DisableAutomaticAuthentication` | No | false | None | N/A 
 | Java | `disableAutomaticAuthentication` | No | false | None | N/A
 | JS/TS | N/A | N/A | N/A | N/A 
 | Python | `disable_automatic_authentication` | No | False | None | N/A
 | Go | ? | ? | ? | ? 
 
 
  **Unencrypted Cache**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `AllowUnencryptedCache` | No | false | None | N/A 
 | Java | `allowUnencryptedCache` | No | false | None | N/A
 | JS/TS | N/A | N/A | N/A | N/A 
 | Python | `allow_unencrypted_cache` | No | False | None | N/A 
 | Go | ? | ? | ? | ?  
 
 
 **Persistent Cache**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `EnablePersistentCache` | No | false | None | N/A 
 | Java | `enablePersistentCache` | No | false | None | N/A
 | JS/TS | N/A | N/A | N/A | N/A 
 | Python | `enable_persistent_cache` | No | False | None | N/A 
 | Go | ? | ? | ? | ? 
 
 
 #### Language Specific Input parameters

  **Executor Service** (Java only)
  
Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- |--- |---  
 | Java | `executorService` | No | null | None | N/A 
 
 
 **Timeout** (Python only)
  
Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- |--- |---  
 | Python | `timeout` | No | None | None | N/A 
 
 //TODO: Add and Discuss Language specific input parameters (which can be potentially applied across the board)


 
 </br>
 </br>
 </br>
 
 ### Environment Variables

**AUTHORITY HOST**


 Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- |--- |--- 
 | .NET | ? | ? | ? | ? | ?
 | Java |  `AZURE_AUTHORITY_HOST` | No | "https://login.microsoftonline.com/" | 1. Valid URI,  2.Follow `HTTPS` protocol | 1. "Must provide a valid URI for authority host."<br> 2."Authority host must use `HTTPS` scheme."
 | JS/TS | `AZURE_AUTHORITY_HOST` | No | "https://login.microsoftonline.com/" | Follow `HTTPS` protocol | "The authorityHost address must use the 'https' protocol." 
 | Python | `AZURE_AUTHORITY_HOST` | No | "https://login.microsoftonline.com/" | Follow `HTTPS` protocol | "'{}' is an invalid authority. The value must be a TLS protected (https) URL."
 | Go | ? | ? | ? | ? | ? 
 
 </br>
 </br>
 </br>
 
### User Scenarios

#### Minimal Credential Config needed by user

**Java**
```java
DeviceCodeCredential deviceCodeCredential = new DeviceCodeCredentialBuilder()
        .clientId("<Client-Id>")
        .build();
```

**.NET**
```c#
var credential = new DeviceCodeCredential();
```

**Python**
```
DeviceCodeCredential("client_id")
```

**JS/TS**
```
const credential = new DeviceCodeCredential(
    undefined,
    "CLIENT_ID"
  );
```

#### Maximum Credential Config possible by user

**Java**
```
 DeviceCodeCredential deviceCodeCredentialghj = new DeviceCodeCredentialBuilder()
         .authorityHost(AzureAuthorityHosts.AZURE_PUBLIC_CLOUD)
         .clientId("Client-Id")
         .tenantId("Tenant-Id")
         .disableAutomaticAuthentication()
         .enablePersistentCache()
         .allowUnencryptedCache()
         .authenticationRecord(authenticationRecord)
         .challengeConsumer(deviceCodeInfo -> System.out.println(deviceCodeInfo.getMessage()))
         .executorService(Executors.newSingleThreadExecutor())
         .httpClient(HttpClient.createDefault())
         .httpPipeline(httpPipeline)
         .build();
```

**.NET**
```c#
options = new DeviceCodeCredentialOptions {
  AuthorityHost = AzureAuthorityHosts.AzurePublicCloud,
  ClientId = "xxx",
  TenantId = "xxx",
  DisableAutomaticAuthentication = false,
  EnablePersistentCache = false,
  AllowUnencryptedCache = false,
  AuthenticationRecord = authRecord
}
var credential = new DeviceCodeCredential()
```

**Python**
```
DeviceCodeCredential(
    "client_id",
    authority="...",
    tenant_id="...",
    timeout=42,
    prompt_callback=lambda verification_uri, user_code, expires_on: None,
    authentication_record=...,
    enable_persistent_cache=True,
    allow_unencrypted_cache=True,
)
```

**JS/TS**
```
const credential = new DeviceCodeCredential(
    "TENANT_ID",
    "CLIENT_ID",
    (details) => console.log({ details }),
    { authorityHost: "https://adfs.redmond.azurestack.corp.microsoft.com" }
  );
```
 </br>
 </br>
 </br>
 
### Messages (Success + Failure) displayed to user.

**Device Code Info Message**

Language | Message |
--- | --- | 
 | .NET | "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code XXXXXXXX to authenticate." | 
 | Java | "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code XXXXXXXX to authenticate." | 
 | JS/TS | "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code XXXXXXXX to authenticate." | 
 | Python | "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code XXXXXXXX to authenticate." | 
 | Go | ? | 
 | C | ? | 
 | C++ | ? |
 
 **Authentication Failure Message**

**.NET**
 Scenario | Exception/Error Type | Message | 
--- | --- | --- |
 | ? | ? | ? |
 | ? | ? | ? | 
 | ? | ? | ? | 
 | ? | ? | ? | 
 
 **Java**
 Scenario | Exception/Error Type | Message | 
--- | --- | --- |
 | Automatic Authentication disabled and Get Token is called without calling authenticate first  | `AuthenticationRequiredException` | "Interactive authentication is needed to acquire token. Call Authenticate to initiate the device code authentication." |
 | Scope cannot be determined for authority host in authenticate method. | `CredentialUnavailableException` | "Authenticating in this environment requires specifying a TokenRequestContext." | 
 | Authentication issue on MSAL end | `ClientAuthenticationException` | "Failed to acquire token with device code" | 
 
 **Python**
 Scenario | Exception/Error Type | Message | 
--- | --- | --- |
 | MSAL issue in Intiating device flow | `ClientAuthenticationError` | "Couldn't begin authentication: {Error Details from MSAL}" |
 | MSAL timed out waiting for user to authenticate | `ClientAuthenticationError` | "Timed out waiting for user to authenticate" | 
 | MSAL Authentication issue | `ClientAuthenticationError` | "Authentication failed: {MSAL error details/description}"" |
 | Scope cannot be determined for authority host in authenticate method. | `CredentialUnavailableError` | "Authenticating in this environment requires a value for the 'scopes' keyword argument." | 
 | Automatic Authentication disabled and Get Token is called without calling authenticate first  | `AuthenticationRequiredError` | "Interactive authentication is required to get a token. Call 'authenticate' to begin. |
 | No Scope passed in | ValueError | "'get_token' requires at least one scope" | 


 **JS/TS**
 Scenario | Exception/Error Type | Message | 
--- | --- | --- |
 | Authentication issue on MSAL end | `Error` | "Device Authentication Error + MSAL Error Details" | 


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
 | ? | ? | ? |
 | ? | ? | ? | 
 | ? | ? | ? | 
 | ? | ? | ? | 
 
 **Java**
 Scenario | Log Level | Log Message | 
--- | --- | --- |
 | Token Fetch Success | INFO | Azure Identity => getToken() result for scopes [{}]: SUCCESS|
 | Token Fetch Failure | ERROR | Azure Identity => ERROR in getToken() call for scopes [{}]: {} | 
 | Any Exception | ERROR | Error Message in the Exception | 
 
 **Python**
 Scenario | Log Level | Log Message | 
--- | --- | --- |
 | Any Error raised in Get token | WARN | "{ClassName}.get_token failed: {Error Details}" |
 | Token Fetch Success | INFO | "{ClassName}.get_token succeeded" | 
 
 **JS/TS**
 Scenario | Log Level | Log Message | 
--- | --- | --- |
 | Error from MSAL | INFO | Message in the Error |


//TODO: Add and Discuss Language specific logging scenarios (which can be potentially applied across the board)



 
