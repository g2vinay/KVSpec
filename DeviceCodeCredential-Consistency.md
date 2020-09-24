## Device Code Credential Review

### Input Parameters

**AuthorityHost**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `AuthorityHost` | No | "https://login.microsoftonline.com/" | Must be a valid Uri, validation done by URI constructor | N/A 
 | Java | `authorityHost` | No | "https://login.microsoftonline.com/" | 1. Valid URI, 2. Follow `HTTPS` protocol | 1. "Must provide a valid URI for authority host.", 2. "Authority host must use `HTTPS` scheme."
 | JS/TS | ? | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? | ? 
 | C | ? | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? | ? 
 
 
 **ClientId**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `clientId` or `ClientId` | No | "04b07795-8ddb-461a-bbee-02f9e1bf7b46" | If specified, must be non-null |  ArgumentNullException "clientId"
 | Java | `clientId` | Yes | N/A | 1. Must be non-null, 2.Character range validated | 1. "Must provide non-null values for clientId property in DeviceCodeCredentialBuilder.", 2."Client id must have characters in the range of [A-Z], [0-9], [a-z], '-'"
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
 
  **TenantId**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `tenantId` or `TenantId` | No | "organizations" | None | N/A 
 | Java | `tenantId` | No | "organizations" | None | N/A 
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
  **Callback / Challenge**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `deviceCodeCallback` | No | Default implementation writes message to console | If specified must be non-null | ArgumentNullException "deviceCodeCallback"
 | Java | `challengeConsumer` | No | Default implementation writes message to console | If specified must be non-null | "Must provide non-null values for challengeConsumer property in DeviceCodeCredentialBuilder."
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
 
  **Authentication Record**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `AuthenticationRecord` | No | null | None | N/A 
 | Java | `authenticationRecord` | No | null | None | N/A 
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
 
  **Automatic Authentication**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `DisableAutomaticAuthentication` | No | false | None | N/A 
 | Java | `disableAutomaticAuthentication` | No | false | None | N/A
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
 
  **Unencrypted Cache**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `AllowUnencryptedCache` | No | false | None | N/A 
 | Java | `allowUnencryptedCache` | No | false | None | N/A
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
 
 **Persistent Cache**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `EnablePersistentCache` | No | false | None | N/A 
 | Java | `enablePersistentCache` | No | false | None | N/A
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
 
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
 | .NET | ? | ? | ? | ? | ?
 | Java |  `AZURE_AUTHORITY_HOST` | No | "https://login.microsoftonline.com/" | 1. Valid URI,  2.Follow `HTTPS` protocol | 1. "Must provide a valid URI for authority host.", 2."Authority host must use `HTTPS` scheme."
 | JS/TS | ? | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? | ? 
 | C | ? | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? | ? 
 
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
??
```

**JS/TS**
```
??
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

#### Minimal Credential Config needed by user

**Device Code Info Message**

Language | Message |
--- | --- | 
 | .NET | "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code XXXXXXXX to authenticate." | 
 | Java | "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code XXXXXXXX to authenticate." | 
 | JS/TS | ? | 
 | Python | ? | 
 | Go | ? | 
 | C | ? | 
 | C++ | ? |
 
 **Authentication Failure Message**

**.NET**
 Scenario | Exception Type | Message | 
--- | --- | --- |
 | ? | ? | ? |
 | ? | ? | ? | 
 | ? | ? | ? | 
 | ? | ? | ? | 
 
 **Java**
 Scenario | Exception Type | Message | 
--- | --- | --- |
 | ? | ? | ? |
 | ? | ? | ? | 
 | ? | ? | ? | 
 | ? | ? | ? | 
 
 **Python**
 Scenario | Exception Type | Message | 
--- | --- | --- |
 | ? | ? | ? |
 | ? | ? | ? | 
 | ? | ? | ? | 
 | ? | ? | ? | 
 
 **JS/TS**
 Scenario | Exception Type | Message | 
--- | --- | --- |
 | ? | ? | ? |
 | ? | ? | ? | 
 | ? | ? | ? | 
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
 | ? | ? | ? |
 | ? | ? | ? | 
 | ? | ? | ? | 
 | ? | ? | ? | 
 
 **Java**
 Scenario | Log Level | Log Message | 
--- | --- | --- |
 | ? | ? | ? |
 | ? | ? | ? | 
 | ? | ? | ? | 
 | ? | ? | ? | 
 
 **Python**
 Scenario | Log Level | Log Message | 
--- | --- | --- |
 | ? | ? | ? |
 | ? | ? | ? | 
 | ? | ? | ? | 
 | ? | ? | ? | 
 
 **JS/TS**
 Scenario | Log Level | Log Message | 
--- | --- | --- |
 | ? | ? | ? |
 | ? | ? | ? | 
 | ? | ? | ? | 
 | ? | ? | ? | 


//TODO: Add and Discuss Language specific logging scenarios (which can be potentially applied across the board)



 
