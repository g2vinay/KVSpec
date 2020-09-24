## Device Code Credential Review

### Input Parameters

**AuthorityHost**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `AuthorityHost` | No | "https://login.microsoftonline.com/" | Must be a valid Uri, validation done by URI constructor | N/A 
 | Java | ? | ? | ? | ? | ? 
 | JS/TS | ? | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? | ? 
 | C | ? | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? | ? 
 
 
 **ClientId**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `clientId` or `ClientId` | No | "04b07795-8ddb-461a-bbee-02f9e1bf7b46" | If specified, must be non-null |  ArgumentNullException "clientId"
 | Java | ? | ? | ? | ? 
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
 
  **TenantId**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `tenantId` or `TenantId` | No | "organizations" | None | N/A 
 | Java | ? | ? | ? | ? 
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
  **Callback / Challenge**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `deviceCodeCallback` | No | Default implementation writes message to console | If specified must be non-null | ArgumentNullException "deviceCodeCallback"
 | Java | ? | ? | ? | ? 
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
 
  **Authentication Record**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | AuthenticationRecord | No | null | none | N/A 
 | Java | ? | ? | ? | ? 
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
 
  **Automatic Authentication**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `DisableAutomaticAuthentication` | No | false | none | N/A 
 | Java | ? | ? | ? | ? 
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
 
  **Unencrypted Cache**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `AllowUnencryptedCache` | No | false | none | N/A 
 | Java | ? | ? | ? | ? 
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
 
 **Persistent Cache**

Language | Name | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- | --- |---  
 | .NET | `EnablePersistentCache` | No | false | none | N/A 
 | Java | ? | ? | ? | ? 
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
 
 #### Language Specific Input parameters

  **Executor Service** (Java only)
  
Language | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- |---  
 | Java | ? | ? | ? | ? 
 
 //TODO: Add and Discuss Language specific input parameters (which can be potentially applied across the board)


 
 </br>
 </br>
 </br>
 
 ### Environment Variables

**AUTHORITY HOST**
 Language | Required ? | Default Value | Validations | Validation Failure Message 
--- | --- | --- | --- |---  
 | .NET | ? | ? | ? | ? 
 | Java | ? | ? | ? | ? 
 | JS/TS | ? | ? | ? | ? 
 | Python | ? | ? | ? | ? 
 | Go | ? | ? | ? | ? 
 | C | ? | ? | ? | ? 
 | C++ | ? | ? | ? | ? 
 
 </br>
 </br>
 </br>
 
### User Scenarios

#### Minimal Credential Config needed by user

**Java**
```
??
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
??
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
 | Java | ? | 
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



 
