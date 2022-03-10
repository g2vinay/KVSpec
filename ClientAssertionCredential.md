### Conext
Adds Support for Azure AD Client Assertion authentication flow.
Allows the end users to exchange a signed JWT token for an AAD access token.

### Use case
Azure Kubernetes and GitHub are looking to provide end users with signed JWT Tokens which can be exchanged for AAD access tokens.


#### Pros
* Client Secret is no longer used, avoids the security risk of it being leaked.
* Client Assertin allows clients to use X.509 certificate to prove token request came from the client. Easier to restrict access to a certificate installed on a web server than to ensure nobody accidentally reveals a client secret. 

### API

![image](https://user-images.githubusercontent.com/5430778/157739237-405d180d-7943-49e3-81a5-f8a0d6a7fc39.png)

#### Code Sample

##### Java
```java
ClientAssertionCredential clientAssertionCredential = new ClientAssertionCredentialBuilder()
        .clientId("Client-Id")
        .tenantId("Tenant-Id")
        .clientAssertion(() -> parseClientAssertion(System.getenv(AZURE_FEDERATED_TOKEN_FILE)))
        .build();

AccessToken accessToken = clientAssertionCredential
  .getToken(new TokenRequestContext().addScopes("http://vault.azure.net/.default")).block();

```
