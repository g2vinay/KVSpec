### Context
Adds Support for Azure AD Client Assertion authentication flow.
Allows the end users to exchange a signed JWT token for an AAD access token.

### Use case
Azure Kubernetes and GitHub are looking to provide end users with signed JWT Tokens which can be exchanged for AAD access tokens.


#### Pros
* Client Secret is no longer used, avoids the security risk of it being leaked.
* Client Assertion allows clients to use X.509 certificate or a pre-signed JWT assertion to prove token request came from the client. Easier to restrict access to a certificate installed on a web server than to ensure nobody accidentally reveals a client secret. 
* Authentication is not limited to Azure Host, e.g. Kubernetes Instance issuing JWT tokens in AWS can be used to exchange tokens with Azure AD, as long as Certificate Issuer is registered/trusted in Azure AD.

### API

![image](https://user-images.githubusercontent.com/5430778/157745060-6c47709d-2154-4140-8c13-62ec944cd82c.png)

#### Code Sample

##### Java
```java
ClientAssertionCredential clientAssertionCredential = new ClientAssertionCredentialBuilder()
        .clientId("Client-Id")
        .tenantId("Tenant-Id")
        .clientAssertion(() -> readClientAssertion(System.getenv(AZURE_FEDERATED_TOKEN_FILE)))
        .build();

AccessToken accessToken = clientAssertionCredential
  .getToken(new TokenRequestContext().addScopes("http://vault.azure.net/.default")).block();

```
