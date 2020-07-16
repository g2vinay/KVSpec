- Give application control over when users are prompted to authenticate
    - Add `authenticate` methods to `InteractiveBrowserCredential` and `DeviceCodeCredential`
    - The option `disableAutomaticAuthentication` can be specified on credential builders to disable automatic prompting of users when `getToken` is called.
    - Add `AuthenticationRequiredException` which can be handled to manually prompt users to authenticate.
  - Persist user authentication details between executions
    - The newly added `AuthenticationRecord` is returned from `authenticate` calls
    - `AuthenticationRecord` supports `serialize` and `deserialize`
    - Added 'enablePersistentCache' option to allow for the persistence of the tokens to the shared token cache

## Expected Usage
### Prompt the user to authenticate and store the AuthenticationRecord
~~~ java
  InteractiveBrowserCredential credential = new InteractiveBrowserCredentialBuilder()
          .clientId("<Client-ID>")
          .enablePersistentCache()
          .disableAutomaticAuthentication()
          .build();

  FileOutputStream outputStream = new FileOutputStream("./profile.json");
  credential.authenticate()
          .flatMap(authenticationRecord -> authenticationRecord.serialize(outputStream))
          .map(outputStreamResponse -> {
              try {
                  outputStreamResponse.close();
                  return Mono.empty();
              } catch (IOException e) {
                  return Mono.error(e);
              }
          }).block();
~~~

### Create a credential from a pre-existing AuthenticationRecord
~~~ java
  FileInputStream inputStream = new FileInputStream("./profile.json");
  InteractiveBrowserCredential interactiveBrowserCredential = AuthenticationRecord.deserialize(inputStream)
          .map(authenticationRecord ->
              new InteractiveBrowserCredentialBuilder()
                      .clientId("<Client-ID>")
                      .authenticationRecord(authenticationRecord)
                      .disableAutomaticAuthentication()
                      .enablePersistentCache()
                      .build()
          ).block();
~~~

### Using a credential to manually authenticate with a service client and handling AuthenticationRequiredException
~~~ java
  SecretClient client = new SecretClientBuilder()
          .vaultUrl("https://myvault.vault.azure.net/")
          .credential(interactiveBrowserCredential)
          .buildClient();

  try {
      client.getSecret("secret");
  }
  catch (AuthenticationRequiredException e) {
      interactiveBrowserCredential.authenticate(e.getTokenRequestContext());
  }
  client.getSecret("secret");
~~~
