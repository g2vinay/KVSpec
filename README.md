

This is the first iteration, following Scott's .NET framework, it will change once I look at implmenentation side of Scott's framework.
It gives high level idea of the structure. 
Azure Identity is the most vague/unknown part, as it currently doesn't exist in any language (.NET in progress).
Azure Identity structure is expected to change.

# Java
## Azure Core/Common
### Credentials Classes
~~~ java
package com.azure.common.credentials;

    //This class already exists in azure core.
    public class TokenCredentials implements ServiceClientCredentials {
        /**
         * The authentication scheme.
         */
        private String scheme;

        /**
         * The secure token.
         */
        private String token;

        /**
         * Creates TokenCredentials.
         *
         * @param scheme scheme to use. If null, defaults to Bearer
         * @param token  valid token
         */
        public TokenCredentials(String scheme, String token) {
            if (scheme == null) {
                scheme = "Bearer";
            }
            this.scheme = scheme;
            this.token = token;
        }

        @Override
        public String authorizationHeaderValue(String uri) throws IOException {
            return scheme + " " + token;
        }
    }

    //Doesn't exist in azure core yet, exists in KV Secrets API within SecretAsyncClientBuilder
    public class AsyncTokenCredentials implements AsyncServiceClientCredentials {

        private String scheme;
        private Mono<String> token;

        AsyncTokenCredentials(String scheme, Mono<String> token) {
            this.scheme = scheme;
            this.token = token;
        }

        @Override
        public Mono<String> authorizationHeaderValueAsync(HttpRequest httpRequest) {
            if (scheme == null) {
                scheme = "Bearer";
            }
            return token.flatMap(tokenValue -> Mono.just("Bearer " + tokenValue));
        }
    }

~~~
### Authentication Policies
~~~ java
package com.azure.common.http.policy;

//The name is deceiving, but it does Authorization. It already exists in azure core/common for Java.
public class CredentialsPolicy implements HttpPipelinePolicy {
    private final ServiceClientCredentials credentials;

    /**
     * Creates CredentialsPolicy.
     *
     * @param credentials the credentials
     */
    public CredentialsPolicy(ServiceClientCredentials credentials) {
        this.credentials = credentials;
    }

    @Override
    public Mono<HttpResponse> process(HttpPipelineCallContext context, HttpPipelineNextPolicy next) {
        try {
            String token = credentials.authorizationHeaderValue(context.httpRequest().url().toString());
            context.httpRequest().headers().set("Authorization", token);
            return next.process();
        } catch (IOException e) {
            return Mono.error(e);
        }
    }
}

~~~
## Azure Identity
The azure com.azure.identity package provides implementations for Active Directory based OAuth token authentication.  It provides an abstraction above the authentication libraries provided by the Azure Identity team.  It also provides mechanisms for querying credential information from the environment.

### Credential Implementations
~~~ java
package com.azure.identity;

    // Use Fluent Pattern During Implementation
    //This is the package with most implementation needed.
    // Scott had the methods Static in his framework -- check the need and usage for it.
    public abstract class AzureCredential extends AsyncTokenCredentials {
        private AzureCredential(HttpPipelinePolicy policies) {
            client = getDefaultClient();
        }

        public List<HttpPipelinePolicy> createDefaultPipelinePolicies();
    }

    public class ClientSecretCredential extends AzureCredential {
        public ClientSecretCredential(String clientId, String clientSecret, String authority);
        public ClientSecretCredential(String clientId, String clientSecret, String authority, List<HttpPipelinePolicy> policies);

        @Override
        public Mono<String> authorizationHeaderValueAsync(HttpRequest httpRequest);
    }

    //Not in focus for now.
    public class ClientCertificateCredential extends AzureCredential {
        public ClientCertificateCredential(X509Certificate certificate, string authority, List<HttpPipelinePolicy> policies);
    }    

~~~
#### Questions / Open Issues:
- Should authority be required parameters?
- Possibly it's odd that these credential classes expose pipeline options when they're not "client" classes
    - Should we try to reuse the policies from the client class rather than having authentication calls have they're own pipeline.  Allowing us to avoid exposing options on the client (at least for now)   

### Credential Providers
~~~ java
package com.azure.identity;

    //Use Fluent Pattern during implementation
    public class TokenCredentialProvider extends AsyncTokenCredentials {
        protected TokenCredentialProvider();

        public TokenCredentialProvider(TokenCredentialProvider... credentialProviders);

        @Override
        public Mono<String> authorizationHeaderValueAsync(HttpRequest httpRequest); // full implementation


        // iterates through the chain of credential providers to find one which returns a credential if none
        // return credential raise exception (full chain on stack)
        protected Mono<TokenCredential> getCredential(HttpRequest httpRequest);
    }

    public class EnvironmentCredentialProvider extends TokenCredentialProvider
    {
        public EnvironmentCredentialProvider(List<HttpPipelinePolicy> policies);
        
        // if available return cred
        protected Mono<TokenCredential> getCredential(HttpRequest httpRequest);  // full implementation
    }

    //
    public class MsiCredentialProvider extends TokenCredentialProvider {
        public MsiCredentialProvider(List<HttpPipelinePolicy> policies);

        // if available return cred
        protected Mono<TokenCredential> getCredential(HttpRequest httpRequest);  // full implementation
    }    
~~~

### Client Library Implementations
~~~ java
package com.azure.keyvault


    //This exists in Secrets API, accepts AsyncServiceClientCredentials for async client, ServiceClientCredentials for sync client
     public final class SecretAsyncClientBuilder {
        private final List<HttpPipelinePolicy> policies;
        private AsyncServiceClientCredentials credentials;
        private HttpPipeline pipeline;
        private URL vaultEndpoint;
        private HttpClient httpClient;
        private HttpLogDetailLevel httpLogDetailLevel;
        private RetryPolicy retryPolicy;

        SecretAsyncClientBuilder() {
            retryPolicy = new RetryPolicy();
            httpLogDetailLevel = HttpLogDetailLevel.NONE;
            policies = new ArrayList<>();
        }
        public SecretAsyncClient build() {

            if (vaultEndpoint == null) {
                throw new IllegalStateException(KeyVaultErrorCodeStrings.getErrorString(KeyVaultErrorCodeStrings.VAULT_END_POINT_REQUIRED));
            }

            if (pipeline != null) {
                return new SecretAsyncClient(vaultEndpoint, pipeline);
            }

            if (credentials == null) {
                throw new IllegalStateException(KeyVaultErrorCodeStrings.getErrorString(KeyVaultErrorCodeStrings.CREDENTIALS_REQUIRED));
            }
            // Closest to API goes first, closest to wire goes last.
            final List<HttpPipelinePolicy> policies = new ArrayList<>();
            policies.add(new UserAgentPolicy(AzureKeyVaultConfiguration.SDK_NAME, AzureKeyVaultConfiguration.SDK_VERSION));
            policies.add(retryPolicy);
            policies.add(new AsyncCredentialsPolicy(getAsyncTokenCredentials()));
            policies.addAll(this.policies);
            policies.add(new HttpLoggingPolicy(httpLogDetailLevel));

            HttpPipeline pipeline = httpClient == null
                ? new HttpPipeline(policies)
                : new HttpPipeline(httpClient, policies);

            return new SecretAsyncClient(vaultEndpoint, pipeline);
        }
    }
~~~

### End User Expected Usage Samples

~~~ java

  //Using ClientSecretCredential
  //Use Fluent Pattern for SecretCredentials or Providers.
  SecretAsyncClient.builder()
    .vaultEndpoint("https://myvault.vault.azure.net/")
    .credentials(new ClientSecretCredential(getClientId(), getClientSecret(), getAuthority()))
    .build();

~~~
