
## Certifciates Datastructures Design

![](https://github.com/g2vinay/KVSpec/blob/master/certsDesign1.png)

![](https://github.com/g2vinay/KVSpec/blob/master/certsDesign2.png)

![](https://github.com/g2vinay/KVSpec/blob/master/certsDesign3.png)


## Points of Discussion

1. Certificate and Certificate Import have the policy in common (do we move it down to a parent class which extends from CertificateBase?)
2. Is it fine to keep ekus and keyUsage properties in KeyOptions class?
3. CertName, issuerName and (subjectName or sans) is required. Besides certName do we keep issuerName and (subjectName or sans) in certifciate constructors?


## __CertificateAsyncClient__
~~~ java
public class CertificateAsyncClient extends ServiceClient
{
    // constructors
    private CertificateAsyncClient(String vaultUrl, HttpPipeline pipeline);
    public static CertificateAsyncClientBuilder builder() {
        return new CertificateAsyncClientBuilder();
    }

    // methods
    // The Get Certificate method , the REST API returns Certificate operation for Get Certificate - check with Scott.
    public Mono<Response<Certificate>> getCertificate(String name);
    public Mono<Response<Certificate>> getCertificate(String name, String version);
    
    // Uses the default policy.
    public Mono<Response<CertificateOperation>> createCertificate(String name);
    // Validates the required certificate configuration parameters are set and then invokes rest api call.
    public Mono<Response<CertificateOperation>> createCertificate(Certificate certificate);

    public Mono<Response<Certificate>> importCertificate( String certificateName, String certificateFilePath);
    public Mono<Response<Certificate>> importCertificate(CertificateImport certificateImport);

    public Flux<CertificateBase> listCertificateVersions(String name);
    public Flux<CertificateBase> listCertificates();
    public Flux<DeletedCertificate> listDeletedCertificates();
    
    //Update works to only update tags and enabled attrbiutes.    
    public Mono<Response<Certificate>> updateCertificateTags(String certificateName, Map<String, String> tags);
    public Mono<Response<Certificate>> updateCertificateEnabled(String certificateName, boolean enabled);

    public Mono<Response<DeletedCertificate>> deleteCertificate(String name);
    public Mono<Response<DeletedCertificate>> getDeletedCertificate(String name);
    public Mono<Response<Certificate>> recoverDeletedCertificate(String name);
    public Mono<VoidResponse> purgeDeletedCertificate(String name);

    public Mono<Response<byte[]>> backupCertificate(String name);
    public Mono<Response<Certificate>> restoreCertificte(byte[] backup);
    
    public Mono<Response<byte[]>> getPendingCertificateSigningRequest(String certificateName);
    public Mono<Response<String>> mergeCertificate(String name, List<byte[]> x509Certificates);
    public Mono<Response<Certificate>> mergeCertificate(MergeCertificateConfig mergeCertificateConfig);
    
    // Certificate Policy
    public Mono<Response<CertificateBase>> getCertificatePolicy(String certificateName);
    public Mono<Response<CertificateBase>> updateCertificatePolicy(String certificateName, CertificateBase certificate);
   
    

    // Certificate Issuer methods
    public Mono<Response<Issuer>> createCertificateIssuer(String name, String provider);
    public Mono<Response<Issuer>> createCertificateIssuer(Issuer issuer);
    public Mono<Response<Issuer>> getCertificateIssuer(String name);
    public Mono<Response<Issuer>> deleteCertificateIssuer(String name);
    public Flux<IssuerBase> listCertificateIssuers();
    public Mono<Response<Issuer>> updateIssuer(Issuer issuer);



    // Certificate Contacts methods
    public Flux<Contact> setCertificateContacts(List<Contact>);
    public Flux<Contact> listCertificateContacts();
    public Flux<Contact> deleteCertificateContacts();



    // Certificate Operation methods
     public Mono<Response<CertificateOperation>> getCertificateOperation(String certificateName);
     public Mono<Response<CertificateOperation>> deleteCertificateOperation(String certificateName);
     public Mono<Response<CertificateOperation>> updateCertificateOperation(String certificateName, boolean cancellationRequested);
       
}

public final class CertificateAsyncClientBuilder {

    private CertificateAsyncClientBuilder() {
    }

    public CertificateAsyncClient build() {
       //Validate and Build the Client
    }

    public CertificateAsyncClientBuilder endpoint(String vaultEndpoint) {}
    public CertificateAsyncClientBuilder credentials(ServiceClientCredentials credentials) {}
    public CertificateAsyncClientBuilder httpLogDetailLevel(HttpLogDetailLevel logLevel) {}
    public CertificateAsyncClientBuilder addPolicy(HttpPipelinePolicy policy) {}
    public CertificateAsyncClientBuilder httpClient(HttpClient client) {}
}

~~~

