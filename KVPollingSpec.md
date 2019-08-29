
# KV Polling API 

## Points of Discussion

1. Is Poller API an add-on or should it be the new default API to create certificates?
2. Sync side API, is it enough to allow timeout and just block ? At time out the operation will not be cancelled, will continue to run on server side. Let user cancel it if they want to ?


## __CertificateAsyncClient__
~~~ java
public class CertificateAsyncClient extends ServiceClient
{
    public Poller<CertificateOperation> createCertificate(String name);
    // Validates the required certificate configuration parameters are set and then invokes rest api call.
    public Poller<CertificateOperation> createCertificate(Certificate certificate);
    
    public Mono<Response<CertificateOperation>> cancelCertificateOperation(String certificateName);
    public Mono<Response<CertificateOperation>> deleteCertificateOperation(String certificateName);
    
    //This can potentially be removed
    public Mono<Response<CertificateOperation>> getCertificateOperation(String certificateName);
}
~~~

## __CertificateClient__
~~~ java
public class CertificateClient extends ServiceClient
{
    public PollResponse<CertificateOperation> createCertificate(String name);
    public PollResponse<CertificateOperation> createCertificate(String name, Duration timeout);
    
    public PollResponse<CertificateOperation> createCertificate(Certificate certificate);
    public PollResponse<CertificateOperation> createCertificate(Certificate certificate, Duration timeout);
    
    public Response<CertificateOperation> cancelCertificateOperation(String certificateName);
    public Response<CertificateOperation> deleteCertificateOperation(String certificateName);
    
    // This can potentially be removed.
    public Response<CertificateOperation> getCertificateOperation(String certificateName); 
}
~~~


## Samples

### Create Certificate Asynchronously
~~~ java
    Certificate cert = new Certificate("userCert4")
        .certificatePolicy(new CertificatePolicy()
        .issuerName("Self")
        .subjectName("CN=SelfSignedJavaPkcs12"));

    KVPoller<CertificateOperation> certOp = client.createCertificate(cert);

    certOp.getObserver().subscribe(pollResponse -> {
        System.out.println(pollResponse.getStatus());
        System.out.println(pollResponse.getValue().status());
        System.out.println(pollResponse.getValue().statusDetails());
    });
~~~
