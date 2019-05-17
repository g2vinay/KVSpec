
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

    // Talk to Scott about service side logic of just passing the certificate name, does it even work?
    public Mono<Response<CertificateOperation>> createCertificate(String name);
    public Mono<Response<CertificateOperation>> createCertificate(Certificate certificate);
    
    Proposition- 
    public Mono<Response<Certificate>> createCertificate(Certificate certificate);
    public Mono<Response<CertificateOperation>> createCertificate(String name);


    public Mono<Response<Certificate>> importCertificate( String certificateName, String certificateFilePath);
    public Mono<Response<Certificate>> importCertificate(CertificateImport certificateImport);

    public Flux<CertificateBase> listCertificateVersions(String name);
    public Flux<CertificateBase> listCertificates();
    public Flux<DeletedCertificate> listDeletedCertificates();
    
    public Mono<Response<Certificate>> updateCertificate(CerticiateBase certificate);


    public Mono<Response<DeletedCertificate>> deleteCertificate(String name);
    public Mono<Response<DeletedCertificate>> getDeletedCertificate(String name);
    public Mono<Response<Certificate>> recoverDeletedCertificate(String name);
    public Mono<VoidResponse> purgeDeletedCertificate(String name);

    public Mono<Response<byte[]>> backupCertificate(String name);
    public Mono<Response<Certificate>> restoreCertificte(byte[] backup);

    public Mono<Response<String>> getPendingCertificateSigningRequest(String certificateName);


    public Mono<Response<String>> mergeCertificate(String name, List<byte[]> x509Certificates);

    public Mono<Response<Certificate>> mergeCertificate(MergeCertificateConfig mergeCertificateConfig);




    // Certificate Issuer methods

    public Mono<Response<Issuer>> createIssuer(String name, String provider);
    public Mono<Response<Issuer>> createIssuer(Issuer issuer);

    public Mono<Response<Issuer>> getCertificateIssuer(String name);

    public Mono<Response<Issuer>> deleteCertificateIssuer(String name);

    public Flux<IssuerBase> listCertificateIssuers();

    public Mono<Response<Issuer>> updateIssuer(Issuer issuer);



    // Certificate Contacts methods
    public Flux<Contact> setCertificateContacts(List<Contact>);
    public Flux<Contact> listCertificateContacts();
    public Flux<Contact> deleteCertificateContacts();


    // Certificate Policy methods
    public Mono<Response<CertificatePolicy>> getCertificatePolicy(String certificateName);
    public Mono<Response<CertificatePolicy>> updateCertificatePolicy(String certificateName, CertificatePolicy policy);


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

    public CertificateAsyncClientBuilder vaultEndpoint(String vaultEndpoint) {}
    public CertificateAsyncClientBuilder credentials(ServiceClientCredentials credentials) {}
    public CertificateAsyncClientBuilder httpLogDetailLevel(HttpLogDetailLevel logLevel) {}
    public CertificateAsyncClientBuilder addPolicy(HttpPipelinePolicy policy) {}
    public CertificateAsyncClientBuilder httpClient(HttpClient client) {}
}

~~~
## Create a SelfSigned Pkcs12 Certificate valid for 1 year.
~~~ java
// TODO: Implement and Verify the usage.
CertificateAsyncClient certificateAsyncClient = CertificateAsyncClient.builder()
                            .vaultEndpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();       



Certificate cert2 = Certificate.builder("securityCert1")
                        .subjectName(""CN=SelfSignedJavaPkcs12")
                        .validityInMonths(12)
                        .issuerName("Self")
                        .secretContentType(SecretContentType.MIME_PKCS12)
                        .build();



CertificateOperation certOp2 = certificateAsyncClient.createCertificate(cert2).block().value();

~~~


## Create a SelfSigned Pem Certificate valid for 1 year.
~~~ java
// TODO: Implement and Verify the usage.
CertificateAsyncClient certificateAsyncClient = CertificateAsyncClient.builder()
                            .vaultEndpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();       



Certificate cert2 = Certificate.builder("securityCert1")
                        .x509SubjectName("CN=SelfSignedJavaPem")
                        .validityInMonths(12)
                        .issuerName("Self")
                        .secretContentType(SecretContentType.MIME_PEM)
                        .build();


CertificateOperation certOp2 = certificateAsyncClient.createCertificate(cert2).block().value();

~~~


## Create a test-issuer issued certificate in PKCS12 format
~~~ java
// TODO: Implement and Verify the usage.

Issuer issuer = new Issuer("createCertificateJavaPkcs12Issuer01")
                        .credentials("accountId", "password")
                        .addAdmin("John", "doe", "john.doe@contoso.com")
                            .phoneNumber("123324324")
                        .addAdmin("Ben", "doe", "Ben.doe@contoso.com");

Issuer createdIssuer = keyVaultClient.setCertificateIssuer(issuer).block().value();


Certificate cert3 = Certificate.builder("createTestJavaPkcs12")
                    .x509SubjectName("CN=TestJavaPkcs12")
                    .validityInMonths(12)
                    .secretContentType(SecretContentType.MIME_PKCS12)
                    .issuerName(createdIssuer.name())


certificateAsyncClient.createCertificate(cert3).block().value();
   
~~~



## Create a SelfSigned Pem Certificate valid for 1 year with RSA Key of size 4076.
~~~ java
// TODO: Implement and Verify the usage.
CertificateAsyncClient certificateAsyncClient = CertificateAsyncClient.builder()
                            .vaultEndpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();       



Certificate cert2 = Certificate.builder("securityCert1")
                        .x509subjectName("CN=SelfSignedJavaPem2")
                        .validityInMonths(12)
                        .issuerName("Self")
                        .secretContentType(SecretContentType.MIME_PEM)
                        .keyType(JsonWebKeyType.RSA)
                        .keySize(4076)
                        .build();


CertificateOperation certOp2 = certificateAsyncClient.createCertificate(cert2).block().value();

~~~


## Create a SelfSigned Pem Certificate valid for 1 year with EC Key and AutoRenewal set for 1 month before expiry using the same key.
~~~ java
// TODO: Implement and Verify the usage.
CertificateAsyncClient certificateAsyncClient = CertificateAsyncClient.builder()
                            .vaultEndpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();       



Certificate cert2 = Certificate.builder("securityCert1")
                        .x509subjectName("CN=SelfSignedJavaPem2")
                        .validityInMonths(12)
                        .issuerName("Self")
                        .secretContentType(SecretContentType.MIME_PEM)
                        .keyType(JsonWebKeyType.EC)
                        .reuseKey(true)
                        .addLifeTimeAction(ActionType.AUTO_RENEW)
                            .activatingLifetimeStage(50)
                            .renewDaysBeforeExpiry(30)
                        .build();


CertificateOperation certOp2 = certificateAsyncClient.createCertificate(cert2).block().value();

~~~




## DataStructures:
~~~ java

/**
 * The contact information for the vault certificates.
 */
public class Contact {
    /**
     * Email addresss.
     */
    @JsonProperty(value = "email")
    private String emailAddress;

    /**
     * Name.
     */
    @JsonProperty(value = "name")
    private String name;

    /**
     * Phone number.
     */
    @JsonProperty(value = "phone")
    private String phone;
}


public class IssuerBase {
    
    /**
     * Identifier for the issuer object.
     */
    @JsonProperty(value = "id", access = JsonProperty.Access.WRITE_ONLY)
    private String id;

    /**
     * The issuer provider.
     */
    @JsonProperty(value = "provider")
    private String provider;

    /**
     * Determines whether the issuer is enabled.
     */
    @JsonProperty(value = "enabled")
    private Boolean enabled;

    /**
     * Creation time in UTC.
     */
    @JsonProperty(value = "created", access = JsonProperty.Access.WRITE_ONLY)
    private Long created;

    /**
     * Last updated time in UTC.
     */
    @JsonProperty(value = "updated", access = JsonProperty.Access.WRITE_ONLY)
    private Long updated;

    String name;

}


public class Issuer extends IssuerBase {

    /**
     * The user name/account name/account id.
     */
    @JsonProperty(value = "account_id")
    private String accountId;

    /**
     * The password/secret/account key.
     */
    @JsonProperty(value = "pwd")
    private String password;


    /**
     * Id of the organization.
     */
    @JsonProperty(value = "id")
    private String id;

    /**
     * Details of the organization administrator.
     */
    @JsonProperty(value = "admin_details")
    private List<AdministratorDetails> adminDetails;


    public Issuer()
}


public class CertificateBase {
    
    /**
     * Determines whether the object is enabled.
     */
    private Boolean enabled;

    /**
     * Not before date in UTC.
     */
    private OffsetDateTime notBefore;

    /**
     * The secret version.
     */
    String version;

    /**
     * Expiry date in UTC.
     */
    private OffsetDateTime expires;

    /**
     * Creation time in UTC.
     */
    private OffsetDateTime created;

    /**
     * Last updated time in UTC.
     */
    private OffsetDateTime updated;

    /**
     * Reflects the deletion recovery level currently in effect for certificates in
     * the current vault. If it contains 'Purgeable', the certificate can be
     * permanently deleted by a privileged user; otherwise, only the system can
     * purge the certificate, at the end of the retention interval. Possible values
     * include: 'Purgeable', 'Recoverable+Purgeable', 'Recoverable',
     * 'Recoverable+ProtectedSubscription'.
     */
    private String recoveryLevel;

    /**
     * The Certificate name.
     */
    String name;

    /**
     * The certificate id.
     */
    @JsonProperty(value = "id", access = JsonProperty.Access.WRITE_ONLY)
    private String id;

    /**
     * The key id.
     */
    @JsonProperty(value = "kid", access = JsonProperty.Access.WRITE_ONLY)
    private String keyId;


    /**
     * Thumbprint of the certificate.
     */
    @JsonProperty(value = "x5t", access = JsonProperty.Access.WRITE_ONLY)
    private Base64Url x509Thumbprint;

    /**
     * Type of the certificate.
     */
    @JsonProperty(value = "contentType")
    private String contentType;

    /**
     * Application specific metadata in the form of key-value pairs.
     */
    @JsonProperty(value = "tags")
    private Map<String, String> tags;

    /**
     * True if the certificate's lifetime is managed by key vault. If this is a key
     * backing a certificate, then managed will be true.
     */
    @JsonProperty(value = "managed", access = JsonProperty.Access.WRITE_ONLY)
    private Boolean managed;

    /**
     * Properties of the secret backing a certificate.
     */
    @JsonProperty(value = "secret_props")
    private String secretContentType;


    /**
     * The subject name. Should be a valid X509 distinguished Name.
     */
    @JsonProperty(value = "subject")
    private String certificateSubjectName;

    /**
     * The enhanced key usage.
     */
    @JsonProperty(value = "ekus")
    private List<String> enhancedKeyUsage;

    /**
     * The subject alternative names.
     */
    @JsonProperty(value = "sans")
    private SubjectAlternativeNames subjectAlternativeNames;

    /**
     * List of key usages.
     */
    @JsonProperty(value = "key_usage")
    private List<KeyUsageType> keyUsage;

    /**
     * The duration that the ceritifcate is valid in months.
     */
    @JsonProperty(value = "validity_months")
    private Integer validityInMonths;

    /**
     * Indicates if the private key can be exported.
     */
    @JsonProperty(value = "exportable")
    private Boolean exportable;

    /**
     * The type of key pair to be used for the certificate. Possible values
     * include: 'EC', 'EC-HSM', 'RSA', 'RSA-HSM', 'oct'.
     */
    @JsonProperty(value = "kty")
    private JsonWebKeyType keyType;

    /**
     * The key size in bits. For example: 2048, 3072, or 4096 for RSA.
     */
    @JsonProperty(value = "key_size")
    private Integer keySize;

    /**
     * Indicates if the same key pair will be used on certificate renewal.
     */
    @JsonProperty(value = "reuse_key")
    private Boolean reuseKey;

    /**
     * Elliptic curve name. For valid values, see JsonWebKeyCurveName. Possible
     * values include: 'P-256', 'P-384', 'P-521', 'P-256K'.
     */
    @JsonProperty(value = "crv")
    private JsonWebKeyCurveName keyCurve;


    /**
     * Actions that will be performed by Key Vault over the lifetime of a
     * certificate.
     */
    @JsonProperty(value = "lifetime_actions")
    private List<LifetimeAction> lifetimeActions;


    /**
     * Name of the referenced issuer object or reserved names; for example,
     * 'Self' or 'Unknown'.
     */
    @JsonProperty(value = "name")
    private String issuerName;

    /**
     * Type of certificate to be requested from the issuer provider.
     */
    @JsonProperty(value = "cty")
    private String issuerCertificateType;

    /**
     * Indicates if the certificates generated under this policy should be
     * published to certificate transparency logs.
     */
    @JsonProperty(value = "cert_transparency")
    private Boolean issuerCertificateTransparency;

}

public class Certificate extends CertificateBase {
    

    /**
     * CER contents of x509 certificate.
     */
    @JsonProperty(value = "cer")
    private byte[] cer;

    /**
     * The secret id.
     */
    @JsonProperty(value = "sid", access = JsonProperty.Access.WRITE_ONLY)
    private String sid;


    public Certificate(String name){
        super.name = name;
    }


}


public class CertificateImport extends CertificateBase {
    
    /**
     * Base64 encoded representation of the certificate object to import. This
     * certificate needs to contain the private key.
     */
    @JsonProperty(value = "value", required = true)
    private String base64EncodedCertificate;

    /**
     * If the private key in base64EncodedCertificate is encrypted, the
     * password used for encryption.
     */
    @JsonProperty(value = "pwd")
    private String password;


    public CertificateImport(String name){
        super.name = name;
    }


}


/**
 * Management policy for a certificate.
 */
public class CertificatePolicy {
    /**
     * The certificate id.
     */
    @JsonProperty(value = "id", access = JsonProperty.Access.WRITE_ONLY)
    private String id;

    /**
     * The type of key pair to be used for the certificate. Possible values
     * include: 'EC', 'EC-HSM', 'RSA', 'RSA-HSM', 'oct'.
     */
    @JsonProperty(value = "kty")
    private JsonWebKeyType keyType;

    /**
     * The key size in bits. For example: 2048, 3072, or 4096 for RSA.
     */
    @JsonProperty(value = "key_size")
    private Integer keySize;

    /**
     * Indicates if the same key pair will be used on certificate renewal.
     */
    @JsonProperty(value = "reuse_key")
    private Boolean reuseKey;

    /**
     * Elliptic curve name. For valid values, see JsonWebKeyCurveName. Possible
     * values include: 'P-256', 'P-384', 'P-521', 'P-256K'.
     */
    @JsonProperty(value = "crv")
    private JsonWebKeyCurveName keyCurve;

    /**
     * Properties of the secret backing a certificate.
     */
    @JsonProperty(value = "secret_props")
    private String secretContentType;

    /**
     * The subject name. Should be a valid X509 distinguished Name.
     */
    @JsonProperty(value = "subject")
    private String subject;

    /**
     * The enhanced key usage.
     */
    @JsonProperty(value = "ekus")
    private List<String> ekus;

    /**
     * The subject alternative names.
     */
    @JsonProperty(value = "sans")
    private SubjectAlternativeNames subjectAlternativeNames;

    /**
     * List of key usages.
     */
    @JsonProperty(value = "key_usage")
    private List<KeyUsageType> keyUsage;

    /**
     * The duration that the ceritifcate is valid in months.
     */
    @JsonProperty(value = "validity_months")
    private Integer validityInMonths;

    /**
     * Actions that will be performed by Key Vault over the lifetime of a
     * certificate.
     */
    @JsonProperty(value = "lifetime_actions")
    private List<LifetimeAction> lifetimeActions;

    /**
     * Name of the referenced issuer object or reserved names; for example,
     * 'Self' or 'Unknown'.
     */
    @JsonProperty(value = "name")
    private String issuerName;

    /**
     * Type of certificate to be requested from the issuer provider.
     */
    @JsonProperty(value = "cty")
    private String certificateType;

    /**
     * Indicates if the certificates generated under this policy should be
     * published to certificate transparency logs.
     */
    @JsonProperty(value = "cert_transparency")
    private Boolean certificateTransparency;


    /**
     * Get the id value.
     *
     * @return the id value
     */
    public String id() {
        return this.id;
    }
}


public class CertificateOperation {
    /**
     * The certificate id.
     */
    @JsonProperty(value = "id", access = JsonProperty.Access.WRITE_ONLY)
    private String id;

    /**
     * Parameters for the issuer of the X509 component of a certificate.
     */
    @JsonProperty(value = "issuer")
    private IssuerParameters issuerParameters;

    /**
     * The certificate signing request (CSR) that is being used in the
     * certificate operation.
     */
    @JsonProperty(value = "csr")
    private byte[] csr;

    /**
     * Indicates if cancellation was requested on the certificate operation.
     */
    @JsonProperty(value = "cancellation_requested")
    private Boolean cancellationRequested;

    /**
     * Status of the certificate operation.
     */
    @JsonProperty(value = "status")
    private String status;

    /**
     * The status details of the certificate operation.
     */
    @JsonProperty(value = "status_details")
    private String statusDetails;

    /**
     * Error encountered, if any, during the certificate operation.
     */
    @JsonProperty(value = "error")
    private Error error;

    /**
     * Location which contains the result of the certificate operation.
     */
    @JsonProperty(value = "target")
    private String target;

    /**
     * Identifier for the certificate operation.
     */
    @JsonProperty(value = "request_id")
    private String requestId;

}


~~~


