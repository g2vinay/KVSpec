
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
    
    // Rerturning certificate operation in async api is not intuitive and natural.
    public Mono<Response<CertificateOperation>> createCertificate(String name);
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
    // Q: In what scenarios is a list of byte[] passed in?
    public Mono<Response<String>> mergeCertificate(String name, List<byte[]> x509Certificates);
    public Mono<Response<Certificate>> mergeCertificate(MergeCertificateConfig mergeCertificateConfig);
    
    //----------------------------------------------------------------------------------------------------------------------

    // Certificate Policy / Properties methods

    // With Certificate Polcy part of Certificate Base, do we still need to stick with these methods names?
    public Mono<Response<CertificateBase>> getCertificatePolicy(String certificateName);
    public Mono<Response<CertificateBase>> updateCertificatePolicy(String certificateName, CertificateBase certificate);
      
    // Possibles renames to:
    public Mono<Response<CertificateBase>> getCertificateProperties(String certificateName);
    public Mono<Response<CertificateBase>> updateCertificateProperties(CertificateBase certificate);
   
    //----------------------------------------------------------------------------------------------------------------------
    

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

    public CertificateAsyncClientBuilder vaultEndpoint(String vaultEndpoint) {}
    public CertificateAsyncClientBuilder credentials(ServiceClientCredentials credentials) {}
    public CertificateAsyncClientBuilder httpLogDetailLevel(HttpLogDetailLevel logLevel) {}
    public CertificateAsyncClientBuilder addPolicy(HttpPipelinePolicy policy) {}
    public CertificateAsyncClientBuilder httpClient(HttpClient client) {}
}

~~~



## Create a test issuer issued Certificate valid for 1 year with EC Key and AutoRenewal set for 1 month before expiry using the same key.
~~~ java
// TODO: Implement and Verify the usage.
CertificateAsyncClient certificateAsyncClient = CertificateAsyncClient.builder()
                            .vaultEndpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();       

Issuer issuer = new Issuer("createCertificateJavaPkcs12Issuer01")
                        .credentials("accountId", "password")
                        .addAdmin(new Administrator("John", "doe", "john.doe@contoso.com")
                                     .phoneNumber("123324324"))
                        .addAdmin(new Administrator("Ben", "doe", "Ben.doe@contoso.com"));

Issuer createdIssuer = keyVaultClient.setCertificateIssuer(issuer).block().value();


Certificate cert4 = new Certificate("securityCert1")
                        .x509subjectName("CN=SelfSignedJavaPem2")
                        .validityInMonths(12)
                        .secretContentType(SecretContentType.MIME_PEM)
                        .issuerName(createdIssuer.name())
                        .rsaKeyConfig(new RSAKeyConfig(JsonWebKeyType.RSA_HSM)
                                          .reuseKey(true)
                                          .keySize(2048))
                        .addLifeTimeAction(new LifeTimeAction(ActionType.EMAIL_CONTACTS)
                                               .activateAtLifetimePercent(60))
                        .addLifeTimeAction(new LifeTimeAction(ActionType.AUTO_RENEW)
                                               .renewAtDaysBeforeExpiry(30));
 

CertificateOperation certOp4 = certificateAsyncClient.createCertificate(cert4).block().value();

~~~


## Import a pkcs certificate witg exportable EC key with P-384 elliptic curve.
~~~ java
// TODO: Implement and Verify the usage.
CertificateAsyncClient certificateAsyncClient = CertificateAsyncClient.builder()
                            .vaultEndpoint("https://myvault.vault.azure.net/")
                            .credentials(AzureCredential.DEFAULT)
                            .build();       


CertificateImport certImport = new CertificateImport("certImport2", certificateFilePath)
                           .secretContentType(SecretContentType.PKCS12)
                           .ecKeyConfig(new EcKeyConfig(JsonWebKeyType.EC_HSM)
                                            .keyCurve(JsonWebKeyCurve.P_384)
                                            .reuseKey(true))
                           .addLifeTimeAction(new LifeTimeAction(ActionType.AUTO_RENEW)
                                              .renewDaysBeforeExpiry(30)));
                                    
                        
Certificate importedCertificate = certificateAsyncClient.importCertificate(certImport).block().value();

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
    private String orgId;

    /**
     * Details of the organization administrator.
     */
    @JsonProperty(value = "admin_details")
    private List<AdministratorDetails> adminDetails;


    public Issuer()
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
    
    /**
     * The key id.
     */
    @JsonProperty(value = "kid", access = JsonProperty.Access.WRITE_ONLY)
    private String keyId;
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
    
    public CertificateImport(String name, String certificateFilePath){
        super.name = name;
    }
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
     *  The configuration of key backing the certificate.
     */
    private KeyConfiguration keyConfig;

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
     * The content type of the secret.
     */
    private SecretContentType secretContentType;

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
    private String secretContentType;

    /**
     * The subject name. Should be a valid X509 distinguished Name.
     */
    @JsonProperty(value = "subject")
    private String subjectName;

    /**
     * The subject alternative names.
     */
    @JsonProperty(value = "sans")
    private SubjectAlternativeNames subjectAlternativeNames;

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
    private String issuerCertificateTypeRequest;

    /**
     * Indicates if the certificates generated under this policy should be
     * published to certificate transparency logs.
     */
    @JsonProperty(value = "cert_transparency")
    private Boolean issuerCertificateTransparency;

    /**
     * Thumbprint of the certificate. Read Only
     */
    @JsonProperty(value = "x5t", access = JsonProperty.Access.WRITE_ONLY)
    private Base64Url x509Thumbprint;
}

public abstract class KeyConfiguration {

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
     * List of key usages.
     */
    @JsonProperty(value = "key_usage")
    private List<KeyUsageType> keyUsage;
    
    /**
     * The enhanced key usage.
     */
    @JsonProperty(value = "ekus")
    private List<String> enhancedKeyUsage;

}

public class RSAKeyConfiguration extends KeyConfiguration {

    public void keySize(Integer keySize);
    
    // Add setters for other variables.
}


public class ECKeyConfiguration extends KeyConfiguration {

    private ECKeyConfiguration KeyCurve(JsonWebKeyCurve keyCurve);
    
    // Add setters for other variables.

}


}


public class CertificateOperation {
    /**
     * The certificate id.
     */
    @JsonProperty(value = "id", access = JsonProperty.Access.WRITE_ONLY)
    private String id;

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

public MergeCertificateConfig {

  private String certificateName;
  private List<Byte[]> x509Certs;
  
  // Add Flattened out attributes here (notBefore, expires etc. )
  
  public MergeCertificateConfig(String certificateName, List<Byte[]> x509Certs);

}

~~~
