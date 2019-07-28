## Questions
When will we not have a local key? Because we can always get the key from Service side and convert to local it seems like?
What is the default algorithm for RSA and Ec Key? how do we pick that? Is is something which is industry standard?
What is the scope of Local Crypto over Service side one? When will we have to rely on Service side crypto? Why can't we just have a 
fully functional local crypto?

What is the scope of symmetrics keys? Local crypto needs to support it regardless if REST API supports it or not currently?



### Design ones
Considering overloads without iv and authenticationTag.
iv is required for some algorithms, for instance AESCBC, I don't see this specified in KeyEncryptionAlgorithm enum?
What are your design thoughts for converting key from local to JSONWebKey and back? 

What is the Key - JsonWebKey? 
WHere is IKey? Is it equivalent to Cryptography client in your design? 
if so, we need to define these guys in the Crypto Client ? :  getDefaultEncryptionAlgorithm(); getDefaultKeyWrapAlgorithm(); getDefaultSignatureAlgorithm();

How do we encrypt the Stream of plain text in blocks? WHat is the size of one block we can encrypt in one op?  on service side too?


## Crypto Keys

### RSA Key

### Service Side Encrypt

{
  "alg": "RSA1_5",
  "value": "5ka5IVsnGrzufA"
}

{
  "kid": "https://karlaugsoftdeletesdk.vault-int.azure-int.net/keys/sdktestkey/f6bc1f3d37c14b2bb1a2ebb4b24e9535",
  "value": "CR0Hk0z72oOit5TxObqRpo-WFGZkb5BeN1C0xJFKHxzdDCESYPCNB-OkiWVAnMcSyu6g2aC8riVRRxY5MC2CWKj-CJ_SMke5X2kTi5yi4hJ5vuOLzmg_M6Bmqib7LsI-TeJHr9rs3-tZaSCdZ2zICeFWYduWV5rPjTnAD98epTorT8AA1zMaYHMIhKpmttcj18-dHr0E0T55dgRtsjK04uC3FlRd3odl4RhO1UHAmYpDd5FUqN-20R0dK0Zk8F8sOtThLhEmuLvqPHOCUBiGUhHA4nRDq1La4SUbThu2KMQJL6BbxxEymuliaYcNNtW7MxgVOf6V3mFxVNRY622i9g"
}

### Local Crypto Encrypt
Key Size? How do we calculate it?
Do we need to provide local EcKey and RsaKey Classes to instantiate and have them get converted to Json Web key.


