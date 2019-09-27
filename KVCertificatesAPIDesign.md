# Azure KeyVault Certificates API Design

## Scenario - Create Certificate

### Java
```java
Poller<CertificateOperation> createCertificate(String name, CertificatePolicy policy, Map<String, String> tags);
Poller<CertificateOperation> createCertificate(String name, CertificatePolicy policy);

CertificatePolicy policy = new CertificatePolicy("Self", "CN=SelfSignedJavaPkcs12");
Map<String, String> tags = new HashMap<>();
tags.put("foo", "bar");
//Creates a certificate and polls on its progress.
certificateAsyncClient.createCertificate("certificateName", policy, tags)
    .getObserver()
    .subscribe(pollResponse -> {
        System.out.println("---------------------------------------------------------------------------------");
        System.out.println(pollResponse.getStatus());
        System.out.println(pollResponse.getValue().status());
        System.out.println(pollResponse.getValue().statusDetails());
    });

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Get Certificate

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Get Certificate Policy

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Update Certificate

### Java
```java


```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Update Certificate Policy

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```


## Scenario - Delete Certificate

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Get Deleted Certificate

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Purge Delete Certificate

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Backup Certificate

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Restore Certificate

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - List Ceriticates

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - List Ceriticate Versions

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - List Deleted Certificates

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - List Deleted Certificates

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Create Certificate Issuer

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Create Certificate Issuer

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Get Certificate Issuer

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Delete Certificate Issuer

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - List Certificate Issuers

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```


## Scenario - List Certificate Issuers

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Update Certificate Issuer

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Set Certificate Contacts

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - List Certificate Contacts

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Delete Certificate Contacts

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Get Certificate Signing Request

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```


## Scenario - Merge Certificate

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```

## Scenario - Import Certificate

### Java
```java

```

### .NET
```net

```
### Python
```python

```
### JS/TS
```javascript

```


