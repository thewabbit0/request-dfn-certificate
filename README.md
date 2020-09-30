A set of scripts for requesting certificates from the German Research Network's CA (DFN PKI) for a Windows host.

## Features
- Generates a Certificate Signing Request (CSR) with the DNS names registered on the host's network connections
- Submits the CSR to the DFN PKI web service
- Optionally generates and emails a pre-filled application form PDF for signing and archiving by your organization's RA operators
- Sets up a periodical check for the CSR's approval and installs the certificate as it becomes available through the DFN PKI web servcie

## Use

`New-CertificateRequest.ps1` takes care of new CSRs. The other scripts in this directory are used by it directly or indirectly.

Parameter | Explanation
--------- | -----------
ApplicantName | Name of the person responsible for the CSR as presented to the Registration Authority (RA) before approval
ApplicantEMail | E-Mail address of the person responsible for the CSR. This is the address the signed certificate will be sent to by the DFN PKI
ApplicantOrgUnit | Organizational unit / Department of the person responsible for the CSR as presented to the RA
SubjectDnSuffix | The mandatory suffix of your Certificate Subject's DN. You will find this suffix printed on your organization's DFN PKI Server certificate application page (`pki.pca.dfn.de/dfn-ca-global-g2/cgi-bin/pub/pki?cmd=pkcs10_req;id=1;menu_item=2&RA_ID=<Your_RA_ID>`) and it will be formatted as `"O=<OrganizationName>,L=<City>,ST=<State>,C=<Country>"`
RegistrationAuthorityID | The Registration authority ID number as issued to your organization by the DFN PKI. Part of the DFN PKI web interface URL: _`https://pki.pca.dfn.de/dfn-ca-global-g2/cgi-bin/pub/pki?cmd=getStaticPage;name=index;id=1&RA_ID=`**`<Your_RA_ID>`**_
GenerateApplicationForm | Switch, generates the pre-filled DFN PKI application form for signing by the person responsible for the CSR, typically signed and archived by your organization's RA operators
SmtpServerName | Optional: name of the SMTP server to use for sending the application form PDF to -ApplicantEMail
SmtpFromEmail | Optional: E-Mail address to use as the "From:" address when sending the PDF application form to -ApplicantEMail
SmtpUseSSL | Switch, makes the SMTP connection negotiate TLS encryption
SmtpCredential | Optional credential (as returned by Powershell's `Get-Credential`) to use for authentication with -SmtpServerName
CertificateKeyLength | Length of the RSA keys in the generated Private/Public keypair for the certificate. Defaults to 2048 bits if not specified.
CertificateHashAlgorithm | Requested hash algorithm to use for the CA's signature. Defaults to SHA256 if not specified.
PublicSOAPUri | The URI of the DFN PKI SOAP service. Defaults to `"https://pki.pca.dfn.de/dfn-ca-global-g2/cgi-bin/pub/soap?wsdl=1"` if not specified.


### Example
```
New-CertificateRequest.ps1 -ApplicantName "Denis Jedig" -ApplicantEMail "denis.jedig@th-koeln.de" `
                           -ApplicantOrgUnit "Campus IT" `
                           -SubjectDnSuffix "O=Technische Hochschule Koeln,L=Koeln,ST=Nordrhein-Westfalen,C=DE" `
                           -RegistrationAuthorityID 1520 -RegisterFetchingTask -GenerateApplicationForm `
                           -SmtpServerName "smtp.intranet.fh-koeln.de" 
```

This requests a new certificate, generates an application PDF which is sent by E-Mail and registers a scheduled task
to check on the signed certificate at regular intervals. The scheduled task's trigger will expire after a month of trying.
If the certificate is signed before the task's trigger expired, the certificate will be fetched and installed and the task 
removed automatically

## Logging
The script(s) log transcripts to the .\log directory

## Links

This script uses pre-compiled libraries of two other projects:
* [The Legion of the Bouncy Castle C# API](http://www.bouncycastle.org/csharp/)  for CSR decoding
* [iTextSharp](https://github.com/itext/itextsharp) for PDF manipulation