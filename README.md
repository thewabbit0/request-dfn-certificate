Skripte zum Beantragen von Zertifikaten von der [DFN PKI](https://www.pki.dfn.de) für einen Windows-Host

## Features
- Generiert einen Certificate Signing Request (CSR) mit den DNS-Namen des Hosts (verwendet die an den aktiven Netzwerkverbindungen definierten Hostnamen)
- Übermittelt den CSR an den DFN PKI web service
- Generiert das Formular "Zertifikatantrag für ein Serverzertifikat" mit vorausgefüllten Daten und verschickt diesen per E-Mail an den Antragsteller (optional)
- Erstellt einen Scheduled Task für die regelmäßige Prüfung des Antragstatus und automatische Installation des signierten Zertifikates, sobald genehmigt

## Nutzung

`New-CertificateRequest.ps1` erstellt den Zertifikatsantrag. Die anderen Skripte in dem Verzeichnis werden von diesem Skript direkt oder indirekt genutzt.

Parameter | Explanation
--------- | -----------
ApplicantName | Name  des Antragstellers (Person, die für den CSR und anschließend auch für das Schlüsselpaar verantwortlich ist)
ApplicantEMail | E-Mail-Adresse des Antragstellers. An diese Adresse schickt das Skript das Formular für den Zertifikatsantrag und die DFN-PKI Infos zum Zertifikatsstatus
ApplicantOrgUnit | "Abteilung" des Antragstellers (darf leer bleiben)
SubjectDnSuffix | Der mandatorische Suffix für den DistinguishedName im "Subject"-Feld des Zertifikats. Der Suffix wird von der DFN-PKI für die antragstellende Organisation vorgegeben und erscheint auf der Beantragungswebseite für Serverzertifikate der DFN PKI (`pki.pca.dfn.de/dfn-ca-global-g2/cgi-bin/pub/pki?cmd=pkcs10_req;id=1;menu_item=2&RA_ID=<Your_RA_ID>`) im Format `"O=<OrganizationsName>,L=<Stadt>,ST=<Bundesland>,C=<Land>"`
RegistrationAuthorityID | Die Registration authority ID wie von der DFN PKI an die Organisation erteilt. Bestandteil der DFN PKI Web-Interface-URL: _`https://pki.pca.dfn.de/dfn-ca-global-g2/cgi-bin/pub/pki?cmd=getStaticPage;name=index;id=1&RA_ID=`**`<Your_RA_ID>`**_
GenerateApplicationForm | Switch, erstellt einen voraisgefüllten "Zertifikatantrag für ein Serverzertifikat" zur unterzeichnung durch den Antragsteller
SmtpServerName | Optional: Name des SMTP-Servers für den E-Mail-Versand des Zertifikatantrag-Formulars an -ApplicantEMail
SmtpFromEmail | Optional: E-Mail-Addresse, die als "From:"-Addresse für den E-Mail-Versand an -ApplicantEMail genutzt wird
SmtpUseSSL | Switch, TLS-Verschlüsselung für die SMTP-Verbindung verwenden
SmtpCredential | Optional: Credential für die Authentifizierung gegen -SmtpServerName (wie Powershell's `Get-Credential` zurückgeliefert)
CertificateKeyLength | Bit-Länge der RSA-Schlüssel im erstellten Private/Public-Schlüsselpaar für das Zertifikat. Standardwert: 2048
CertificateHashAlgorithm | Hash-Algotithmus für die CA-Signatur des Zertifikats. Standardwert: SHA256
PublicSOAPUri | Die URI des DFN PKI SOAP "public" Webservice. Standardwert: `"https://pki.pca.dfn.de/dfn-ca-global-g2/cgi-bin/pub/soap?wsdl=1"`


### Beispiel
```
New-CertificateRequest.ps1 -ApplicantName "Denis Jedig" -ApplicantEMail "denis.jedig@th-koeln.de" `
                           -ApplicantOrgUnit "Campus IT" `
                           -SubjectDnSuffix "O=Technische Hochschule Koeln,L=Koeln,ST=Nordrhein-Westfalen,C=DE" `
                           -RegistrationAuthorityID 1520 -RegisterFetchingTask -GenerateApplicationForm `
                           -SmtpServerName "smtp.intranet.fh-koeln.de" 
```

Obiges beantragt ein neues Zertifikat, generiert das PDF-Formular des Zertifikatsantrags, verschickt es per E-Mail und registriert
in der Windows-Aufgabenplanung einen neuen Task, um regelmäßig nachzuschauen, ob der Zertifikatsantrag geneghmigt wurde.
Der Task läuft nach einem Monat ab. Wenn der Zertifikatsantrag vor Ablauf dieser Zeit genehmigt wurde, wird das Zertifikat
heruntergeladen und installiert und der Task automatisch entfernt.

## Protokollierung
Die Skripte schreiben ihre Transcripts ind das Verzeichnis `.\log`

--------

A set of scripts for requesting certificates from the [German Research Network's CA (DFN PKI)](https://www.pki.dfn.de) for a Windows host.

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
* [The Legion of the Bouncy Castle C# API](http://www.bouncycastle.org/csharp/) for CSR decoding
* [iTextSharp](https://github.com/itext/itextsharp) for PDF manipulation

## Author
Denis Jedig

originally created for: Cologne University of Applied Sciences (TH Köln), Germany

2020-10

## Foreign licenses
### The Legion of the Bouncy Castle C# API 

Copyright (c) 2000 - 2017 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### iTextSharp

This program is free software; you can redistribute it and/or modify it under the terms of the GNU Affero General Public License version 3 as published by the Free Software Foundation with the addition of the following permission added to Section 15 as permitted in Section 7(a): FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY iText Group NV, iText Group NV DISCLAIMS THE WARRANTY OF NON INFRINGEMENT OF THIRD PARTY RIGHTS.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details. You should have received a copy of the GNU Affero General Public License along with this program; if not, see http://www.gnu.org/licenses or write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA, 02110-1301 USA, or download the license from the following URL:

http://itextpdf.com/terms-of-use/

The interactive user interfaces in modified source and object code versions of this program must display Appropriate Legal Notices, as required under Section 5 of the GNU Affero General Public License.

In accordance with Section 7(b) of the GNU Affero General Public License, a covered work must retain the producer line in every PDF that is created or manipulated using iText.

You can be released from the requirements of the license by purchasing a commercial license. Buying such a license is mandatory as soon as you develop commercial activities involving the iText software without disclosing the source code of your own applications. These activities include: offering paid services to customers as an ASP, serving PDFs on the fly in a web application, shipping iText with a closed source product.

For more information, please contact iText Software Corp. at this address: sales@itextpdf.com
