<#
.SYNOPSIS
Generates a new certificate signing request for the current computer using the template INF file
and sends the request for signing to the DFN PKI.
A PDF which needs signing and processing by the RA officers is being written to the 
$RequestStatusDirectory.

Take care to protect access to $RequestStatusDirectory as it will contain the request password 
which can be used to revoke the certificate.
#>
Param(
    # Name of the contact for the certificate application
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicantName,
    # email address of the contact for the certificate application
    [Parameter(Mandatory)]
    [ValidatePattern('^.+@([^.]+\.)+[^.]+$')]
    [string]$ApplicantEMail,
    # Name of the organizational unit of the applicant
    [Parameter(Mandatory)]
    [string]$ApplicantOrgUnit,
    # Distinguished Name string to use for constructing the certificate "Subject". Needs to match
    # the requirement of the DFN PKI RA, e.g. "O=Technische Hochschule Koeln,L=Koeln,ST=Nordrhein-Westfalen,C=DE"
    [Parameter(Mandatory)]
    [ValidatePattern('^O=[^,]+,L=[^,]+,ST=[^,]+,C=[^,]+$')]
    [string]$SubjectDnSuffix,
    # Length of the RSA keys in the generated private/public keypair
    [int]$CertificateKeyLength = 2048,
    # Hash algorithm to use in the request
    [string]$CertificateHashAlgorithm = "SHA256",
    # Registration Authority ID for the DFN PKI.
    # as of 2020, TH Köln has been assigned the RA ID 1520
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [int]$RegistrationAuthorityID,
    # URL for the DFN PKI "public" SOAP service
    [string]$PublicSOAPUri = "https://pki.pca.dfn.de/dfn-ca-global-g2/cgi-bin/pub/soap?wsdl=1",
    # Directory to place the request status information in
    [string]$RequestStatusDirectory = "$PSScriptRoot\PendingRequests",
    # Whether to generate a printable PDF application form for in-person signing along with the request
    [switch]$GenerateApplicationForm,
    # Name of the SMTP server to use for mailing the generated application form to $ApplicantEMail
    [string]$SmtpServerName,
    # Optional: email address to use as "from" for the mailing of the application form.
    # defaults to csr@$ComputerPrimaryFQDN
    [string]$SmtpFromEmail,
    # Optional: use TLS encryption for the SMTP connection?
    [switch]$SmtpUseSSL,
    # Optional: credential to use when sending the mail
    [PSCredential]$SmtpCredential,
    # Whether to register the scheduled task to try fetching the certificate corresponding to our CSR 
    # on a regular basis
    [switch]$RegisterFetchingTask
)

Function Register-FetchingTask {
<#
.SYNOPSIS
Registers a scheduled task to try fetching the signed certificate corresponding to our CSR
#>
    Param (
        [string]$TaskTemplateFile = "$PSScriptRoot\Templates\FetchCertificateScheduledTaskTemplate.xml",
        # Name of the task to create
        [string]$TaskName,
        # Name of the request file to use for fetching
        [string]$RequestFile,
        # The date for the request to time out (i.e. to consider the request unsuccessful)
        [datetime]$ValidTo = (Get-Date).AddMonths(1)
    )

    # The XML task format expects a date with seconds-precision - cut off everything after that
    # for the "XMLValidTo" and "XMLValidFrom" variables
    $XMLValidTo = $ValidTo.ToString("o") -replace "\..+"
    $XMLValidFrom = (Get-Date).AddHours(1).ToString("o") -replace "\..+"
    # Expand the strings in $TaskTemplateFile with our local variables and parse the result as XML
    $TaskDefinition = $ExecutionContext.InvokeCommand.ExpandString((Get-Content -Path $TaskTemplateFile -Raw))
    Register-ScheduledTask -Xml $TaskDefinition -TaskName $TaskName -Force

}

Function New-CSR {
<#
.SYNOPSIS
Creates a certificate signing request off the specified template file using the given parameters
#>

    Param (
        # "subject" line of the certificate (distinguished name)
        [Parameter(Mandatory)]
        [string]$CertSubject,
        # Array with "subject alternative name" entries, should include the CN of the subject
        [Parameter(Mandatory)]
        [string[]]$CertSANs,
        # File name of the INF request template for use with certreq.exe
        [string]$RequestTemplateFile = "$PSScriptRoot\Templates\CertificateRequestTemplate.inf",
        # Lenth of the generated RSA keys
        [Parameter(Mandatory)]
        [int]$CertKeylength,
        # hash algorithm to use for signing
        [Parameter(Mandatory)]
        [string]$CertHashAlgorithm 
    )

    $SANString = $CertSANs -join '&'
    # Read the template and expand its variables
    $CSRinf = $ExecutionContext.InvokeCommand.ExpandString((Get-Content -Path $RequestTemplateFile -Raw))

    # Temporary INF file to use for CSR creation
    $SubjectCommonName = $CertSubject -replace "^CN=", "" -replace ",.+", ""
    $Timestamp = (Get-Date -Format o) -replace "\..+" -replace ":"
    $CSRinfFileName = "$env:TEMP\$SubjectCommonName-request-$Timestamp.inf"
    # Temporary CSR result file
    $ResultCSRFile = "$env:TEMP\$SubjectCommonName-request-$Timestamp.csr"

    # Create a CSR file using certreq.exe and read the contents
    $CSRinf | Out-File -FilePath $CSRinfFileName -Force

    # Generate the request using certreq.exe 
    $CertReqResult = certreq.exe -new -q $CSRinfFileName $ResultCSRFile
    If($LASTEXITCODE -ne 0) {
        Throw "CSR generation using options in '$CSRinfFileName' failed: $CertReqResult"
    }

    # Return the INF contents as the function's result
    $ReturnResult = [PSObject]@{ INF = $CSRinf
                                 PEM = (Get-Content -Path $ResultCSRFile -Raw) }
    $ReturnResult

    # Remove the temporary CSR inf file
    Try {
        Remove-Item -Path $CSRinfFileName -Force
    } Catch {
        Write-Warning "Could not remove temporary inf file $($CSRinfFileName): $_"
    }

    # Remove the temporary CSR file
    Try {
        Remove-Item -Path $ResultCSRFile -Force
    } Catch {
        Write-Warning "Could not remove temporary CSR file $($ResultCSRFile): $_"
    }


}

$ErrorActionPreference = "Stop"
$VerboseActionPreference = "Continue"

If(-not $psISE) {
    $ScriptName = $PSCommandPath -replace "^.+\\"
    Start-Transcript -Path "$PSScriptRoot\logs\$ScriptName.transcript" -Force
}

# Only allow to run elevated
if (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Throw "Administrator privileges are required to request a new machine certificate."
}

Write-Verbose "Fetching system info for own host names from WMI..."
# Get name and DNS suffix data from WMI
$WMIComputerSystem = Get-WmiObject -Class Win32_ComputerSystem
$WMINetworkAdapterConfiguration = gwmi -Query "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = 'TRUE'"

$ComputerFQDNs = [System.Collections.ArrayList]::new()
$WMINetworkAdapterConfiguration | ForEach-Object {
    $_.DNSDomainSuffixSearchOrder | ForEach-Object {
        $ComputerFQDNs.Add("$($WMIComputerSystem.DNSHostName).$_") | Out-Null
    }
}

$ComputerPrimaryFQDN = $ComputerFQDNs | Select-Object -First 1
$ComputerFQDNs = [array]$ComputerFQDNs | Select-Object -Unique
[string[]]$CertificateSANs = $ComputerFQDNs | ForEach-Object { "DNS=$_" }
$Timestamp = (Get-Date -Format o) -replace "\..+" -replace ":"

If(-not $SmtpFromEmail) {
    $SmtpFromEmail = "csr@$ComputerPrimaryFQDN"
}


Write-Verbose "Generating a new Certificate Signing Request for 'CN=$ComputerPrimaryFQDN,$SubjectDnSuffix'"
$CSR = New-CSR -CertSubject "CN=$ComputerPrimaryFQDN,$SubjectDnSuffix" `
               -CertSANs $CertificateSANs `
               -CertKeylength $CertificateKeyLength `
               -CertHashAlgorithm $CertificateHashAlgorithm `


Write-Verbose "Connecting to DFN PKI public web service at '$PublicSOAPUri'..."
# Allow the use of TLS 1.2 for the SOAP connection
[System.Net.ServicePointManager]::SecurityProtocol = "Tls11,Tls12"
$CA = New-WebServiceProxy -Uri $PublicSOAPUri

# Generate a password and calculate its SHA-1 hash value
$PwLength = 15 ## characters
$PwNonAlphaChars = 2
$Password = [System.Web.Security.Membership]::GeneratePassword($Pwlength, $PwnonAlphaChars)
$PasswordBinaryHash = [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Password))
$HashedPassword = ($PasswordBinaryHash | ForEach-Object { $_.ToString("x2") }) -join ""

$CertRole = "Web Server"

Write-Verbose "Sending the CSR to the DFN PKI web service..."
$CARequestId = $CA.newRequest($RegistrationAuthorityID, $CSR.PEM, $CertificateSANs, 
                              $CertRole, $HashedPassword, $ApplicantName, $ApplicantEMail,
                              $ApplicantOrgUnit, $true)

$Data = [ordered]@{    RAID = $RegistrationAuthorityID
                       RequestID = $CARequestId
                       HashedPassword = $HashedPassword
                       Password = $Password
                       CertificateRole = $CertRole
                       ApplicantName = $ApplicantName
                       ApplicantEmail = $ApplicantEMail
                       ApplicantOrgUnit = $ApplicantOrgUnit
                       SubjectAlternativeNames = $CertificateSANs
                       CSR = $CSR.PEM | Out-String
                       RequestINF = $CSR.INF | Out-String
                       RequestTime = (Get-Date)}

# Save status data
$RequestStatusFile = "$RequestStatusDirectory\$ComputerPrimaryFQDN-$Timestamp.request"
Write-Verbose "Saving the request status data as '$RequestStatusFile'"
New-Object -TypeName PSCustomObject -Property $Data | 
    ConvertTo-Json | 
    Out-File -FilePath $RequestStatusFile


If($GenerateApplicationForm) {
    # Generate PDF with the request data to be signed by $ApplicantName
    Try {
        Write-Verbose "Generating the certificate application form from '$RequestStatusFile'..."
        $ApplicationFormFile = . "$PSScriptRoot\New-CertificateApplicationForm.ps1" `
                                    -RequestFile $RequestStatusFile
    } Catch {
        Throw "Could not generate the certificate application form PDF: $_"
    }
    # Send the form file out via email, if $SmtpServerName has been defined
    If($SmtpServerName) {
        Try {
            $MessageSubject = "Certificate request for $ComputerPrimaryFQDN"
            $MessageBody = "Attached, you find the DFN PKI certificate application form for your computer $ComputerPrimaryFQDN" 
            Write-Verbose "Sending the certificate application form to '$ApplicantEMail' using '$SmtpServerName'..."
            If($SmtpCredential) {
                Send-MailMessage -Attachments $ApplicationFormFile.FullName `
                                    -To $ApplicantEMail `
                                    -From $SmtpFromEMail `
                                    -Subject $MessageSubject `
                                    -Body $MessageBody `
                                    -SmtpServer $SmtpServerName `
                                    -UseSsl:$SmtpUseSSL `
                                    -Credential $SmtpCredential
            } Else {
                Send-MailMessage -Attachments $ApplicationFormFile.FullName `
                                    -To $ApplicantEMail `
                                    -From $SmtpFromEMail `
                                    -Subject $MessageSubject `
                                    -Body $MessageBody `
                                    -SmtpServer $SmtpServerName `
                                    -UseSsl:$SmtpUseSSL `
            }
        } Catch {
            Throw "Could not send the certificate application form PDF to $ApplicantEmail through '$SmtpServerName': $_"
        }
    }
}

If($RegisterFetchingTask) {
    Try {
        $ComputerName = $ComputerPrimaryFQDN -replace "\..+"
        Write-Verbose "Registering a scheduled task for installing the certificate as soon as the application request is approved..."
        Register-FetchingTask -TaskName "Certificate Request $CARequestId for $ComputerName on $Timestamp" `
                              -RequestFile $RequestStatusFile
    } Catch {
        "Could not register the scheduled task for fetching the approved certificate: $_"
    }
}

If(-not $psISE) {
    Stop-Transcript
}