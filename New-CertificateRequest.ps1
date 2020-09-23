Param(
    # Registration Authority ID for the DFN PKI
    [int]$CA_RAID = 1520,
    [string]$PublicSOAPUri = "https://pki.pca.dfn.de/dfn-ca-global-g2/cgi-bin/pub/soap?wsdl=1",
    [string]$RequestStatusDirectory = "$PSScriptRoot\PendingRequests"
)

# Get name and DNS suffix data from WMI
$WMIComputerSystem = Get-WmiObject -Class Win32_ComputerSystem
$WMINetworkAdapterConfiguration = gwmi -Query "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = 'TRUE'"

$ComputerFQDNs = [System.Collections.ArrayList]::new()
$WMINetworkAdapterConfiguration | ForEach-Object {
    $_.DNSDomainSuffixSearchOrder | ForEach-Object {
        $ComputerFQDNs.Add("$($WMIComputerSystem.DNSHostName).$_") | Out-Null
    }
}

# Get the delegated OU and the department from the DN in the adworkstationou environment variable (set by deployment)
If(-not ($env:adworkstationou -match "^(OU=[^,]+,)+OU=(?<DelegatedOU>[^,]+),OU=(?<Department>[^,]+),(OU=[^,]+,)(DC=[^,]+,)*(DC=[^,]+)$")) {
    Throw "Could not determine the delegated OU from adworkstationou ($env:adworkstationou)"
}

$DelegatedOUName = $Matches.DelegatedOU
$DepartmentName = $Matches.Department

# Only allow to run elevated
if (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Throw "Administrator privileges are required to request a new machine certificate."
}


$ComputerPrimaryFQDN = $ComputerFQDNs | Select-Object -First 1
$ComputerFQDNs = [array]$ComputerFQDNs | Select-Object -Unique
$Timestamp = (Get-Date -Format o) -replace "\..+" -replace ":"
$CSRinfFileName = "$env:TEMP\$ComputerPrimaryFQDN-request-$Timestamp.inf"
$CSRFileName = "$env:TEMP\$ComputerPrimaryFQDN-$Timestamp.csr"


$CSRinf = @"
;----------------- request.inf -----------------

[Version]
Signature="`$Windows NT$"

[NewRequest]
Subject = "CN=$ComputerPrimaryFQDN, O=Technische Hochschule Koeln,L=Koeln,ST=Nordrhein-Westfalen,C=DE"

KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
HashAlgorithm = SHA256

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1
;-----------------------------------------------
"@

# Create a CSR file using certreq.exe and read the contents
$CSRinf | Out-File -FilePath $CSRinfFileName
certreq.exe -new $CSRinfFileName $CSRFileName
$CSRpem = Get-Content -Path $CSRFileName -Raw

# Allow the use of TLS 1.2 for the SOAP connection
[System.Net.ServicePointManager]::SecurityProtocol = "Tls11,Tls12"
$CA = New-WebServiceProxy -Uri $PublicSOAPUri

$PwLength = 15 ## characters
$PwNonAlphaChars = 2
$Password = [System.Web.Security.Membership]::GeneratePassword($Pwlength, $PwnonAlphaChars)
$PasswordBinaryHash = [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Password))
$HashedPassword = ($PasswordBinaryHash | ForEach-Object { $_.ToString("x2") }) -join ""

$CertRole = "Web Server"

$AddName = "Denis Jedig"
$AddEMail = "denis.jedig@th-koeln.de"
$AddOrgUnit = "$DepartmentName, $DelegatedOUName"

$CARequestId = $CA.newRequest($CA_RAID, $CSRpem, $ComputerFQDNs, 
                              $CertRole, $HashedPassword, $AddName, $AddEMail,
                              $AddOrgUnit, $true)

$Data = [ordered]@{    RAID = $CA_RAID
                       RequestID = $CARequestId
                       HashedPassword = $HashedPassword
                       Password = $Password
                       CertificateRole = $CertRole
                       ApplicantName = $AddName
                       ApplicantEmail = $AddEMail
                       ApplicantOrgUnit = $AddOrgUnit
                       SubjectAlternativeNames = $ComputerFQDNs
                       CSR = $CSRpem | Out-String
                       RequestINF = $CSRinf | Out-String
                       RequestTime = (Get-Date)}

New-Object -TypeName PSCustomObject -Property $Data | ConvertTo-Json | Out-File -FilePath "$RequestStatusDirectory\$ComputerPrimaryFQDN-$Timestamp.request"