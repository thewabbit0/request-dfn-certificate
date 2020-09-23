Param(
    [string]$RequestStatusDirectory = "$PSScriptRoot\PendingRequests",
    [string]$AcceptedRequestsDirectory = "$PSScriptRoot\AcceptedRequests",
    [string]$TimedoutRequestsDirectory = "$PSScriptRoot\TimedoutRequests",
    [string]$PublicSOAPUri = "https://pki.pca.dfn.de/dfn-ca-global-g2/cgi-bin/pub/soap?wsdl=1"
)

$RequestFiles = Get-ChildItem -Path "$RequestStatusDirectory\*.request"
If(-not $RequestFiles) {
    Write-Verbose "No request files present in '$RequestStatusDirectory', finished processing."
}

$CA = New-WebServiceProxy -Uri $PublicSOAPUri

$RequestFiles | ForEach-Object {
    $CertRequestStatusFile = $_.FullName
    $CertRequest = Get-Content -Path $CertRequestStatusFile -Raw | ConvertFrom-Json
    $CertificateData = $CA.getCertificateByRequestSerial($CertRequest.RAID, $CertRequest.RequestID, $CertRequest.HashedPassword)
    If($CertificateData) {
        $Timestamp = (Get-Date -Format o) -replace "\..+" -replace ":"
        $CertFileName = "$env:TEMP\$($CertRequest.RequestID)-$Timestamp.crt"
        $CertificateData | Out-String | Out-File -FilePath $CertFileName
        certreq.exe -accept $CertFileName
        If($LASTEXITCODE -eq 0) {
            Write-Verbose "Installed certificate for request ID $($CertRequest.RequestID)"
            Move-Item -Path $_ -Destination $AcceptedRequestsDirectory -Force
        }
        Remove-Item $CertFileName -Force
    }
}


