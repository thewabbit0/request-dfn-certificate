Param(
    # The full path to the status file holding the certificate request information
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$CertRequestStatusFile,
    # Destination directory for successfully processed requests
    [string]$AcceptedRequestsDirectory = "$PSScriptRoot\AcceptedRequests",
    # Option to move the request status file to $AcceptedRequestsDirectory upon a successful certificate installation
    [switch]$MoveStatusFileWhenSuccessful = $true,
    # Option to remove the scheduled task for regularily checking on the certificate upon a successful certificate installation
    [switch]$RemoveScheduledTask = $true,
    # URI of the DFN PKI "public" SOAP interface
    [string]$PublicSOAPUri = "https://pki.pca.dfn.de/dfn-ca-global-g2/cgi-bin/pub/soap?wsdl=1"
)

Function Remove-ScheduledFetchingTask {
<#
.SYNOPSIS
Unregisters the scheduled task which has called this script.
#>
    Param(
        [Parameter(Mandatory)]
        [string]$RequestFile
    )
    
    $CertificateFetchingTask = Get-ScheduledTask | Where-Object { $_.Actions.Execute -ilike "*powershell.exe" `
                                                                  -and  $_.Actions.Arguments -ilike "*-File*$PSCommandPath*-CertRequestStatusFile*$RequestFile*"} 
    If(-not $CertificateFetchingTask) {
        Write-Warning "Could not find a scheduled task invoking '$PSCommandPath' with '$RequestFile' as part of its parameter set"
    } Else {
        $CertificateFetchingTask | Unregister-ScheduledTask -Confirm:$false
    }

}

$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

If(-not $psISE) {
    $ScriptName = $PSCommandPath -replace "^.+\\"
    Start-Transcript -Path "$PSScriptRoot\logs\$ScriptName.transcript" -Force
}

Write-Verbose "Connecting to DFN PKI public web service at '$PublicSOAPUri'..."
# Allow the use of TLS 1.2 for the SOAP connection
[System.Net.ServicePointManager]::SecurityProtocol = "Tls11,Tls12"
$CA = New-WebServiceProxy -Uri $PublicSOAPUri

Write-Verbose "Reading request data from '$CertRequestStatusFile'..."
$CertRequest = Get-Content -Path $CertRequestStatusFile -Raw | ConvertFrom-Json
Write-Verbose "Fetching certificate from the DFN PKI web service (RA ID: $($CertRequest.RAID), RequestID: $($CertRequest.RequestID)..."
$CertificateData = $CA.getCertificateByRequestSerial($CertRequest.RAID, $CertRequest.RequestID, $CertRequest.HashedPassword)
If($CertificateData) {
    $Timestamp = (Get-Date -Format o) -replace "\..+" -replace ":"
    $CertFileName = "$env:TEMP\$($CertRequest.RequestID)-$Timestamp.crt"
    Write-Verbose "A certificate has been received and saved as a temporary file to '$CertFileName', importing it using 'certreq -accept'..."
    $CertificateData | Out-String | Out-File -FilePath $CertFileName
    certreq.exe -accept -q -machine $CertFileName
    If($LASTEXITCODE -ne 0) {
    #    Throw "Certificate installation of '$CertFileName' failed."
    }
    Write-Verbose "Installed certificate for request ID $($CertRequest.RequestID)"

    Try {
        Remove-Item $CertFileName -Force
    } Catch {
        Write-Warning "Error removing the temporary certificate file '$CertFileName': $_"
    }

    If($MoveStatusFileWhenSuccessful) {
        Try {
            Write-Verbose "Moving the certificate request status file '$CertRequestStatusFile' to '$AcceptedRequestsDirectory'..."
            Move-Item $CertRequestStatusFile -Destination $AcceptedRequestsDirectory -Force
        } Catch {
            Write-Warning "Error moving the request status file '$CertRequestStatusFile' to '$AcceptedRequestsDirectory': $_"
        }
    }

    If($RemoveScheduledTask) {
        Try {
            Write-Verbose "Removing the scheduled task checking for certificate availability..."
            Remove-ScheduledFetchingTask -RequestFile $CertRequestStatusFile
        } Catch {
            Write-Warning "Removing the scheduled task failed: $_"
        }
    }
} Else {
    Write-Verbose "No certificate has been received - try checking again after the request has been approved by the RA."
}


If(-not $psISE) {
    Stop-Transcript
}