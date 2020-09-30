Param(
    # The request file to base the application form on
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$RequestFile,
    # the PDF form with defined fields to use as a fill template
    [string]$PDFFormTemplate = "$PSScriptRoot\Templates\CertificateRequestApplicationFormTemplate.pdf",
    # the path and file name of the output PDF file with field data entered
    [string]$OutFile = "$($RequestFile -replace ".request$").pdf"
)

# We use BouncyCastle for CSR decoding, but it is a prerequisite for itextsharp too
Add-Type -Path "$PSScriptRoot\bin\BouncyCastle.Crypto.dll"
# itextsharp allows us to work with PDFs
Add-Type -Path "$PSScriptRoot\bin\itextsharp.dll"


function Save-PdfField
<#
.SYNOPSIS
Creates a new PDF documend based on $InputPdfFilePath with its defined fields filled with data according 
to the hashtable $Fields
.DETAIL
stolen from https://raw.githubusercontent.com/adbertram/Random-PowerShell-Work/master/Random%20Stuff/PdfForm.psm1
#>
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[Hashtable]$Fields,
		
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('\.pdf$')]
		[ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
		[string]$InputPdfFilePath,
		
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('\.pdf$')]
		[ValidateScript({ -not (Test-Path -Path $_ -PathType Leaf) })]
		[string]$OutputPdfFilePath
	)
	begin
	{
		$ErrorActionPreference = 'Stop'
	}
	process
	{
		try
		{
			$reader = New-Object iTextSharp.text.pdf.PdfReader -ArgumentList $InputPdfFilePath
			$stamper = New-Object iTextSharp.text.pdf.PdfStamper($reader, [System.IO.File]::Create($OutputPdfFilePath))
			
			## Apply all hash table elements into the PDF form
			foreach ($j in $Fields.GetEnumerator())
			{
				$null = $stamper.AcroFields.SetField($j.Key, "$($j.Value)")
			}
		}
		catch
		{
			$PSCmdlet.ThrowTerminatingError($_)
		}
		finally
		{
			## Close up shop 
			$stamper.Close()
			Get-Item -Path $OutputPdfFilePath
		}
	}
}

Function Out-DfnPKITextKey {
    Param (
        [Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters]$RSAKey,
        [string]$LineIndentation = "    ",
        [int]$BytesPerLine = 15,
        [string]$ByteSeparator = ":"
    )

    $Output = [System.Collections.ArrayList]::new()
    $Output.Add(@("Modulus ($($RSAKey.Modulus.BitLength) bit):")) | Out-Null

    [byte[]]$Bytes = $RSAKey.Modulus.ToByteArray()
    # Build lines of up to $BytesPerLine elements separated
    # by $ByteSeparator and prepended by $LineIndentation
    For($i=0; $i -lt $Bytes.Count; $i+=$BytesPerLine) {
        # Determine the upper range - either the end of array
        # or the current index + BytesPerLine
        $UpperRangeForLine = If($i + $BytesPerLine -lt $Bytes.Count) { 
                                $i + $BytesPerLine - 1 
                             } Else {
                                $Bytes.Count - 1
                             }
        [byte[]]$lineBytes = $Bytes[$i..$UpperRangeForLine]
        $lineElements = [System.Collections.ArrayList]::new()
        $lineBytes | ForEach-Object {
            $lineElements.Add($_.ToString("x2") + $ByteSeparator) | Out-Null
        }
        [string]$currentLine = $LineIndentation + ($lineElements -join "")
        # Trim off the last separator 
        If($UpperRangeForLine -eq ($Bytes.Count - 1)) {
            $currentLine = $currentLine.TrimEnd($ByteSeparator)
        }
        $Output.Add($currentLine) | Out-Null
    }
    $Exponent = $RSAKey.Exponent.LongValue
    $Output.Add("Exponent: $Exponent (0x$($Exponent.ToString("x2")))") | Out-Null
    # return the assembled lines as a string array
    [string[]]$Output
}

$ErrorActionPreference = "Stop"

$CertRequest = Get-Content -Path $RequestFile -Raw | ConvertFrom-Json
# Read and decode the CSR PEM data using BouncyCastle's PemReader
$PEMOobject = [Org.BouncyCastle.OpenSsl.PemReader]::new([System.IO.StringReader]::new($CertRequest.csr)).ReadObject()
# Determine the certificate request's subject, formatted as a distinguished name string
# split it up into its elements and reverse them (certreq stores the attributes in reverse 
# order compared to what DFN-PKI is printing on the application form)
[string[]]$PEMSubjectArray = $PEMOobject.GetCertificationRequestInfo().Subject -split ","
[array]::Reverse($PEMSubjectArray)

[string]$PublicKeyDataString = ((Out-DfnPKITextKey -RSAKey $PEMOobject.GetPublicKey()) -join "`n") + "`n"
[byte[]]$PublicKeyDataBytes = [System.Text.Encoding]::UTF8.GetBytes($PublicKeyDataString)
$PublicKeyFingerPrint = ([System.Security.Cryptography.SHA1]::Create().ComputeHash($PublicKeyDataBytes) | ForEach-Object {
                             $_.ToString("X2")
                         }) -join ":"

$Fields = @{
    RequestID = $CertRequest.RequestID
    ApplicantName = $CertRequest.ApplicantName
    ApplicantEmail = $CertRequest.ApplicantEmail
    ApplicantOrgUnit = $CertRequest.ApplicantOrgUnit
    CertificateCN = $PEMSubjectArray -join ", "
    CertificateSANs = ($CertRequest.SubjectAlternativeNames | ForEach-Object { "DNS:$_" }) -join ", "
    CertificatePKFingerprint = $PublicKeyFingerPrint
    CertificateRole = $CertRequest.CertificateRole
    date = Get-Date -Date $CertRequest.RequestTime.DateTime -UFormat "%Y-%m-%d"
    datetime = Get-Date -Date $CertRequest.RequestTime.DateTime -UFormat "%Y-%m-%d %R"
    RAID = $CertRequest.RAID
}

# Create the new filled out PDF - returns the fileinfo object of the created file
Save-PdfField -Fields $Fields -InputPdfFilePath $PDFFormTemplate -OutputPdfFilePath $OutFile
