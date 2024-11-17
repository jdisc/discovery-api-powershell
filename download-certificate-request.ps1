<#
.SYNOPSIS
  Download a certificate request via a GraphQL API.

.DESCRIPTION
  This script logs in to a GraphQL API, generates a certificate request with given parameters, downloads the request, and then logs out. It takes user inputs such as API URL, username, password, subject, key usage, and output format, and outputs the certificate request to a specified file.

.PARAMETER apiUrl
  The URL of the GraphQL API.

.PARAMETER username
  The username for authentication.

.PARAMETER password
  The password for authentication. If not provided, it will be asked at the console.

.PARAMETER subject
  The certificate subject.

.PARAMETER subjectAlternativeNames
  The certificate subject alternative names.

.PARAMETER shouldMakePEM
  Flag to indicate whether the desired certificate request should be delivered in PEM encoding (textual form).

.PARAMETER outputPath
  The path to save the downloaded certificate request.

.EXAMPLE
  .\Download-CertificateRequest.ps1 -apiUrl "https://localhost/graphql" -username "Administrator" -subject "CN=example.com" -keyUsage "digitalSignature, keyEncipherment" -shouldMakePEM $true -outputPath "C:\path\to\request.csr"
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$apiUrl = "https://localhost/graphql",

    [Parameter(Mandatory=$false)]
    [string]$username = $env:USERNAME,

    [Parameter(Mandatory=$false)]
    [string]$password,

    [Parameter(Mandatory=$false)]
    [string]$subject,

    [Parameter(Mandatory=$false)]
    [string[]]$subjectAlternativeNames = @(),

    [Parameter(Mandatory=$false)]
    [bool]$shouldMakePEM = $false,

    [Parameter(Mandatory=$false)]
    [string[]]$keyUsage = @("digitalSignature", "keyEncipherment"),

    [Parameter(Mandatory=$true)]
    [string]$outputPath
)

# Parse the apiUrl to get the protocol, server, and port
$uri = [System.Uri]$apiUrl
$protocol = $uri.Scheme
$server = $uri.Host
$port = if ($uri.Port -eq -1) { if ($protocol -eq "https") { 443 } else { 80 } } else { $uri.Port }

# Output parsed components (optional - for debugging purposes)
Write-Output "Protocol: $protocol"
Write-Output "Server: $server"
Write-Output "Port: $port"

# Prompt for missing password
if (-not $password) {
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host -Prompt 'Enter password' -AsSecureString)))
}

# Generate default subject
$countryCode = [System.Globalization.CultureInfo]::CurrentCulture.Name.Split('-')[-1]
$defaultSubject = "CN=$($env:COMPUTERNAME), C=$countryCode"

# Prompt for subject if not provided, showing the default value in brackets
if (-not $subject) {
    $subjectPrompt = "Enter subject [${defaultSubject}]"
    $subjectInput = Read-Host -Prompt $subjectPrompt
    $subject = if ($subjectInput) { $subjectInput } else { $defaultSubject }
}

# Get the DNS and IP entries for the current computer name
$dnsEntry = $env:COMPUTERNAME
$ipEntries = [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }

# Add DNS entry
$subjectAlternativeNames += "DNS:$dnsEntry"

# Add IP entries
$subjectAlternativeNames += $ipEntries | ForEach-Object { "IP:$_" }

# Function to check for GraphQL errors
function Check-GraphQLError {
    param (
        [Parameter(Mandatory=$true)]
        $response
    )
    if ($response.errors) {
        foreach ($error in $response.errors) {
            Write-Error "GraphQL Error: $($error.message)"
        }
        exit 1
    }
}

# Login
Write-Output "Logging in..."
$loginQuery = @'
mutation login($username: String!, $password: String!) {
  authentication {
    login(login: $username, password: $password) {
      accessToken
      status
    }
  }
}
'@

$loginVariables = @{ username = $username; password = $password }
$loginResponse = Invoke-RestMethod -Uri $apiUrl -Method Post -ContentType "application/json" -Body (@{ query = $loginQuery; variables = $loginVariables } | ConvertTo-Json) -Verbose
Write-Debug "Raw Login Response:"
Write-Debug ($loginResponse | ConvertTo-Json -Depth 10)
Check-GraphQLError -response $loginResponse
$accessToken = $loginResponse.data.authentication.login.accessToken
if (-not $accessToken) {
    Write-Error "Failed to log in. (Status: $($loginResponse.data.authentication.login.status))"
    exit 1
}

# Generate Certificate Request
Write-Output "Generating certificate request..."
$generateMutation = @'
mutation generateCertificateRequest($certificateRequest: CertificateRequestOptions!) {
  administration {
    certificateRequest(certificateRequestOptions: $certificateRequest) {
      baseUrl
      contentId
      accessToken
    }
  }
}
'@

$requestVariables = @{
    certificateRequest = @{
        shouldMakePEM = $shouldMakePEM
        subject = $subject
        subjectAlternativeNames = $subjectAlternativeNames
    }
}

Write-Debug "Request Body: $(@{ query = $generateMutation; variables = $requestVariables } | ConvertTo-Json  -Depth 4)"

$headers = @{ Authorization = "Bearer $accessToken" }
$generateResponse = Invoke-RestMethod -Uri $apiUrl -Method Post -ContentType "application/json" -Headers $headers -Body (@{ query = $generateMutation; variables = $requestVariables } | ConvertTo-Json -Depth 4 ) -Verbose
Write-Debug "Raw Generate Certificate Request Response:"
Write-Debug ($generateResponse | ConvertTo-Json -Depth 10)
Check-GraphQLError -response $generateResponse

$baseUrl = $generateResponse.data.administration.certificateRequest.baseUrl
$contentId = $generateResponse.data.administration.certificateRequest.contentId
$accessToken = $generateResponse.data.administration.certificateRequest.accessToken

if (-not $baseUrl -or -not $contentId -or -not $accessToken) {
    Write-Error "Failed to generate the certificate request."
    exit 1
}

# Define constant for port in URL
$portForUrl = if ($uri.Port -eq -1) { "" } else { ":$port" }

# Construct base request URL
$baseRequestUrl = "${protocol}://$server$portForUrl$baseUrl"

# Download Certificate Request from the provided URL
$requestUrl = "$baseRequestUrl/$contentId"
Write-Output "Downloading certificate request from $requestUrl..."
$downloadHeaders = @{ Authorization = "Bearer $accessToken" }
$response = Invoke-WebRequest -Uri $requestUrl -Method Get -Headers $downloadHeaders -ContentType "application/pkcs10" -OutFile $outputPath

# Validate the download
if (Test-Path $outputPath) {
    Write-Output "Certificate Request saved to $outputPath"
} else {
    Write-Error "Failed to save the certificate request."
}

# Logout
Write-Output "Logging out..."
$logoutQuery = @'
mutation logout($accessToken: String!) {
  authentication {
    logout(accessToken: $accessToken)
  }
}
'@

$logoutVariables = @{ accessToken = $accessToken }
$logoutResponse = Invoke-RestMethod -Uri $apiUrl -Method Post -ContentType "application/json" -Headers $headers -Body (@{ query = $logoutQuery; variables = $logoutVariables } | ConvertTo-Json) -Verbose
Write-Debug "Raw Logout Response:"
Write-Debug ($logoutResponse | ConvertTo-Json -Depth 10)
Check-GraphQLError -response $logoutResponse

Write-Output "Done."