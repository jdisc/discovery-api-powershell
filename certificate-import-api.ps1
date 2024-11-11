<#
.SYNOPSIS
  Install a certificate via a GraphQL API.

.DESCRIPTION
  This script logs in to a GraphQL API, installs a given certificate, and then logs out. It takes user inputs such as API URL, username, and password, and paths to certificates and keys. Missing passwords are requested interactively at runtime.

.PARAMETER apiUrl
  The URL of the GraphQL API.

.PARAMETER username
  The username for authentication.

.PARAMETER password
  The password for authentication. If not provided, it will be asked at the console.

.PARAMETER certPath
  The path to the X.509 certificate or PKCS#12 bundle.

.PARAMETER keyPath
  The path to the private key.

.PARAMETER keyPassword
  Password to decrypt the private key. If not provided, it will be asked at the console.

.EXAMPLE
  .\Install-Certificate.ps1 -apiUrl "https://localhost/graphql" -username "Administrator" -certPath "C:\path\to\cert.pfx" -keyPath "C:\path\to\key.pem"
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$apiUrl = "https://localhost/graphql",

    [Parameter(Mandatory=$false)]
    [string]$username = "Administrator",

    [Parameter(Mandatory=$false)]
    [string]$password,

    [Parameter(Mandatory=$true)]
    [string]$certPath,

    [Parameter(Mandatory=$false)]
    [string]$keyPath,

    [Parameter(Mandatory=$false)]
    [string]$keyPassword
)

if (-not $certPath) {
    Write-Output "Usage: .\Install-Certificate.ps1 -apiUrl <API URL> -username <Username> -certPath <Path to Certificate> -keyPath <Path to Private Key>"
    exit 1
}

Write-Output "API URL: $apiUrl"
Write-Output "Username: $username"
Write-Output "Certificate Path: $certPath"
Write-Output "Private Key Path: $keyPath"

if (-not $password) {
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host -Prompt 'Enter password' -AsSecureString)))
}

if (-not $keyPassword) {
    $keyPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host -Prompt 'Enter private key password' -AsSecureString)))
}

# Convert certificate and private key to integer arrays
$certBytes = ([System.IO.File]::ReadAllBytes($certPath) | ForEach-Object { if ($_ -gt 127) { $_ - 256 } else { $_ } }) -join ','
# Initialize keyBytes to an empty string if keyPath is not provided
$keyBytes = ""
if ($keyPath) {
    Write-Verbose "Reading private key from $keyPath"
    $keyBytes = ([System.IO.File]::ReadAllBytes($keyPath) | ForEach-Object { if ($_ -gt 127) { $_ - 256 } else { $_ } }) -join ','
}

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
      refreshToken
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

# Install Certificate
Write-Output "Installing certificate..."
$installQuery = @'
mutation installWebServerCertificate ($certificate: [Int]!, $privateKey: [Int], $password: String) {
  administration {
    installWebServerCertificate (certificateBytes: $certificate, privateKeyBytes: $privateKey, password: $password)
  }
}
'@
$installVariables = @{ certificate = $certBytes -split ','; privateKey = if ($keyPath) { $keyBytes -split ',' } else { $null }; password = $keyPassword }
$headers = @{ Authorization = "Bearer $accessToken" }
$installResponse = Invoke-RestMethod -Uri $apiUrl -Method Post -ContentType "application/json" -Headers $headers -Body (@{ query = $installQuery; variables = $installVariables } | ConvertTo-Json) -Verbose
Write-Debug "Raw Install Certificate Response:"
Write-Debug ($installResponse | ConvertTo-Json -Depth 10)
Check-GraphQLError -response $installResponse
Write-Output "Certificate import completed. (Status: $($installResponse.data.administration.installWebServerCertificate))"

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
