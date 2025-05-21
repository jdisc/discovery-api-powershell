<#
.SYNOPSIS
  Login/Logout example with GraphQL API.

.DESCRIPTION
  This script logs in and out to a GraphQL API. It takes user inputs such as API URL, username, and password. Missing passwords are requested interactively at runtime.

.PARAMETER apiUrl
  The URL of the GraphQL API.

.PARAMETER username
  The username for authentication.

.PARAMETER password
  The password for authentication. If not provided, it will be asked at the console.

.EXAMPLE
  .\login-logout-api.ps1 -apiUrl "https://localhost/graphql" -username "Administrator"
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$apiUrl = "https://localhost/graphql",

    [Parameter(Mandatory=$false)]
    [string]$username = "Administrator",

    [Parameter(Mandatory=$false)]
    [string]$password
)

# Define a callback to ignore SSL certificate errors
Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

Write-Output "API URL: $apiUrl"
Write-Output "Username: $username"

if (-not $password) {
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host -Prompt 'Enter password' -AsSecureString)))
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

$headers = @{ Authorization = "Bearer $accessToken" }

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
