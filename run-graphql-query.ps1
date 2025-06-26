<#
.SYNOPSIS
  Runs a GraphQL Query that is provided in a text file (graphQLQueryFileName) and stores the Query response into a text file (graphQLResponseFileName)

.DESCRIPTION
  This script logs in to a GraphQL API, installs a given certificate, and then logs out. It takes user inputs such as API URL, username, and password, and paths to certificates and keys. Missing passwords are requested interactively at runtime.

.PARAMETER apiUrl
  The URL of the GraphQL API.

.PARAMETER username
  The username for authentication.

.PARAMETER password
  The password for authentication. If not provided, it will be asked at the console.
  
.PARAMETER graphQLQueryFileName
  The text file containing the GraphQL query to run.
  
.PARAMETER graphQLResponseFileName
  The text file name to store the response of the GraphQL query 
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$apiUrl = "https://localhost/graphql",

    [Parameter(Mandatory=$false)]
    [string]	$username = "Administrator",

    [Parameter(Mandatory=$false)]
    [string]$password,
	
	[Parameter(Mandatory=$true)]
	[string]$graphQLQueryFileName,
	
	[Parameter(Mandatory=$true)]
	[string]$graphQLResponseFileName
)


Write-Output "API URL: $apiUrl"
Write-Output "Username: $username"

if (-not $password) {
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host -Prompt 'Enter password' -AsSecureString)))
}

if(-not $graphQLQueryFileName) {
	$graphQLQueryFileName = Read-Host -Prompt 'Enter graphQLQueryFileName'
}

if(-not $graphQLResponseFileName) {
	$graphQLQuerygraphQLResponseFileNameFileName = Read-Host -Prompt 'Enter graphQLResponseFileName'
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

Write-Output ("Reading Query from file '" + $graphQLQueryFileName+ "'") 
$contentToInsert = Get-Content $graphQLQueryFileName | Out-String
$exportQuery = $contentToInsert 
$exportQueryVariables = @{ accessToken = $accessToken }

Write-Output "Running Query..."
$exportQueryResponse = Invoke-RestMethod -Uri $apiUrl -Method Post -ContentType "application/json" -Headers $headers -Body (@{ query = $exportQuery; variables = $exportQueryVariables } | ConvertTo-Json) -Verbose

Write-Output ("Writing Query Response to '" + $graphQLResponseFileName+ "'") 

($exportQueryResponse | ConvertTo-Json -Depth 10) | Out-File -FilePath $graphQLResponseFileName

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