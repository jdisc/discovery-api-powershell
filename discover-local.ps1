

param (
    [string]$url = 'https://localhost/graphql',
    [string]$user = "Administrator",
    [Parameter(Mandatory=$true)][string]$password = $( Read-Host "Input password, please" )
)
$DebugPreference = 'Continue'

# authenticate to the JDisc API using login mutation
function JDisc-Authenticate {
    param (
        [string]$url = "https://localhost/graphql",
        [string]$user = "Administrator",
        [Parameter(Mandatory=$true)][string]$password
     )


    $mutation = "
    mutation {
      authentication {
        login(login: `"$user`", password: `"$password`") {
          status
          accessToken
          refreshToken
          rights
        }
      }
    }"
    
    Write-Host "Authenticating with URL $url and user $user" 
    #Write-Debug "mutation $mutation"
    $jsonResult = Invoke-GraphQLQuery -Mutation $mutation -Uri $url 
    return $jsonResult.data.authentication.login.accessToken
}

# upload a define using the importManager mutation
# attention the device is not json but the format that the graphql API requires, that is without quotes around the attributes
function JDisc-Upload-Device {
    param (
        [string]$url = "https://localhost/graphql",
        [Parameter(Mandatory=$true)][string]$token,
        $device
     )

    $mutation = "
        mutation {
          importManager {
            devices {
              importDevice(device: $device) {
                warnings
                errors
              }
            }
          }
        }"
    $requestHeaders = @{ Authorization="Bearer $token" }
    #Write-Debug "Senging importManager mutation to $url`: $mutation"
    $jsonResult = Invoke-GraphQLQuery -Mutation $mutation -Headers $requestHeaders -Uri $url 
    $errors = $jsonResult.data.errors
    $warnings = $jsonResult.data.warnings
    if ( $warnings ){
        Write-Host "Warnings: $warnings"
    }
    if ( $errors ){
      Write-Host "Errors: $errors"
  }
}

# authenticate
$token = JDisc-Authenticate -url $url -user $user -password $password
#Write-Debug "token $token"

# collect information
$os = Get-WmiObject -ComputerName DESKTOP-RT1CMG3 -Class Win32_OperatingSystem|Select-Object -Property *
$computer = Get-CimInstance -ClassName Win32_ComputerSystem|Select-Object -Property *

#build json object
$device = @"
{
  type: `"Laptop`",
  model: `"$($computer.Model)`",
  name: `"$($computer.Name)`",
  computername: `"$($computer.Name)`",
  serialNumber: `"$($os.SerialNumber)`",
  operatingSystem: {
    osFamily: `"Windows`",
    osVersion: `"$($os.Caption)`",
    manufacturer: `"$($os.Manufacturer)`",
    systemType: `"$($computer.SystemType)`"
  }
}
"@
Write-Host "Uploading device $device"

# upload the device
JDisc-Upload-Device -url $url -token $token -device $device

# eof