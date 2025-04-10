using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Output "PowerShell HTTP trigger function processed a request."

$content = @'
authentication level:i:0
full address:s:{0}
gatewayhostname:s:{1}
gatewayusagemethod:i:1
username:s:{2}
use multimon:i:0
prompt for credentials:i:1
'@

//$Request.params.hostname = $Request.params.hostname
//$env:APPSETTING_rdgwfedauth_gwhost = $env:APPSETTING_rdgwfedauth_gwhost
//$Request.Headers["x-ms-client-principal-name"] = $Request.Headers["x-ms-client-principal-name"]

Write-Output "rdgwfedauth_hostname = $Request.params.hostname"
Write-Output "rdgwfedauth_gwhost = $env:APPSETTING_rdgwfedauth_gwhost"
Write-Output "rdgwfedauth_username = $Request.Headers["x-ms-client-principal-name"]"

$Response = $null

if (-not ($env:APPSETTING_rdgwfedauth_gwhost)) {
    Write-Output "Failure: Missing env APPSETTING_rdgwfedauth_gwhost"
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::InternalServerError
        Body = "Internal server error.  Required configuration keys are missing."
    })
}

if (-not $Request.Headers["x-ms-client-principal-name"]) {
    Write-Output "Failure: Missing header x-ms-client-principal-name"
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::Unauthorized
        Body = "Unauthorized.  Client principal name is missing from token."
    })
}

if (-not ($Request.params.hostname -match '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')) {
    Write-Output "Failure: Hostname mismatches regex"
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::BadRequest
        Body = "Bad Request.  Host name not valid: $($Request.params.hostname)"
    })
}

if (-not ((-not $Response) -and $Request.params.hostname -and $env:APPSETTING_rdgwfedauth_gwhost -and $Request.Headers["x-ms-client-principal-name"])) {
    Write-Output "Failure: Unidentified"
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::InternalServerError
        Body = "Internal server error.  Unidentified failure."
    })
}

if ((-not $Response) -and $Request.params.hostname -and $env:APPSETTING_rdgwfedauth_gwhost -and $Request.Headers["x-ms-client-principal-name"]) {
    // connect to key vault
    // create token https://github.com/Azure/azure-devtestlab/blob/master/samples/DevTestLabs/GatewaySample/src/RDGatewayAPI/Functions/CreateToken.cs
    // figure out where to put token in RDP file
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body = $content.replace('{0}',$Request.params.hostname).replace('{1}',$env:APPSETTING_rdgwfedauth_gwhost).replace('{2}',$Request.Headers["x-ms-client-principal-name"])
        ContentType = 'application/octet-stream'
    })
}

if ($Response) {
    Push-OutputBinding -Name Response -Value $Response
} else {
    Write-Output "Failure: response missing, this should not happen"
}