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
'@

$rdgwfedauth_hostname = $Request.params.hostname
$rdgwfedauth_gwhost = $env:APPSETTING_rdgwfedauth_gwhost
$rdgwfedauth_username = $Request.Headers["x-ms-client-principal-name"]

Write-Output "rdgwfedauth_hostname = $rdgwfedauth_hostname"
Write-Output "rdgwfedauth_gwhost = $rdgwfedauth_gwhost"
Write-Output "rdgwfedauth_username = $rdgwfedauth_username"

$Response = $null

if (-not ($rdgwfedauth_gwhost)) {
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::InternalServerError
        Body = "Internal server error.  Required configuration keys are missing."
    })
}

if (-not $Request.Headers["x-ms-client-principal-name"]) {
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::Unauthorized
        Body = "Unauthorized.  Client principal name is missing from token."
    })
}

if (-not ($Request.params.hostname -match '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')) {
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::BadRequest
        Body = "Bad Request.  Host name not valid: $($Request.params.hostname)"
    })
}

if ((-not $Response) -and $rdgwfedauth_hostname -and $rdgwfedauth_gwhost -and $rdgwfedauth_username) {
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body = $content.replace('{0}',$rdgwfedauth_hostname).replace('{1}',$rdgwfedauth_gwhost).replace('{2}',$rdgwfedauth_username)
        ContentType = 'application/octet-stream'
    })
} Else {
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::InternalServerError
        Body = "Internal server error.  Unidentified failure."
    })
}

Push-OutputBinding -Name Response -Value $Response