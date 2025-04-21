using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Information "PowerShell HTTP trigger function processed a request."

$rdpfile = @'
authentication level:i:0
full address:s:{0}
gatewayhostname:s:{1}
gatewayusagemethod:i:1
username:s:{2}
use multimon:i:0
prompt for credentials:i:1
'@

$rdpfile = @'
full address:s:{1}
alternate full address:s:{1}
username:s:{2}
gatewayhostname:s:{0}
screen mode id:i:2
audiomode:i:0
redirectprinters:i:0
redirectcomports:i:0
redirectsmartcards:i:1
redirectclipboard:i:1
redirectposdevices:i:0
drivestoredirect:s:*
autoreconnection enabled:i:1
authentication level:i:0
prompt for credentials:i:0
negotiate security layer:i:1
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewayusagemethod:i:1
gatewaycredentialssource:i:0
gatewayprofileusagemethod:i:1
promptcredentialonce:i:1
audiocapturemode:i:0
videoplaybackmode:i:1
connection type:i:2
redirectdirectx:i:1
use redirection server name:i:0
networkautodetect:i:1
bandwidthautodetect:i:1
enableworkspacereconnect:i:0
rdgiskdcproxy:i:0
kdcproxyname:s:
gatewaybrokeringtype:i:0
redirectwebauthn:i:1
enablerdsaadauth:i:0
'@

#$Request.params.hostname = $Request.params.hostname
#$env:APPSETTING_rdgwfedauth_gwhost = $env:APPSETTING_rdgwfedauth_gwhost
#$Request.Headers["x-ms-client-principal-name"] = $Request.Headers["x-ms-client-principal-name"]

<#
Write-Information "rdgwfedauth_hostname = $($Request.params.hostname)"
Write-Information "rdgwfedauth_gwhost = $($env:APPSETTING_rdgwfedauth_gwhost)"
Write-Information "rdgwfedauth_username = $($Request.Headers["x-ms-client-principal-name"])"

Write-Information '$Request.Headers'
$Request.Headers.keys |
Select-Object @{Name="Key";Expression={$_}},@{Name="Value";Expression={$Request.Headers[$_]}}
Write-Information 'end $Request.Headers'
Write-Information 'Env:'
Get-ChildItem env:\*
Write-Information 'end Env:'
#>

$Response = $null

if (-not ($env:APPSETTING_rdgwfedauth_gwhost)) {
    Write-Information "Failure: Missing env APPSETTING_rdgwfedauth_gwhost"
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::InternalServerError
        Body = "Internal server error.  Required configuration keys are missing."
    })
}

if (-not $Request.Headers["x-ms-client-principal-name"]) {
    Write-Information "Failure: Missing header x-ms-client-principal-name"
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::Unauthorized
        Body = "Unauthorized.  Client principal name is missing from token."
    })
}

if (-not ($Request.params.hostname -match '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')) {
    Write-Information "Failure: Hostname mismatches regex"
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::BadRequest
        Body = "Bad Request.  Host name not valid: $($Request.params.hostname)"
    })
}

<#
if (-not ((-not $Response) -and $Request.params.hostname -and $env:APPSETTING_rdgwfedauth_gwhost -and $Request.Headers["x-ms-client-principal-name"])) {
    Write-Information "Failure: Unidentified"
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::InternalServerError
        Body = "Internal server error.  Unidentified failure."
    })
}
#>

Write-Information "Almost to processing"

if ((-not $Response) -and $Request.params.hostname -and $env:APPSETTING_rdgwfedauth_gwhost -and $Request.Headers["x-ms-client-principal-name"]) {
    # connect to key vault
    # done: create token? https://github.com/Azure/azure-devtestlab/blob/master/samples/DevTestLabs/GatewaySample/src/RDGatewayAPI/Functions/CreateToken.cs
    # done: sign token: https://github.com/Azure/azure-devtestlab/blob/544d203c22bc3efc28781ffd6ef6d31b0c7e6ab2/samples/DevTestLabs/GatewaySample/src/RDGatewayAPI/Functions/CreateToken.cs
    # sign rdp file: https://github.com/gabriel-sztejnworcel/pyrdgw

    $securesettings = @{
        'username:s:'='Username';
        'full address:s:'='Full Address';
        'alternate full address:s:'='Alternate Full Address'
        'gatewaycredentialssource:i:5'='GatewayCredentialsSource'
        'gatewayaccesstoken:s:'='GatewayAccesstoken'
        #'endpointfedauth:s:'='?'
    }
    $othersettings = @{
        'pcb:s:'='PCB';
        'use redirection server name:i:'='Use Redirection Server Name';
        'server port:i:'='Server Port';
        'negotiate security layer:i:'='Negotiate Security Layer';
        'enablecredsspsupport:i:'='EnableCredSspSupport';
        'disableconnectionsharing:i:'='DisableConnectionSharing';
        'autoreconnection enabled:i:'='AutoReconnection Enabled';
        'gatewayhostname:s:'='GatewayHostname';
        'gatewayusagemethod:i:'='GatewayUsageMethod';
        'gatewayprofileusagemethod:i:'='GatewayProfileUsageMethod';
        'support url:s:'='Support URL';
        'promptcredentialonce:i:'='PromptCredentialOnce';
        'require pre-authentication:i:'='Require pre-authentication';
        'pre-authentication server address:s:'='Pre-authentication server address';
        'alternate shell:s:'='Alternate Shell';
        'shell working directory:s:'='Shell Working Directory';
        'remoteapplicationprogram:s:'='RemoteApplicationProgram';
        'remoteapplicationexpandworkingdir:s:'='RemoteApplicationExpandWorkingdir';
        'remoteapplicationmode:i:'='RemoteApplicationMode';
        'remoteapplicationguid:s:'='RemoteApplicationGuid';
        'remoteapplicationname:s:'='RemoteApplicationName';
        'remoteapplicationicon:s:'='RemoteApplicationIcon';
        'remoteapplicationfile:s:'='RemoteApplicationFile';
        'remoteapplicationfileextensions:s:'='RemoteApplicationFileExtensions';
        'remoteapplicationcmdline:s:'='RemoteApplicationCmdLine';
        'remoteapplicationexpandcmdline:s:'='RemoteApplicationExpandCmdLine';
        'prompt for credentials:i:'='Prompt For Credentials';
        'authentication level:i:'='Authentication Level';
        'audiomode:i:'='AudioMode';
        'redirectdrives:i:'='RedirectDrives';
        'redirectprinters:i:'='RedirectPrinters';
        'redirectcomports:i:'='RedirectCOMPorts';
        'redirectsmartcards:i:'='RedirectSmartCards';
        'redirectposdevices:i:'='RedirectPOSDevices';
        'redirectclipboard:i:'='RedirectClipboard';
        'devicestoredirect:s:'='DevicesToRedirect';
        'drivestoredirect:s:'='DrivesToRedirect';
        'loadbalanceinfo:s:'='LoadBalanceInfo';
        'redirectdirectx:i:'='RedirectDirectX';
        'rdgiskdcproxy:i:'='RDGIsKDCProxy';
        'kdcproxyname:s:'='KDCProxyName';
        'eventloguploadaddress:s:'='EventLogUploadAddress'
    }
    
    $rdpfile_output = $rdpfile.split("[`r`n]") |
    ForEach-Object {
        if (-not $securesettings.ContainsKey($_.split(":",3)[0]) ) {
            $rdpfile_output += "$_`r`n"
        }
    }

    $rdgwtoken = Get-RdGwToken -KeyVault -Machinehost $Request.params.hostname

    if ($rdgwtoken) {
        $rdpfile_output += "full address:s:$($Request.params.hostname)`r`n"
        $rdpfile_output += "alternate full address:s:$($Request.params.hostname)`r`n"
        $rdpfile_output += "gatewayhostname:s:$($env:APPSETTING_rdgwfedauth_gwhost)`r`n"
        $rdpfile_output += "username:s:$($Request.Headers["x-ms-client-principal-name"])`r`n"
        $rdpfile_output += "gatewaycredentialssource:i:5`r`n"
        $rdpfile_output += "gatewayaccesstoken:s:$rdgwtoken`r`n"

        $Response = ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body = $rdpfile_output
        })
    } else {
        Write-Information "Failure: Token not returned"
        $Response = ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::InternalServerError
            Body = "Unknown failure requesting token."
        })
    }
}

if ($Response) {
    Push-OutputBinding -Name Response -Value $Response
} else {
    Write-Information "Failure: response missing, this should not happen"
}

<#
if (-not $Response) {
    $Response = ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body = $content.replace('{0}',$Request.params.hostname).replace('{1}',$env:APPSETTING_rdgwfedauth_gwhost).replace('{2}',$Request.Headers["x-ms-client-principal-name"])
        ContentType = 'application/octet-stream'
    })
}

function Get-RdpFile {
    param (
        [string]$InputFile
    )
    
    $securesettings = @{
        'username:s:'='Username';
        'full address:s:'='Full Address';
        'alternate full address:s:'='Alternate Full Address'
        'gatewaycredentialssource:i:5'='GatewayCredentialsSource'
        'gatewayaccesstoken:s:'='GatewayAccesstoken'
    }
    $othersettings = @{
        'pcb:s:'='PCB';
        'use redirection server name:i:'='Use Redirection Server Name';
        'server port:i:'='Server Port';
        'negotiate security layer:i:'='Negotiate Security Layer';
        'enablecredsspsupport:i:'='EnableCredSspSupport';
        'disableconnectionsharing:i:'='DisableConnectionSharing';
        'autoreconnection enabled:i:'='AutoReconnection Enabled';
        'gatewayhostname:s:'='GatewayHostname';
        'gatewayusagemethod:i:'='GatewayUsageMethod';
        'gatewayprofileusagemethod:i:'='GatewayProfileUsageMethod';
        'support url:s:'='Support URL';
        'promptcredentialonce:i:'='PromptCredentialOnce';
        'require pre-authentication:i:'='Require pre-authentication';
        'pre-authentication server address:s:'='Pre-authentication server address';
        'alternate shell:s:'='Alternate Shell';
        'shell working directory:s:'='Shell Working Directory';
        'remoteapplicationprogram:s:'='RemoteApplicationProgram';
        'remoteapplicationexpandworkingdir:s:'='RemoteApplicationExpandWorkingdir';
        'remoteapplicationmode:i:'='RemoteApplicationMode';
        'remoteapplicationguid:s:'='RemoteApplicationGuid';
        'remoteapplicationname:s:'='RemoteApplicationName';
        'remoteapplicationicon:s:'='RemoteApplicationIcon';
        'remoteapplicationfile:s:'='RemoteApplicationFile';
        'remoteapplicationfileextensions:s:'='RemoteApplicationFileExtensions';
        'remoteapplicationcmdline:s:'='RemoteApplicationCmdLine';
        'remoteapplicationexpandcmdline:s:'='RemoteApplicationExpandCmdLine';
        'prompt for credentials:i:'='Prompt For Credentials';
        'authentication level:i:'='Authentication Level';
        'audiomode:i:'='AudioMode';
        'redirectdrives:i:'='RedirectDrives';
        'redirectprinters:i:'='RedirectPrinters';
        'redirectcomports:i:'='RedirectCOMPorts';
        'redirectsmartcards:i:'='RedirectSmartCards';
        'redirectposdevices:i:'='RedirectPOSDevices';
        'redirectclipboard:i:'='RedirectClipboard';
        'devicestoredirect:s:'='DevicesToRedirect';
        'drivestoredirect:s:'='DrivesToRedirect';
        'loadbalanceinfo:s:'='LoadBalanceInfo';
        'redirectdirectx:i:'='RedirectDirectX';
        'rdgiskdcproxy:i:'='RDGIsKDCProxy';
        'kdcproxyname:s:'='KDCProxyName';
        'eventloguploadaddress:s:'='EventLogUploadAddress'
        }
    $rdpfile_output = ""

    $content.split("[`r`n]") |
    ForEach-Object {
        if (-not $securesettings.ContainsKey($_.split(":",3)[0]) ) {
            $rdpfile_output += "$_`r`n"
        }
    }

    $rdpfile_output += "full address:s:$($Request.params.hostname)`r`n"
    $rdpfile_output += "alternate full address:s:$($Request.params.hostname)`r`n"
    $rdpfile_output += "gatewayhostname:s:$($env:APPSETTING_rdgwfedauth_gwhost)`r`n"
    $rdpfile_output += "username:s:$($Request.Headers["x-ms-client-principal-name"])`r`n"

    $rdpfile_output
}
#>