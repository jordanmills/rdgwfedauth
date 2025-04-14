# Azure Functions profile.ps1
#
# This profile.ps1 will get executed every "cold start" of your Function App.
# "cold start" occurs when:
#
# * A Function App starts up for the very first time
# * A Function App starts up after being de-allocated due to inactivity
#
# You can define helper functions, run commands, or specify environment variables
# NOTE: any variables defined that are not environment variables will get reset after the first execution

# Authenticate with Azure PowerShell using MSI.
# Remove this if you are not planning on using MSI or Azure PowerShell.
if ($env:MSI_SECRET) {
    Disable-AzContextAutosave -Scope Process | Out-Null
    #Connect-AzAccount -Identity
}

# Uncomment the next line to enable legacy AzureRm alias in Azure PowerShell.
# Enable-AzureRmAlias

# You can also define functions or aliases that can be referenced in any of your PowerShell functions.

$AZURE_MANAGEMENT_API = "https://management.azure.com/";
$MACHINE_TOKEN_PATTERN = "Host={0}&Port={1}&ExpiresOn={2}";
$AUTH_TOKEN_PATTERN = "{0}&Signature=1|SHA256|{1}|{2}";
$rdgw_loginEndpoint = $env:rdgw_loginEndpoint # "https://login.microsoftonline.com/"; # $env:rdgw_loginEndpoint, should be pushed in template from environment().authentication.loginEndpoint
$rdgw_keyvaultDns = $env:rdgw_keyvaultDns # ".vault.azure.net"; # $env:rdgw_keyvaultDns, should be pushed in template from environment().suffixes.keyvaultDns
$rdgw_keyvaultName = $env:rdgw_keyvaultName # "kvusdrdgwfedauthtst"; # $env:rdgw_keyvaultDns, should be pushed in template from resource
$rdgw_keyvaultkey = $env:rdgw_keyvaultkey # "rdgwfedauth"; # $env:rdgw_keyvaultDns, should be pushed in template from key resource if possible

$global:tokenresponse = @{} # hashtable to keep token responses for reuse

#$AzureServiceTokenProvider AzureManagementApiTokenProvider = new AzureServiceTokenProvider();
[DateTime]$PosixBaseTime = [DateTime]::new(1970, 1, 1, 0, 0, 0, 0)

function Get-RdGwToken
{
    [CmdletBinding(DefaultParameterSetName='certificate')]
    [Alias()]
    [OutputType([String])]
    Param
    (
        [Parameter(Mandatory, Position=0, ParameterSetName='certificate')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory, Position=0, ParameterSetName='thumbprint')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]$Thumbprint,

        [Parameter(Mandatory, Position=1, ParameterSetName='certificate')]
        [Parameter(Mandatory, Position=1, ParameterSetName='thumbprint')]
        [string]
        $machinehost,

        # Param3 help description
        [Parameter(Position=2,ParameterSetName='certificate')]
        [Parameter(Position=2,ParameterSetName='thumbprint')]
        [AllowNull()]
        [ValidateRange(0,65535)]
        [int]
        $port=3389
    )

    Begin
    {
    }
    Process
    {
        #[System.Security.Cryptography.X509Certificates.X509Certificate2]
        $machineToken = [string]::Format([CultureInfo]::InvariantCulture, $MACHINE_TOKEN_PATTERN, $machinehost, $port, (Get-PosixLifetime));
        $machineTokenBuffer = [System.Text.Encoding]::ASCII.GetBytes($machineToken);
        switch ($PSCmdlet.ParameterSetName) {
            "thumbprint" {
                [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate = Get-Item "Cert:\currentUser\my\$thumbprint"
                $RSACng = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
                $machineTokenSignature = $RSACng.SignData(
                    $machineTokenBuffer, 
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256, 
                    [System.Security.Cryptography.RSASignaturePadding]::Pss
                )

            }
            "certificate" {
                exit "Not implemented"
            }
            default {
                exit "Unspecified error"
            }
        }
        $machineTokenString = [string]::Format(
            [CultureInfo]::InvariantCulture, 
            $AUTH_TOKEN_PATTERN, 
            $machineToken, 
            $thishumbprint, 
            [uri]::EscapeDataString([System.Convert]::ToBase64String($machineTokenSignature))
        );
        # rest from here https://blog.ahasayen.com/how-to-use-azure-key-vault-with-powershell-to-encrypt-data
        # need $keyid, from config?
        # need $accesstoken

        $resourceURI = "https://<Entra-resource-URI-for-resource-to-obtain-token>"
        $tokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=$resourceURI&api-version=2019-08-01"
        $tokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER"="$env:IDENTITY_HEADER"} -Uri $tokenAuthURI
        $accessToken = $tokenResponse.access_token

        $queryUrl = $rdgw_keyvaultkey + '/encrypt?api-version=2016-10-01'
        $headers = @{ 'Authorization' = "Bearer $accessToken"; "Content-Type" = "application/json" }
        $body = ConvertTo-Json -InputObject @{ "alg" = "RSA-OAEP"; "value" = $base64Array }
        Invoke-RestMethod -Method Post -UseBasicParsing -Uri $queryUrl -Headers $headers -Body $body |
        Select-Object -ExpandProperty Value
    }
    End
    {
    }
}

function Get-AzureResourceToken {
    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        # Param1 help description
        [Parameter(Position=0,
                   ParameterSetName='resourceURI')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [uri]$resourceURI
    )
    if ((Get-Date $Request.Headers["x-ms-token-aad-expires-on"]) -gt (Get-Date)) {
        if ($global:tokenResponse[$resourceURI]) {
            $global:tokenResponse[$resourceURI]
        } else {
            #$global:tokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER"="$env:IDENTITY_HEADER"} -Uri $env:IDENTITY_ENDPOINT + "?resource=$resourceURI&api-version=2019-08-01"
            $thistoken = Invoke-RestMethod -Method Get -Headers @{"Authorization"="Bearer " + $Request.Headers["x-ms-token-aad-id-token"]} -Uri $env:IDENTITY_ENDPOINT + "?resource=$resourceURI&api-version=2019-08-01"
            $global:tokenResponse.add($resourceURI,$thistoken)
            $thistoken
        }
    } else { Write-Error "Token expired" }
}

function Get-PosixLifetime
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([Int64])]
    Param
    (
        # Param1 help description
        [Parameter(Position=0,
                   ParameterSetName='seconds')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [int]$Seconds=60
    )

    Begin
    {
        [DateTime]$PosixBaseTime = [DateTime]::new(1970, 1, 1, 0, 0, 0, 0)
        [int]$tokenLifetime = if ([int]$env:TokenLifetimeSeconds) { [int]$env:TokenLifetimeSeconds } else { $Seconds }

    }
    Process
    {
            $endOfLife = (Get-Date).ToUniversalTime().AddSeconds($tokenLifetime)

            #return lifetime in posix format
            [int64]$endOfLife.Subtract($PosixBaseTime).TotalSeconds
    }
    End
    {
    }
}

