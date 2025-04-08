using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

<#
# Interact with query parameters or the body of the request.
$name = $Request.Query.Name
if (-not $name) {
    $name = $Request.Body.Name
}

$body = "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."

if ($name) {
    $body = "Hello, $name. This HTTP triggered function executed successfully."
}
#>
Write-Information "New response"

[string[]]$arrbody = @();

Try {
    $arrbody += "hostname = $($Request.params.hostname)"
} Catch {}

Try {
    $arrbody += "rdgwfedauth_gwhost = $($env:APPSETTING_rdgwfedauth_gwhost)"
    $arrbody += "rdgwfedauth_gwport = $($env:APPSETTING_rdgwfedauth_gwport)"
} Catch {}

Try {
    $arrbody += "x-ms-client-principal-name_hash: $(Request.Headers["x-ms-client-principal-name"])"
} Catch {}

Try {
    $arrbody += "x-ms-client-principal-name_prop: $(Request.Headers.x-ms-client-principal-name)"
} Catch {}

Try {
    $arrbody += [string]::join("`r`n",($Request.Headers | Get-Member))
} Catch {}

Try {
    $arrbody += "x-ms-client-principal-name: $(Request.Headers["x-ms-client-principal-name"])"
} Catch {}

<#
Try {
    $arrbody += "Environment:"
    Get-ChildItem "env:" |
    ForEach-Object {
        $arrbody += "$($_.Name) =  $($_.value)"
    }
} Catch {}
#>

<#
Try {
    $arrbody += "Headers:"
    $Request.Headers |
    ForEach-Object {
        $arrbody += "$($_.name) =  $($_.value)"
    }
} Catch {}

Try {
    $arrbody += "Headers:"
    $arrbody += $Request.Headers | ConvertTo-Json -Compress
} Catch {}
#>

$body = [string]::join("`r`n",$arrbody)

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $body
})
