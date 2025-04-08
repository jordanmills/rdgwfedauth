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
[string[]]$arrbody = @();

Try {
    $arrbody += "hostname = $($Request.params.hostname)"
} Catch {}

Try {
    $body += "Environment:"
    Get-ChildItem "env:" |
    ForEach-Object {
        $body += "$($_.Name) =  $($_.value)"
    }
} Catch {}

<#
Try {
    $body += "Headers:"
    $Request.Headers.keys |
    ForEach-Object {
        $body += "$_ =  $($Request.Headers.GetItem($_))"
    }
} Catch {}
#>

$body = [string]::join("`r`n",$arrbody)

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $body
})
