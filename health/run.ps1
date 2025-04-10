using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

$Response = ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
})

Push-OutputBinding -Name Response -Value $Response
