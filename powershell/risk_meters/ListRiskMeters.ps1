
function Invoke-List-Risk-Meters
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]$BaseUrl,

        [Parameter(Mandatory)]
        [Object]$Headers
    )
    
    $Resp = {}
    $listAssetGroupsApi = "$($BaseUrl)asset_groups"
    Try {
        $Resp = Invoke-RestMethod -Headers $Headers -Method Get -Uri $listAssetGroupsApi
    }
    Catch {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.Source
        $Line = $_.InvocationInfo.ScriptLineNumber
        Write-Error "Line $Line -`r`n$FailedItem with error: $ErrorMessage" -ForegroundColor Red
        Write-Host $_.Exception.Response -ForegroundColor Red
        Throw "List Asset Group API failed."
    }

    $Resp.asset_groups
}


# main
Write-Host "List Risk Meters"
Write-Host ""

# Obtain the Kenna Security API key from an environment variable.
$KennaApiKey = ""
Try {
    $KennaApiKey = (Get-ChildItem -Path Env:\KENNA_API_KEY -ErrorAction Stop).Value
}
Catch {
    Write-Host "API key is non-existent"
    Exit
}

# HTTP headers.
$Headers = @{
    "Accept" = "application/json"
    "Content-Type" = "application/json; charset=utf-8"
    "X-Risk-Token" = $KennaApiKey
}

# You might have to change this depending on your deployment.
$BaseUrl = "https://api.kennasecurity.com/"

$AssetGroups = Invoke-List-Risk-Meters -BaseUrl $BaseUrl -Headers $Headers

$AssetGroups | Format-Table -Property name, id, asset_count, @{Label="Score"; Expression={$_.risk_meter_score}}, updated_at
