<#
.SYNOPSIS
    Outputs a CSV file containing the monthly historical number of past due vulnerabilites
    that are high risk and the total number of vulnerabilities at high risk for all risk meters.
.DESCRIPTION
    Obtains a list of risk meters and iterates through all the risk meters to collect
    the historical number of vulnerabilities at high risk that are past due and the total number
    of high risk vulnerabilities by month.  This information is exported to a CSV file.

    The CVS file is removed explitly before each run even though the Export-CSV documentation
    states that it does.
.EXAMPLE
    ShowHistoricalVulnCounts.ps1 $startDate $csvFileName
    ShowHistoricalVulnCounts.ps1 2021-10-01 /users/john/tmp/vuln_count.csv
.INPUTS
    The start date.
    The CSV file file.
.OUTPUTS
    The CSV file at the file path specified.
#>

# Command line parameters.
[cmdletbinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$false)]
    [String]$startDate,

    [Parameter(Mandatory=$true, ValueFromPipeline=$false)]
    [String]$csvFileName
)

function New-Blank-Row
{
    $blankRow = [ordered] @{} 

    $blankRow["Risk Name"] = ""
    $blankRow["ID"] = ""
    $blankRow["Score"] = ""
    $blankRow["Asset Count"] = ""
    $blankRow["Updated At"] = ""
    $blankRow["Vuln Title"] = ""

    return $blankRow
}

# Create a CSV row with all the desired risk meter information.
function New-Risk-Meter-Row
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Object]$AssetGroup,

        [Parameter(Mandatory)]
        [Object]$dateKeys
    )

    $riskMeterRow = New-Blank-Row

    #Write-Host "$($AssetGroup.name)  $($AssetGroup.id)  $($AssetGroup.asset_count)  $($AssetGroup.risk_meter_score)"
    $riskMeterRow["Risk Name"] = $AssetGroup.name
    $riskMeterRow["ID"] = $AssetGroup.id
    $riskMeterRow["Score"] = $AssetGroup.risk_meter_score
    $riskMeterRow["Asset Count"] = $AssetGroup.asset_count
    $riskMeterRow["Updated At"] = $AssetGroup.updated_at

    # Initialize the dates.
    ForEach ($dateKey in $dateKeys) {
        $riskMeterRow[$dateKey] = $dateKey
    }

    Return $riskMeterRow
}

# Create a CSV row of vulnerability count data.
function New-Data-Row
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Object]$title,

        [Parameter(Mandatory)]
        [Object]$dateHash
    )

    $dataRow = New-Blank-Row
    $dataRow["Vuln Title"] = $title

    # Add the values for each date.
    ForEach ($dateKey in $dateHash.Keys) {
        $dataRow[$dateKey] = $dateHash[$dateKey]
    }

    Return $dataRow
}

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
    $ListAssetGroupsApiUrl = "$($BaseUrl)asset_groups"
    Try {
        $Resp = Invoke-RestMethod -Headers $Headers -Method Get -Uri $ListAssetGroupsApiUrl
    }
    Catch {
        $ErrorMessage = $_.Exception.Message
        $Line = $_.InvocationInfo.ScriptLineNumber
        $RequestUrl = $_.Exception.Response.RequestMessage.RequestUri
        Write-Host "List Asset Group API failed." -ForegroundColor Red
        Write-Host "Line $($Line): $($ErrorMessage)" -ForegroundColor Red
        Write-Host "URL: $($RequestUrl)" -ForegroundColor Red
        Exit
    }

    Return $Resp.asset_groups
}

# Invoke various risk meter reports as specified by $Report.
function Invoke-Risk-Meter-Report
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]$BaseUrl,

        [Parameter(Mandatory)]
        [Object]$Headers,

        [Parameter(Mandatory)]
        [Int64]$Id,

        [Parameter(Mandatory)]
        [String]$Report,

        [Parameter(Mandatory)]
        [String]$startDate
    )
    
    $Resp = {}
    $reportUrl = "$($BaseUrl)asset_groups/$($Id)/report_query/$($Report)?start_date=$($startDate)"
    Try {
        $Resp = Invoke-RestMethod -Headers $Headers -Method Get -Uri $reportUrl
    }
    Catch {
        $ErrorMessage = $_.Exception.Message
        $Line = $_.InvocationInfo.ScriptLineNumber
        $RequestUrl = $_.Exception.Response.RequestMessage.RequestUri
        Write-Host "Report API failed" -ForegroundColor Red
        Write-Host "Line $($Line): $($ErrorMessage)" -ForegroundColor Red
        Write-Host "URL: $($RequestUrl)" -ForegroundColor Red
        Exit
    }

    Return $Resp
}

function Invoke-Historical-Vuln-Counts
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]$BaseUrl,

        [Parameter(Mandatory)]
        [Object]$Headers,

        [Parameter(Mandatory)]
        [Int64]$Id,

        [Parameter(Mandatory)]
        [String]$startDate
    )
    
    $Resp = Invoke-Risk-Meter-Report -BaseUrl $BaseUrl -Headers $Headers -Id $Id `
                                     -Report "historical_open_vulnerability_count_by_risk_level" -startDate $startDate

    Return $Resp
}

function Invoke-Historical-Past-Due-Vuln-Counts
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]$BaseUrl,

        [Parameter(Mandatory)]
        [Object]$Headers,

        [Parameter(Mandatory)]
        [Int64]$Id,

        [Parameter(Mandatory)]
        [String]$startDate
    )
    
    $Resp = Invoke-Risk-Meter-Report -BaseUrl $BaseUrl -Headers $Headers -Id $Id `
                                     -Report "historical_past_due_vulnerabilities_by_risk_level" -startDate $startDate

    Return $Resp
}
# main
Write-Host "Historical Risk Meter Vulnerability Counts"
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

# Obtain a list of risk meters.
$AssetGroups = Invoke-List-Risk-Meters -BaseUrl $BaseUrl -Headers $Headers

#$AssetGroups | Format-Table -Property name, id, asset_count, @{Label="Score"; Expression={$_.risk_meter_score}}, updated_at

# Remove the CSV file if it exists, since Export-CSV doesn't do this as documented.
if (Test-Path $csvFileName) {
    Remove-Item -Path $csvFileName
}

# For each asset group, obtain the total number of vulnerabilities (vulns) and the number of vulns past the due date.
ForEach ($AssetGroup in $AssetGroups) {
    # Invoke APIs to obtain the historical vuln counts.
    $VulnCountsResp = Invoke-Historical-Vuln-Counts -BaseUrl $BaseUrl -Headers $Headers -Id $AssetGroup.id -startDate $startDate
    $PastDueVulnCountsResp = Invoke-Historical-Past-Due-Vuln-Counts -BaseUrl $BaseUrl -Headers $Headers `
                                                                    -Id $AssetGroup.id -startDate $startDate

    #Write-Host "$($AssetGroup.name)  $($AssetGroup.id)  $($AssetGroup.asset_count)  $($AssetGroup.risk_meter_score)"
    # Verify that the Asset Group IDs match.
    If ($VulnCountsResp.id -ne $PastDueVulnCountsResp.id) {
        Write-How "IDs don't match" -ForegroundColor Red
        Exit
    }

    # Acquire the vuln counts by dates.
    $HistoricalVulnCounts = $VulnCountsResp.historical_vulnerability_count_by_risk
    $HistoricalPastDueVulnCounts = $PastDueVulnCountsResp.historical_past_due_vulnerabilities_by_risk_level

    # Keep only the first day of the months for total vuln counts.
    $keyHash = [ordered] @{}
    $HistoricalVulnCounts.PsObject.Properties | ForEach-Object {
        if ($_.Name -match '^\d\d\d\d-\d\d-01$') {
            $keyHash[$_.Name] = $_.Value.high
        }
    }
    
    # Keep only the first day of the months for past due vuln counts.
    $pastDueKeyHash = [ordered] @{}
    $HistoricalPastDueVulnCounts.PsObject.Properties | ForEach-Object {
        if ($_.Name -match '\d\d\d\d-\d\d-01') {
            $pastDueKeyHash[$_.Name] = $_.Value.high
        }
    }
    
    Write-Host "Processing Historical Vuln Counts for " $AssetGroup.name

    $riskMeterRow = New-Risk-Meter-Row -AssetGroup $AssetGroup -dateKeys $keyHash.Keys
    $riskMeterRow | Export-Csv -Path $csvFileName -Append 

    $pastDueVulnCountDataRow = New-Data-Row -Title "Past Due Vuln Count" -dateHash $pastDueKeyHash
    $pastDueVulnCountDataRow | Export-Csv -Path $csvFileName -Append 

    $vulnCountDataRow = New-Data-Row -Title "Total Vuln Count" -dateHash $keyHash
    $vulnCountDataRow | Export-Csv -Path $csvFileName -Append 
}

Write-Host ""
