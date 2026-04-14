<#
.SYNOPSIS
    Generates a monthly cost report for resource groups tagged with 'DoNotDestroy'
    and emails it via SendGrid.

.DESCRIPTION
    Queries the Azure Cost Management API for last month's actual cost, grouped
    by resource group and filtered to resource groups that carry the 'DoNotDestroy'
    tag. For each resource group, the 'Owner' and 'Purpose' tags are included in
    the resulting HTML table. The report is emailed via the SendGrid REST API.

    Intended to run as an Azure Automation PowerShell runbook using the Automation
    Account's system-assigned managed identity.

    Required permissions on the managed identity:
      - Cost Management Reader on the subscription
      - Reader on the subscription

    Required Automation Account assets:
      - Encrypted variable 'SendGridApiKey' containing the SendGrid API key

.PARAMETER SubscriptionId
    Target subscription. Defaults to the current context after managed identity login.

.PARAMETER Recipients
    Comma-separated list of recipient email addresses.

.PARAMETER FromAddress
    The 'from' address used when sending via SendGrid. Must be a verified sender
    in the SendGrid account.

.PARAMETER WhatIf
    If set, builds the report and writes the HTML to output but does NOT send email.

.EXAMPLE
    Send-DoNotDestroyCostReport.ps1 -Recipients "nwagner@getnerdio.com"

.NOTES
    Repo: https://github.com/Get-Nerdio/NME-SE
    Path: nerdio-management-aa/Send-DoNotDestroyCostReport.ps1
#>

param(
    [Parameter(Mandatory = $false)]
    [string] $SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string] $Recipients = "nwagner@getnerdio.com",

    [Parameter(Mandatory = $false)]
    [string] $FromAddress = "team@nerdio.net",

    [Parameter(Mandatory = $false)]
    [string] $AutomationResourceGroup = "nerdio-management-rg",

    [Parameter(Mandatory = $false)]
    [string] $AutomationAccountName = "nerdio-management-aa",

    [Parameter(Mandatory = $false)]
    [string] $RunbookName = "Send-DoNotDestroyCostReport",

    [Parameter(Mandatory = $false)]
    [double] $OtherRgThreshold = 10.0,

    [Parameter(Mandatory = $false)]
    [string] $TenantShortName,

    [Parameter(Mandatory = $false)]
    [string] $TenantDisplayName,

    [Parameter(Mandatory = $false)]
    [switch] $WhatIf
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Level, [string]$Message)
    Write-Output "[$Level] $Message"
}

# ---------------------------------------------------------------------------
# 1. Authenticate using the Automation Account's managed identity
# ---------------------------------------------------------------------------
Write-Log INFO "Connecting with managed identity..."
try {
    Disable-AzContextAutosave -Scope Process | Out-Null
    $null = Connect-AzAccount -Identity
} catch {
    Write-Log ERROR "Managed identity login failed: $($_.Exception.Message)"
    throw
}

if (-not $SubscriptionId) {
    $SubscriptionId = (Get-AzContext).Subscription.Id
}
$null = Set-AzContext -SubscriptionId $SubscriptionId
$ctx              = Get-AzContext
$SubscriptionName = $ctx.Subscription.Name
$TenantId         = $ctx.Tenant.Id

# Tenant labels come from parameters (pass them on the schedule). If not provided,
# fall back to the tenant GUID so the report is still usable.
if (-not $TenantShortName)   { $TenantShortName   = $TenantId }
if (-not $TenantDisplayName) { $TenantDisplayName = $TenantId }
Write-Log INFO "Tenant: $TenantDisplayName ($TenantId) / Subscription: $SubscriptionName ($SubscriptionId)"

# ---------------------------------------------------------------------------
# 2. Retrieve the SendGrid API key from the encrypted Automation variable
# ---------------------------------------------------------------------------
Write-Log INFO "Retrieving SendGrid API key..."
$sendGridKey = Get-AutomationVariable -Name "SendGridApiKey"
if (-not $sendGridKey) {
    throw "Automation variable 'SendGridApiKey' is empty or missing."
}

# ---------------------------------------------------------------------------
# 3. Build the Cost Management query for the previous calendar month
# ---------------------------------------------------------------------------
$today      = Get-Date
$firstOfThis = Get-Date -Year $today.Year -Month $today.Month -Day 1 -Hour 0 -Minute 0 -Second 0
$lastMonthStart = $firstOfThis.AddMonths(-1)
$lastMonthEnd   = $firstOfThis.AddSeconds(-1)

$fromStr = $lastMonthStart.ToString("yyyy-MM-ddT00:00:00Z")
$toStr   = $lastMonthEnd.ToString("yyyy-MM-ddT23:59:59Z")

Write-Log INFO "Reporting period: $fromStr -> $toStr"

$queryBody = @{
    type       = "ActualCost"
    timeframe  = "Custom"
    timePeriod = @{ from = $fromStr; to = $toStr }
    dataset    = @{
        granularity = "None"
        aggregation = @{
            totalCost = @{ name = "Cost"; function = "Sum" }
        }
        grouping    = @(
            @{ type = "Dimension"; name = "ResourceGroupName" }
        )
    }
} | ConvertTo-Json -Depth 10

$queryUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.CostManagement/query?api-version=2023-11-01"

Write-Log INFO "Querying Cost Management API..."
$token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
$response = $null
$maxAttempts = 6
for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    try {
        $response = Invoke-RestMethod -Method Post -Uri $queryUri -Headers $headers -Body $queryBody
        break
    } catch {
        $statusCode = $null
        if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
        if ($statusCode -eq 429 -or $statusCode -eq 503) {
            $backoffSeconds = [math]::Min(60, [math]::Pow(2, $attempt) * 5)
            Write-Log WARN "Cost Management returned $statusCode (attempt $attempt/$maxAttempts). Backing off ${backoffSeconds}s..."
            Start-Sleep -Seconds $backoffSeconds
            continue
        }
        Write-Log ERROR "Cost Management query failed: $($_.Exception.Message)"
        throw
    }
}
if (-not $response) { throw "Cost Management query failed after $maxAttempts attempts." }

# ---------------------------------------------------------------------------
# 4. Shape the result: Cost Management returns rows as arrays keyed by column index
# ---------------------------------------------------------------------------
$columns = $response.properties.columns
$rows    = $response.properties.rows

$costIdx = -1; $rgIdx = -1; $currencyIdx = -1
for ($i = 0; $i -lt $columns.Count; $i++) {
    switch ($columns[$i].name) {
        "Cost"              { $costIdx = $i }
        "ResourceGroup"     { $rgIdx = $i }
        "ResourceGroupName" { $rgIdx = $i }
        "Currency"          { $currencyIdx = $i }
    }
}

# Build a case-insensitive cost lookup keyed by RG name, and sum the full subscription total
# (which includes costs attributed to resource groups that no longer exist).
$costByRg = @{}
$currency = "USD"
$subscriptionTotal = 0.0
if ($rows) {
    foreach ($row in $rows) {
        $key = ([string]$row[$rgIdx]).ToLowerInvariant()
        $rowCost = [double]$row[$costIdx]
        $costByRg[$key] = $rowCost
        $subscriptionTotal += $rowCost
        if ($currencyIdx -ge 0) { $currency = $row[$currencyIdx] }
    }
}

# Enumerate all RGs where the DoNotDestroy tag KEY exists (matches policy 'exists' semantics)
Write-Log INFO "Enumerating resource groups with DoNotDestroy tag..."
$allRgs = Get-AzResourceGroup
$dndRgs = @()
foreach ($rg in $allRgs) {
    if ($rg.Tags -and $rg.Tags.ContainsKey("DoNotDestroy")) {
        $dndRgs += $rg
    }
}
Write-Log INFO "Found $($dndRgs.Count) resource group(s) with DoNotDestroy tag."

$report = @()
$total  = 0.0
foreach ($rg in $dndRgs) {
    $key  = $rg.ResourceGroupName.ToLowerInvariant()
    $cost = 0.0
    if ($costByRg.ContainsKey($key)) { $cost = $costByRg[$key] }

    $owner   = ""
    $purpose = ""
    if ($rg.Tags) {
        if ($rg.Tags.ContainsKey("Owner"))   { $owner   = $rg.Tags["Owner"] }
        if ($rg.Tags.ContainsKey("Purpose")) { $purpose = $rg.Tags["Purpose"] }
    }

    $report += [pscustomobject]@{
        ResourceGroup = $rg.ResourceGroupName
        Cost          = [math]::Round($cost, 2)
        Owner         = $owner
        Purpose       = $purpose
    }
    $total += $cost
}

$report = $report | Sort-Object Cost -Descending

# Split: RGs at or above the threshold are shown individually; everything below is
# aggregated into a single "Other RGs" row.
$mainRows    = @()
$otherCost   = 0.0
$otherCount  = 0
foreach ($entry in $report) {
    if ($entry.Cost -ge $OtherRgThreshold) {
        $mainRows += $entry
    } else {
        $otherCost += $entry.Cost
        $otherCount += 1
    }
}

# ---------------------------------------------------------------------------
# 5. Build the HTML email body
# ---------------------------------------------------------------------------
$periodLabel       = $lastMonthStart.ToString("MMMM yyyy")
$totalStr          = "{0:N2}" -f $total
$subscriptionTotalStr = "{0:N2}" -f $subscriptionTotal
$otherCostStr      = "{0:N2}" -f $otherCost

$runbookResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$AutomationResourceGroup/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/$RunbookName"

$rowsHtml = ""
foreach ($entry in $mainRows) {
    $costStr = "{0:N2}" -f $entry.Cost
    $rowsHtml += "<tr><td>$($entry.ResourceGroup)</td><td style='text-align:right'>$costStr $currency</td><td>$($entry.Owner)</td><td>$($entry.Purpose)</td></tr>`n"
}
if ($otherCount -gt 0) {
    $rowsHtml += "<tr><td><i>Other RGs ($otherCount under $([string]::Format('{0:N0}', $OtherRgThreshold)) $currency)</i></td><td style='text-align:right'>$otherCostStr $currency</td><td></td><td></td></tr>`n"
}

$htmlBody = @"
<html>
<body style="font-family: Segoe UI, Arial, sans-serif;">
<h2>$TenantShortName Cost Report &mdash; $periodLabel</h2>
<p>
  <b>Tenant:</b> $TenantDisplayName ($TenantId)<br/>
  <b>Subscription:</b> $SubscriptionName ($SubscriptionId)
</p>
<h3>DoNotDestroy Resource Groups</h3>
<table cellpadding="6" cellspacing="0" border="1" style="border-collapse: collapse; border-color: #ccc;">
  <thead style="background:#f0f0f0;">
    <tr><th>Resource Group</th><th>Cost</th><th>Owner</th><th>Purpose</th></tr>
  </thead>
  <tbody>
    $rowsHtml
  </tbody>
  <tfoot>
    <tr style="font-weight:bold; background:#fafafa;">
      <td>DoNotDestroy Total</td><td style='text-align:right'>$totalStr $currency</td><td></td><td></td>
    </tr>
    <tr style="font-weight:bold; background:#eef3fb;">
      <td>Subscription Total (all resources, incl. deleted)</td><td style='text-align:right'>$subscriptionTotalStr $currency</td><td></td><td></td>
    </tr>
  </tfoot>
</table>
<p style="color:#888; font-size: 11px;">
  Generated by runbook: <code>$runbookResourceId</code>
</p>
</body>
</html>
"@

if ($WhatIf) {
    Write-Log INFO "WhatIf enabled - not sending email. HTML body follows:"
    Write-Output $htmlBody
    return
}

# ---------------------------------------------------------------------------
# 6. Send via SendGrid
# ---------------------------------------------------------------------------
Write-Log INFO "Sending email via SendGrid to: $Recipients"

$toList = @()
foreach ($r in ($Recipients -split ",")) {
    $trimmed = $r.Trim()
    if ($trimmed) { $toList += @{ email = $trimmed } }
}

$sendGridBody = @{
    personalizations = @(
        @{
            to      = $toList
            subject = "$TenantShortName Cost Report - $periodLabel"
        }
    )
    from    = @{ email = $FromAddress; name = "Nerdio SE Automation" }
    content = @(
        @{ type = "text/html"; value = $htmlBody }
    )
} | ConvertTo-Json -Depth 10

try {
    $sgHeaders = @{
        Authorization = "Bearer $sendGridKey"
        "Content-Type" = "application/json"
    }
    Invoke-RestMethod -Method Post -Uri "https://api.sendgrid.com/v3/mail/send" -Headers $sgHeaders -Body $sendGridBody | Out-Null
    Write-Log SUCCESS "Report emailed for period $periodLabel (total $totalStr $currency across $($report.Count) RGs)."
} catch {
    Write-Log ERROR "SendGrid send failed: $($_.Exception.Message)"
    throw
}
