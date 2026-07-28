<#
    .SYNOPSIS
        Nerdio Manager for Enterprise (NME) deployment readiness pre-flight.

    .DESCRIPTION
        Validates that a target Azure environment can host a Nerdio Manager for Enterprise
        deployment. It runs, in parallel where possible:
          * Permission checks   - Entra directory roles (WITHOUT the Microsoft.Graph module) and
                                   Azure Owner on the subscription.
          * Resource providers  - registration state of the providers NME requires.
          * Deployability tests  - deploys throwaway copies of the exact resources (matching SKUs)
                                   NME's installer creates, to surface Azure Policy blocks. Reports
                                   the blocking policy by name where possible. This is how blocking
                                   policies are detected - there is no separate read-only policy scan.
          * Private endpoint/DNS - (optional) deploys a private endpoint into an existing VNet and
                                   reports which required private DNS zones are missing / not linked.
          * Outbound connectivity- (optional, tested together with private endpoints - NME requires
                                   both a private endpoint subnet and an App Service integration
                                   subnet) tests App Service VNet-integration outbound access to the
                                   endpoints NME requires, from inside an App Service worker. If the
                                   named subnet isn't delegated to Microsoft.Web/serverFarms, this is
                                   reported and the VNet integration attempt is skipped.

        Every check captures errors instead of failing, cleans up the resources it creates, and
        emits a copy/paste-ready report to send to your Nerdio SE.

        Authenticate first:  Connect-AzAccount -UseDeviceAuthentication

    .PARAMETER SubscriptionId
        Target subscription id (GUID). Prompted for if omitted.

    .PARAMETER ResourceGroupName
        Existing resource group to test in. If omitted, a temporary rg-nme-preflight-<rand> is
        created and removed at the end.

    .PARAMETER Location
        Azure region for created resources / the temporary resource group. Prompted for if omitted.

    .PARAMETER OutFile
        Path for the JSON results file. Defaults to NmeReadinessOutput_<timestamp>.json in the working
        directory, where <timestamp> identifies the run and orders its date component (y/M/d) to match
        the current culture's short date pattern, e.g. yyyy-MM-dd_HHmm vs dd-MM-yyyy_HHmm.

    .EXAMPLE
        Run in Azure Cloud Shell with a single command:

        $s=New-Object Net.WebClient; & ([scriptblock]::Create($s.DownloadString('https://raw.githubusercontent.com/Get-Nerdio/NME-SE/main/preflight/Test-NmeDeploymentReadiness.ps1')))

    .EXAMPLE
        .\Test-NmeDeploymentReadiness.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000"

    .NOTES
        Author: Nick Wagner
        Requires PowerShell 7 and the Az modules (pre-installed in Azure Cloud Shell).
        Does not require the Microsoft.Graph module.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [System.String] $SubscriptionId,

    [Parameter(Mandatory = $false)]
    [System.String] $ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [System.String] $Location,

    [Parameter(Mandatory = $false)]
    [System.String] $OutFile,

    [Parameter(Mandatory = $false)]
    [switch] $PrivateEndpointOnly
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"

if (-not $OutFile) {
    # Order the y/M/d tokens the same way the current culture's short date pattern does (e.g.
    # dd/MM/yyyy vs MM/dd/yyyy), so the default filename's date order matches what the user expects,
    # but always zero-padded and hyphen-joined so it stays a valid, sortable filename on any OS.
    $dateTokens = [System.Collections.Generic.List[string]]::new()
    foreach ($ch in (Get-Culture).DateTimeFormat.ShortDatePattern.ToCharArray()) {
        $token = switch ($ch) { 'y' { 'yyyy' }; 'M' { 'MM' }; 'd' { 'dd' }; default { $null } }
        if ($token -and -not $dateTokens.Contains($token)) { $dateTokens.Add($token) }
    }
    if ($dateTokens.Count -ne 3) { $dateTokens = @('yyyy', 'MM', 'dd') }
    $timestampFormat = ($dateTokens -join '-') + '_HHmm'
    $OutFile = Join-Path -Path $PWD -ChildPath "NmeReadinessOutput_$(Get-Date -Format $timestampFormat).json"
}

#region Shared state and helpers ------------------------------------------------------------------
# Single flat result list. Every check appends one object with this exact shape.
$Results = [System.Collections.Generic.List[object]]::new()
# Resources we create, recorded as we go, removed in reverse order during cleanup.
$Tracker = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("Permissions", "ResourceProviders", "Deployability", "PrivateDns", "PrivateEndpoint", "Connectivity", "Info")][string] $Category,
        [Parameter(Mandatory = $true)][string] $Check,
        [Parameter(Mandatory = $true)][ValidateSet("Pass", "Fail", "Warn", "Info")][string] $Result,
        [string] $Detail = "",
        [string] $PolicyName = $null,
        [string] $Message = $null,
        [string] $RawMessage = $null
    )
    $obj = [pscustomobject]@{
        Category   = $Category
        Check      = $Check
        Result     = $Result
        Detail     = $Detail
        PolicyName = $PolicyName
        Message    = $Message
        RawMessage = $RawMessage
    }
    $Results.Add($obj) | Out-Null

    switch ($Result) {
        "Pass" { Write-Host -ForegroundColor "Green"  "[$([char]0x2713)] $Check$(if($Detail){" - $Detail"})" }
        "Fail" { Write-Host -ForegroundColor "Red"    "[x] $Check$(if($Detail){" - $Detail"})" }
        "Warn" { Write-Host -ForegroundColor "Yellow" "[!] $Check$(if($Detail){" - $Detail"})" }
        "Info" { Write-Host -ForegroundColor "Cyan"   "[i] $Check$(if($Detail){" - $Detail"})" }
    }
}

function Add-TrackedResource {
    param(
        [Parameter(Mandatory = $true)][string] $Type,
        [Parameter(Mandatory = $true)][string] $ResourceGroupName,
        [Parameter(Mandatory = $true)][string] $Name,
        [string] $Id = $null,
        [string] $Note = $null
    )
    $Tracker.Add([pscustomobject]@{
            Type              = $Type
            ResourceGroupName = $ResourceGroupName
            Name              = $Name
            Id                = $Id
            Note              = $Note
        }) | Out-Null
}

#region Report rendering (shared palette -> console ANSI + HTML) -----------------------------------
# One palette drives both the on-screen ANSI table and the HTML file so the two look the same.
# Hex values are used verbatim in the HTML; the same RGB triplets colour the ANSI status pills.
$script:StatusStyle = @{
    Pass = @{ Label = "PASS"; Symbol = [char]0x2713; Rgb = @(45, 164, 78);  Hex = "#2da44e" }
    Fail = @{ Label = "FAIL"; Symbol = "x";           Rgb = @(229, 72, 77); Hex = "#e5484d" }
    Warn = @{ Label = "WARN"; Symbol = "!";           Rgb = @(210, 153, 34); Hex = "#d29922" }
    Info = @{ Label = "INFO"; Symbol = "i";           Rgb = @(59, 130, 246); Hex = "#3b82f6" }
}

# Whether we can emit ANSI colour. PowerShell 7 in Cloud Shell supports it; honour NO_COLOR and a
# non-VT host so redirected/piped output stays clean plain text.
$script:UseAnsi = $false
try {
    $script:UseAnsi = [string]::IsNullOrEmpty($env:NO_COLOR) -and
        ($Host.UI.SupportsVirtualTerminal -or $env:TERM -or $env:ACC_CLOUD)
}
catch { $script:UseAnsi = $false }

# Are we running inside Azure Cloud Shell? Used to auto-trigger a browser download of the report.
$script:IsCloudShell = -not [string]::IsNullOrEmpty($env:ACC_CLOUD) -or
    ($env:AZUREPS_HOST_ENVIRONMENT -like "cloud-shell*")

function Get-ReadinessVerdict {
    # Overall verdict from the result set: any Fail -> FAIL; else any Warn -> WARN; else PASS.
    param([System.Collections.IEnumerable] $Results)
    $hasFail = $false; $hasWarn = $false
    foreach ($r in $Results) {
        if ($r.Result -eq "Fail") { $hasFail = $true }
        elseif ($r.Result -eq "Warn") { $hasWarn = $true }
    }
    if ($hasFail) { return "Fail" }
    elseif ($hasWarn) { return "Warn" }
    else { return "Pass" }
}

function ConvertTo-HtmlText {
    param([string] $Text)
    if ($null -eq $Text) { return "" }
    return ($Text -replace "&", "&amp;" -replace "<", "&lt;" -replace ">", "&gt;" -replace '"', "&quot;")
}

function New-ReadinessHtmlReport {
    # Builds a single self-contained HTML document (inline CSS, no external assets) from the same
    # data the JSON and console report use, so it renders identically offline and can be emailed.
    param(
        [System.Collections.IEnumerable] $Results,
        [System.Collections.Specialized.OrderedDictionary] $ConfigSummary,
        [System.Collections.Specialized.OrderedDictionary] $CustomResourceNames,
        [object] $Meta,
        [System.Collections.IEnumerable] $CreatedResources,
        [string] $RawJson
    )
    $verdict = Get-ReadinessVerdict -Results $Results
    $vStyle = $script:StatusStyle[$verdict]
    $counts = @{ Pass = 0; Fail = 0; Warn = 0; Info = 0 }
    foreach ($r in $Results) { if ($counts.ContainsKey($r.Result)) { $counts[$r.Result]++ } }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine('<title>NME Deployment Readiness Report</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine(@"
:root{color-scheme:light dark;--bg:#ffffff;--fg:#1f2328;--muted:#656d76;--card:#f6f8fa;--border:#d0d7de;
--pass:$($script:StatusStyle.Pass.Hex);--fail:$($script:StatusStyle.Fail.Hex);--warn:$($script:StatusStyle.Warn.Hex);--info:$($script:StatusStyle.Info.Hex);}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--card:#161b22;--border:#30363d;}}
*{box-sizing:border-box;}
body{margin:0;padding:24px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
background:var(--bg);color:var(--fg);line-height:1.45;}
.wrap{max-width:1100px;margin:0 auto;}
h1{font-size:22px;margin:0 0 4px;}
.sub{color:var(--muted);font-size:13px;margin-bottom:20px;}
.banner{border-radius:10px;padding:16px 20px;margin:18px 0;color:#fff;font-size:18px;font-weight:700;
display:flex;align-items:center;gap:12px;}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0 22px;}
.chip{border:1px solid var(--border);border-radius:20px;padding:4px 12px;font-size:13px;font-weight:600;background:var(--card);}
.chip .n{font-weight:700;}
.meta,.cfg{width:100%;border-collapse:collapse;margin:8px 0 22px;font-size:13px;}
.meta td,.cfg td{padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;}
.meta td:first-child,.cfg td:first-child{color:var(--muted);width:34%;white-space:nowrap;}
h2{font-size:15px;margin:26px 0 8px;padding-bottom:6px;border-bottom:1px solid var(--border);}
table.res{width:100%;border-collapse:collapse;font-size:13px;}
table.res th{text-align:left;color:var(--muted);font-weight:600;padding:6px 10px;border-bottom:2px solid var(--border);}
table.res td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top;}
table.res tr:hover td{background:var(--card);}
.pill{display:inline-block;min-width:52px;text-align:center;padding:2px 8px;border-radius:12px;color:#fff;
font-size:11px;font-weight:700;letter-spacing:.03em;}
.pill.Pass{background:var(--pass);}.pill.Fail{background:var(--fail);}.pill.Warn{background:var(--warn);}.pill.Info{background:var(--info);}
.cat{color:var(--muted);white-space:nowrap;}
.detail{color:var(--fg);}
details{margin-top:26px;}summary{cursor:pointer;color:var(--muted);font-size:13px;}
pre{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px;overflow:auto;font-size:12px;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;}
"@)
    [void]$sb.AppendLine('</style></head><body><div class="wrap">')
    [void]$sb.AppendLine('<h1>Nerdio Manager for Enterprise &ndash; Deployment Readiness Report</h1>')
    [void]$sb.AppendLine("<div class=`"sub`">Generated $(ConvertTo-HtmlText $Meta.TimestampUtc)</div>")

    $vColor = @{ Pass = "var(--pass)"; Fail = "var(--fail)"; Warn = "var(--warn)" }[$verdict]
    $vText = @{ Pass = "READY &ndash; all checks passed"; Fail = "NOT READY &ndash; one or more checks failed"; Warn = "READY WITH WARNINGS &ndash; review the items below" }[$verdict]
    [void]$sb.AppendLine("<div class=`"banner`" style=`"background:$vColor`"><span>$($vStyle.Symbol)</span><span>$vText</span></div>")

    [void]$sb.AppendLine('<div class="chips">')
    [void]$sb.AppendLine("<span class=`"chip`" style=`"border-color:var(--pass)`">Pass <span class=`"n`">$($counts.Pass)</span></span>")
    [void]$sb.AppendLine("<span class=`"chip`" style=`"border-color:var(--warn)`">Warn <span class=`"n`">$($counts.Warn)</span></span>")
    [void]$sb.AppendLine("<span class=`"chip`" style=`"border-color:var(--fail)`">Fail <span class=`"n`">$($counts.Fail)</span></span>")
    [void]$sb.AppendLine("<span class=`"chip`" style=`"border-color:var(--info)`">Info <span class=`"n`">$($counts.Info)</span></span>")
    [void]$sb.AppendLine('</div>')

    # Run metadata.
    [void]$sb.AppendLine('<table class="meta">')
    foreach ($p in $Meta.PSObject.Properties) {
        [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlText $p.Name)</td><td>$(ConvertTo-HtmlText ([string]$p.Value))</td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    # Configuration used (reference for install).
    if ($ConfigSummary -and $ConfigSummary.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Configuration used (reference for install)</h2><table class="cfg">')
        foreach ($k in $ConfigSummary.Keys) {
            $v = ([string]$ConfigSummary[$k]) -replace "[`r`n]+", " "
            [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlText $k)</td><td>$(ConvertTo-HtmlText $v)</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    }
    if ($CustomResourceNames -and $CustomResourceNames.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Custom resource names</h2><table class="cfg">')
        foreach ($k in $CustomResourceNames.Keys) {
            [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlText $k)</td><td>$(ConvertTo-HtmlText ([string]$CustomResourceNames[$k]))</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    }

    # Check results.
    [void]$sb.AppendLine('<h2>Check results</h2>')
    [void]$sb.AppendLine('<table class="res"><thead><tr><th>Status</th><th>Category</th><th>Check</th><th>Detail</th></tr></thead><tbody>')
    foreach ($r in $Results) {
        $cls = if ($script:StatusStyle.ContainsKey($r.Result)) { $r.Result } else { "Info" }
        $lbl = if ($script:StatusStyle.ContainsKey($r.Result)) { $script:StatusStyle[$r.Result].Label } else { $r.Result.ToUpper() }
        $detailHtml = ConvertTo-HtmlText (($r.Detail -replace "[`r`n]+", " ").Trim())
        [void]$sb.AppendLine("<tr><td><span class=`"pill $cls`">$lbl</span></td><td class=`"cat`">$(ConvertTo-HtmlText $r.Category)</td><td>$(ConvertTo-HtmlText $r.Check)</td><td class=`"detail`">$detailHtml</td></tr>")
    }
    [void]$sb.AppendLine('</tbody></table>')

    if ($RawJson) {
        [void]$sb.AppendLine('<details><summary>Raw JSON (machine-readable detail)</summary><pre>')
        [void]$sb.AppendLine((ConvertTo-HtmlText $RawJson))
        [void]$sb.AppendLine('</pre></details>')
    }
    [void]$sb.AppendLine('</div></body></html>')
    return $sb.ToString()
}

function Write-StatusPill {
    # Emits a bracketed status token to the console ([PASS]/[FAIL]/...), with the text itself
    # coloured (ANSI truecolor foreground) rather than a filled background. Falls back to a plain
    # [TOKEN] where ANSI is unavailable.
    param([string] $Result)
    $style = if ($script:StatusStyle.ContainsKey($Result)) { $script:StatusStyle[$Result] } else { $script:StatusStyle.Info }
    $label = "[{0}]" -f $style.Label
    if ($script:UseAnsi) {
        $e = [char]27
        $rgb = $style.Rgb
        Write-Host -NoNewline ("{0}[38;2;{1};{2};{3};1m{4}{0}[0m" -f $e, $rgb[0], $rgb[1], $rgb[2], $label)
    }
    else {
        Write-Host -NoNewline $label
    }
}

function Write-ConsoleResultsTable {
    # Renders $Results as a colour-coded table that mirrors the HTML: a status pill, the category,
    # then the check + detail wrapped into the remaining terminal width.
    param([System.Collections.IEnumerable] $Results)
    $width = 120
    try { if ($Host.UI.RawUI.WindowSize.Width -gt 40) { $width = $Host.UI.RawUI.WindowSize.Width - 1 } } catch {}

    $pillWidth = 7   # " FAIL " padded to a uniform column, plus a trailing gap
    $catWidth = [Math]::Min(14, (($Results | ForEach-Object { $_.Category.Length } | Measure-Object -Maximum).Maximum))
    $textWidth = [Math]::Max(30, $width - $pillWidth - $catWidth - 2)
    $indent = " " * ($pillWidth + $catWidth + 2)

    foreach ($r in $Results) {
        $d = ($r.Detail -replace "[`r`n]+", " ").Trim()
        $text = if ($d) { "$($r.Check) > $d" } else { $r.Check }

        # Word-wrap the check+detail column.
        $lines = [System.Collections.Generic.List[string]]::new()
        $line = ""
        foreach ($word in ($text -split "\s+")) {
            if ($line.Length -eq 0) { $line = $word }
            elseif (($line.Length + 1 + $word.Length) -le $textWidth) { $line = "$line $word" }
            else { $lines.Add($line); $line = $word }
        }
        if ($line.Length -gt 0) { $lines.Add($line) }
        if ($lines.Count -eq 0) { $lines.Add("") }

        Write-StatusPill -Result $r.Result
        Write-Host ("{0}{1}  {2}" -f " ", $r.Category.PadRight($catWidth), $lines[0])
        for ($i = 1; $i -lt $lines.Count; $i++) { Write-Host ("{0}{1}" -f $indent, $lines[$i]) }
    }
}

function Invoke-CloudShellDownload {
    # In Azure Cloud Shell, trigger a browser download of a file created in the session. No-op (with
    # a hint) anywhere else, since the `download` helper only exists in Cloud Shell.
    param([string] $Path)
    if (-not $script:IsCloudShell) { return }
    if (-not (Test-Path -LiteralPath $Path)) { return }

    # The `download` helper is provided by the Cloud Shell profile. Depending on the image it may be
    # a function, an alias, or a shell shim - and it isn't always discoverable via Get-Command - so
    # don't gate on Get-Command; just try to invoke it and fall back to the toolbar hint on failure.
    # `download` wants a path relative to the Cloud Shell home/working directory, so resolve to a
    # relative path when we can (an absolute path silently fails to produce the browser prompt).
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $arg = $resolved
    try {
        $rel = [System.IO.Path]::GetRelativePath($PWD.Path, $resolved)
        if ($rel -and -not $rel.StartsWith("..")) { $arg = $rel }
    }
    catch {}

    try {
        download $arg
        return
    }
    catch {
        Write-Host -ForegroundColor "Yellow" "  Could not auto-download '$Path': $($_.Exception.Message)."
        Write-Host -ForegroundColor "Yellow" "  Use the Cloud Shell 'Manage files -> Download' toolbar button and enter: $arg"
    }
}
#endregion

# The installer applies CanNotDelete locks to the SQL Database, Key Vault, and (DPS) storage
# account - mirror that here. Tracked as its own resource so cleanup removes the lock first.
function New-PreflightLock {
    param(
        [Parameter(Mandatory = $true)][string] $ResourceId,
        [Parameter(Mandatory = $true)][string] $LockName,
        [Parameter(Mandatory = $true)][string] $Label
    )
    try {
        New-AzResourceLock -LockName $LockName -LockLevel "CanNotDelete" -Scope $ResourceId -Force -ErrorAction Stop | Out-Null
        $lockResourceId = "$ResourceId/providers/Microsoft.Authorization/locks/$LockName"
        Add-TrackedResource -Type "lock" -ResourceGroupName $ResourceGroupName -Name $LockName -Id $lockResourceId -Note $ResourceId
        Add-Result -Category "Deployability" -Check "$Label lock" -Result "Pass" -Detail "CanNotDelete lock applied."
    }
    catch {
        Add-Result -Category "Deployability" -Check "$Label lock" -Result "Warn" -Detail "Could not apply CanNotDelete lock." -Message $_.Exception.Message
    }
}

# Parse an ARM/policy error message for the blocking policy details.
# Ported from Start-NerdioManagerPreFlight.ps1's New-PreflightObject.
function Get-PolicyFromError {
    param([string] $ExceptionMessage)
    $out = [pscustomobject]@{
        Message                     = $ExceptionMessage
        PolicyDefinitionId          = $null
        PolicyAssignmentId          = $null
        PolicySetDefinitionId       = $null
        PolicyDefinitionDisplayName = $null
        PolicyAssignmentDisplayName = $null
    }
    if ([string]::IsNullOrEmpty($ExceptionMessage)) { return $out }

    # Primary: ARM embeds a "Policy identifiers: '[{"policyAssignment":{"name":"...","id":"..."},
    # "policyDefinition":{"name":"...","id":"..."}}]'" block directly in the denial message text. This
    # is present regardless of which SDK/exception shape wraps it, and - critically - regardless of
    # whatever other diagnostic text (ErrorDetails, response body, etc.) got concatenated around it, so
    # search for this specific marker instead of assuming the whole message is (or ends in) one valid
    # JSON blob. The bracketed text can be plain or JSON-escaped (nested a level inside another JSON
    # string), depending on which cmdlet threw it - strip any escaping before parsing.
    if ($ExceptionMessage -match "Policy identifiers:\s*'(\[.*?\])'") {
        try {
            $piArr = @(($Matches[1] -replace '\\"', '"') | ConvertFrom-Json -ErrorAction Stop)
            $first = $piArr | Select-Object -First 1
            if ($first) {
                if ($first.policyAssignment.name) { $out.PolicyAssignmentDisplayName = $first.policyAssignment.name }
                if ($first.policyAssignment.id) { $out.PolicyAssignmentId = $first.policyAssignment.id }
                if ($first.policyDefinition.name) { $out.PolicyDefinitionDisplayName = $first.policyDefinition.name }
                if ($first.policyDefinition.id) { $out.PolicyDefinitionId = $first.policyDefinition.id }
            }
        }
        catch {}
    }

    # Secondary: the error.additionalInfo[].info shape (ids, display names, and - for Initiative-
    # assigned policies - the set definition id). Only attempted when the primary parse above didn't
    # already resolve a name, and only trusted when the message truly is one clean trailing JSON blob -
    # appended diagnostic text (ErrorDetails/response body/etc.) can otherwise garble this parse.
    if (-not $out.PolicyAssignmentDisplayName -and -not $out.PolicyDefinitionDisplayName -and $ExceptionMessage -match "({.*}$)") {
        try {
            $j = $Matches[0] | ConvertFrom-Json -ErrorAction Stop
            if ($j.error.message) { $out.Message = $j.error.message }
            $info = ($j.error.additionalInfo | Where-Object { $_.type -eq "PolicyViolation" } | Select-Object -First 1).info
            if ($info) {
                if (-not $out.PolicyDefinitionId -and $info.policyDefinitionId) { $out.PolicyDefinitionId = $info.policyDefinitionId }
                if (-not $out.PolicyAssignmentId -and $info.policyAssignmentId) { $out.PolicyAssignmentId = $info.policyAssignmentId }
                if ($info.policySetDefinitionId) { $out.PolicySetDefinitionId = $info.policySetDefinitionId }
                if ($info.policyDefinitionDisplayName) { $out.PolicyDefinitionDisplayName = $info.policyDefinitionDisplayName }
                if ($info.policyAssignmentDisplayName) { $out.PolicyAssignmentDisplayName = $info.policyAssignmentDisplayName }
            }
        }
        catch {}
    }

    # Last resort: bare policyDefinitionId/policyAssignmentId resource-id keys (older/odd shapes).
    if (-not $out.PolicyDefinitionId -and $ExceptionMessage -match "policyDefinitionId'?:?\s*'?(/[^',\s\}]+)") { $out.PolicyDefinitionId = $Matches[1] }
    if (-not $out.PolicyAssignmentId -and $ExceptionMessage -match "policyAssignmentId'?:?\s*'?(/[^',\s\}]+)") { $out.PolicyAssignmentId = $Matches[1] }
    return $out
}

# Reduce a raw (often multi-part) ARM/SDK error blob to the single actionable line for display - the
# top-level error.message (e.g. the quota text). The full raw text is preserved separately in the JSON
# output (Add-Result -RawMessage), so nothing is lost here.
function Get-ConciseErrorMessage {
    param([string] $RawMessage)
    if ([string]::IsNullOrWhiteSpace($RawMessage)) { return $RawMessage }

    $extract = {
        param($obj)
        if ($null -eq $obj) { return $null }
        $m = $null
        if ($obj.error -and $obj.error.message) { $m = $obj.error.message }
        elseif ($obj.message) { $m = $obj.message }
        if ($m -and $obj.error -and $obj.error.details) {
            $d = @($obj.error.details) | Where-Object { $_.message } | Select-Object -First 1
            if ($d -and $d.message -and $m -match "multiple error|see details|one or more") { $m = $d.message }
        }
        return $m
    }

    # Candidate JSON snippets: the whole blob first (single clean JSON), then each line that is itself a
    # JSON object (the raw is a concatenation of Message + ErrorDetails + Response.Content + Body).
    $snippets = @($RawMessage)
    $snippets += ($RawMessage -split "`r`n|`n|`r" | Where-Object { $_ -match '^\s*\{.*\}\s*$' })
    foreach ($s in $snippets) {
        try {
            $j = $s | ConvertFrom-Json -ErrorAction Stop
            $m = & $extract $j
            if ($m) { return ($m -replace "[`r`n]+", " ").Trim() }
        }
        catch {}
    }

    # No parseable JSON error.message - return the first meaningful line (skip Track1 boilerplate).
    $line = $RawMessage -split "`r`n|`n|`r" | ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and $_ -notmatch "Operation returned an invalid status code" } |
        Select-Object -First 1
    if ($line) { return $line }
    return $RawMessage.Trim()
}

# Resolve a policy definition/assignment id to a friendly display name.
function Resolve-PolicyName {
    param(
        [string] $PolicyDefinitionId,
        [string] $PolicyAssignmentId,
        [string] $PolicySetDefinitionId,
        [string] $DisplayNameHint
    )
    # A display name already handed to us (e.g. straight from the ARM error's/Activity Log's
    # additionalInfo) is authoritative and avoids extra API calls that can fail under limited rights.
    if ($DisplayNameHint) { return $DisplayNameHint }

    $name = $null
    $assignment = $null
    if ($PolicyAssignmentId) {
        try { $assignment = Get-AzPolicyAssignment -Id $PolicyAssignmentId -ErrorAction Stop } catch {}
        if ($assignment) { $name = $assignment.Properties.DisplayName }
    }
    if (-not $name -and $PolicyDefinitionId) {
        if ($PolicyDefinitionId -like "/*") {
            # A real ARM resource id - look the definition up directly.
            try { $name = (Get-AzPolicyDefinition -Id $PolicyDefinitionId -ErrorAction Stop).Properties.DisplayName } catch {}
        }
        else {
            # No leading "/" means this isn't a resource id at all. When the blocking policy is a
            # member of an Initiative (policy set) assignment, Azure's additionalInfo reports the
            # member's short policyDefinitionReferenceId in this field instead of a real definition id -
            # resolve it by looking up the initiative and matching that reference id to its member policy.
            $setId = $PolicySetDefinitionId
            if (-not $setId -and $assignment -and $assignment.Properties.PolicyDefinitionId -match "/policySetDefinitions/") {
                $setId = $assignment.Properties.PolicyDefinitionId
            }
            if ($setId) {
                try {
                    $setDef = Get-AzPolicySetDefinition -Id $setId -ErrorAction Stop
                    $member = $setDef.Properties.PolicyDefinitions | Where-Object { $_.policyDefinitionReferenceId -eq $PolicyDefinitionId } | Select-Object -First 1
                    if ($member -and $member.policyDefinitionId) {
                        try { $name = (Get-AzPolicyDefinition -Id $member.policyDefinitionId -ErrorAction Stop).Properties.DisplayName } catch {}
                    }
                    if (-not $name) { $name = $setDef.Properties.DisplayName }
                }
                catch {}
            }
        }
    }
    if (-not $name) { $name = $PolicyAssignmentId; if (-not $name) { $name = $PolicyDefinitionId } }
    return $name
}

# When an ARM error doesn't embed the blocking policy's identifiers (New-AzResourceGroup's
# RequestDisallowedByPolicy frequently doesn't), the Activity Log does: the failed control-plane
# operation is recorded with a PolicyViolation carrying the policy/assignment ids AND display names.
# Activity Log ingestion can lag the operation by minutes, so poll for up to 5 minutes by default.
function Get-PolicyFromActivityLog {
    param(
        [Parameter(Mandatory = $true)][string] $ResourceGroupName,
        [datetime] $StartTime,
        [int] $MaxAttempts = 30,
        [int] $DelaySeconds = 10
    )
    $out = [pscustomobject]@{
        PolicyDefinitionId     = $null
        PolicyAssignmentId     = $null
        PolicyDefinitionName   = $null
        PolicyAssignmentName   = $null
        PolicySetDefinitionId  = $null
        Found                  = $false
    }
    if (-not $StartTime) { $StartTime = (Get-Date).ToUniversalTime().AddMinutes(-15) }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $events = @()
        try {
            $events = @(Get-AzLog -ResourceGroupName $ResourceGroupName -StartTime $StartTime -WarningAction SilentlyContinue -ErrorAction Stop)
        }
        catch {
            # Filtering on a resource group that was never created can fault on some API versions -
            # fall back to a subscription-scoped query filtered client-side by resource group name.
            try { $events = @(Get-AzLog -StartTime $StartTime -WarningAction SilentlyContinue -ErrorAction Stop | Where-Object { $_.ResourceGroupName -eq $ResourceGroupName }) }
            catch { $events = @() }
        }

        foreach ($ev in $events) {
            # Flatten the event's Properties bag into one text blob - used both to detect the deny and
            # to regex-extract policy fields if the structured parse below doesn't land.
            $content = $null
            try { if ($ev.Properties -and $ev.Properties.Content) { $content = $ev.Properties.Content } } catch {}
            $statusMessage = $null
            $blob = ""
            if ($content) {
                try {
                    foreach ($k in @($content.Keys)) {
                        $blob += "`n$k=$($content[$k])"
                        if ($k -eq "statusMessage") { $statusMessage = $content[$k] }
                    }
                }
                catch {}
            }
            $subStatus = $null; try { $subStatus = $ev.SubStatus.Value } catch {}
            $isDeny = ($subStatus -eq "RequestDisallowedByPolicy") -or ($blob -match "RequestDisallowedByPolicy") -or ($blob -match "disallowed by policy")
            if (-not $isDeny) { continue }

            # Preferred: the statusMessage JSON carries error.additionalInfo[].info with ids AND names.
            if ($statusMessage) {
                try {
                    $j = $statusMessage | ConvertFrom-Json
                    $info = ($j.error.additionalInfo | Where-Object { $_.type -eq "PolicyViolation" } | Select-Object -First 1).info
                    if ($info) {
                        if ($info.policyDefinitionId) { $out.PolicyDefinitionId = $info.policyDefinitionId }
                        if ($info.policyAssignmentId) { $out.PolicyAssignmentId = $info.policyAssignmentId }
                        if ($info.policySetDefinitionId) { $out.PolicySetDefinitionId = $info.policySetDefinitionId }
                        $out.PolicyDefinitionName = $(if ($info.policyDefinitionDisplayName) { $info.policyDefinitionDisplayName } else { $info.policyDefinitionName })
                        $out.PolicyAssignmentName = $(if ($info.policyAssignmentDisplayName) { $info.policyAssignmentDisplayName } else { $info.policyAssignmentName })
                    }
                }
                catch {}
            }
            # Fallback: regex the blob for anything the structured parse didn't fill in.
            if (-not $out.PolicyDefinitionId -and $blob -match 'policyDefinitionId"?\s*:\s*"?([^",\s}]+)') { $out.PolicyDefinitionId = $Matches[1] }
            if (-not $out.PolicyAssignmentId -and $blob -match 'policyAssignmentId"?\s*:\s*"?(/[^",\s}]+)') { $out.PolicyAssignmentId = $Matches[1] }
            if (-not $out.PolicySetDefinitionId -and $blob -match 'policySetDefinitionId"?\s*:\s*"?(/[^",\s}]+)') { $out.PolicySetDefinitionId = $Matches[1] }
            if (-not $out.PolicyDefinitionName -and $blob -match 'policyDefinition(?:Display)?Name"?\s*:\s*"([^"]+)"') { $out.PolicyDefinitionName = $Matches[1] }
            if (-not $out.PolicyAssignmentName -and $blob -match 'policyAssignment(?:Display)?Name"?\s*:\s*"([^"]+)"') { $out.PolicyAssignmentName = $Matches[1] }

            if ($out.PolicyDefinitionId -or $out.PolicyAssignmentId -or $out.PolicyDefinitionName -or $out.PolicyAssignmentName) {
                $out.Found = $true
                break
            }
        }

        if ($out.Found) { break }
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
    }
    return $out
}

function New-RandomString {
    param([int] $Length = 8)
    $chars = "abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
    return (-join (1..$Length | ForEach-Object { $chars | Get-Random })).ToLower()
}

function Get-MaskedAccount {
    # Mask the local part of a UPN for display: keep the first 1 and last 2 characters, replace the
    # middle with '*' (one per replaced char); leave the domain intact. Local parts of 3 chars or
    # fewer are returned unchanged (nothing meaningful to mask). No '@' -> treat the whole string as
    # the local part.  e.g. jsmith@contoso.com -> j***th@contoso.com
    param([string] $Account)
    if ([string]::IsNullOrWhiteSpace($Account)) { return $Account }
    $atIndex = $Account.IndexOf("@")
    if ($atIndex -ge 0) { $local = $Account.Substring(0, $atIndex); $domain = $Account.Substring($atIndex) }
    else { $local = $Account; $domain = "" }
    if ($local.Length -le 3) { return "$local$domain" }
    $masked = $local.Substring(0, 1) + ("*" * ($local.Length - 3)) + $local.Substring($local.Length - 2, 2)
    return "$masked$domain"
}

function Write-HelpText {
    param([string] $Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    # Bracket the help block with blank lines so it stands apart from the prompt above and the
    # re-prompt below.
    Write-Host ""
    $width = 90
    $paragraphs = $Text -split "`r`n|\n|\r"
    foreach ($paragraph in $paragraphs) {
        if ([string]::IsNullOrWhiteSpace($paragraph)) { Write-Host ""; continue }
        $words = $paragraph -split "\s+"
        $line = ""
        foreach ($word in $words) {
            if ($line.Length -eq 0) { $line = $word }
            elseif (($line.Length + 1 + $word.Length) -le $width) { $line = "$line $word" }
            else { Write-Host -ForegroundColor "Cyan" "    $line"; $line = $word }
        }
        if ($line.Length -gt 0) { Write-Host -ForegroundColor "Cyan" "    $line" }
    }
    Write-Host ""
}

function Read-YesNo {
    param([string] $Prompt, [string] $Default = "y", [string] $Help)
    $displayPrompt = if ($Help) { "$Prompt (or '?' for help)" } else { $Prompt }
    do {
        Write-Host ""
        $r = Read-Host -Prompt $displayPrompt
        if ([string]::IsNullOrWhiteSpace($r)) { $r = $Default }
        if ($Help -and $r -eq "?") { Write-HelpText -Text $Help; continue }
    } while ($r -notmatch "^[YyNn]$")
    Write-Host ""
    return ($r -match "^[Yy]$")
}

function Read-Choice {
    param(
        [Parameter(Mandatory = $true)][string] $Prompt,
        [Parameter(Mandatory = $true)][string[]] $Options,
        [string] $Help,
        [int] $Default = 1
    )
    $hasHelp = -not [string]::IsNullOrWhiteSpace($Help)

    # Present the default option first, but keep track of each displayed position's original
    # index so the function still returns the original 1-based index into $Options.
    $originalIndices = @($Default) + @(1..$Options.Count | Where-Object { $_ -ne $Default })
    $displayOptions = @($originalIndices | ForEach-Object { $Options[$_ - 1] })

    $tokens = @(1..$Options.Count | ForEach-Object { "$_" })
    if ($hasHelp) { $tokens += "?" }
    $choiceStr = $tokens -join "/"
    while ($true) {
        Write-Host ""
        Write-Host $Prompt
        Write-Host ""
        for ($i = 0; $i -lt $displayOptions.Count; $i++) { Write-Host ("  {0}) {1}" -f ($i + 1), $displayOptions[$i]) }
        if ($hasHelp) { Write-Host "  ?) More information" }
        Write-Host ""
        $r = Read-Host -Prompt "Choose [$choiceStr] (default 1)"
        if ([string]::IsNullOrWhiteSpace($r)) { Write-Host ""; return $Default }
        if ($hasHelp -and $r -eq "?") { Write-HelpText -Text $Help; continue }
        if ($r -match "^\d+$" -and [int]$r -ge 1 -and [int]$r -le $displayOptions.Count) { Write-Host ""; return $originalIndices[[int]$r - 1] }
        Write-Host -ForegroundColor "Yellow" "  Invalid choice. Try again."
    }
}
#endregion

#region Banner and auth guard ---------------------------------------------------------------------
$Logo = @"
                                                                  ::::
                           ++++++++++                            ::::::
                        +++++++++++++++++                        ::::::
                      ++++++*+*++*++++++++*               ::::   ::::::   ::::
                    ++++++*          +*+++++             :::::   ::::::   ::::::
                   +++++*              +++++*           :::::    ::::::    ::::::
                   +++++                +++++          :::::     ::::::     ::::::
                  ++++*                  +++++         ::::       ::::       :::::
                  +++++                  +++++++++=::::::::                  :::::
               ++++++++                  ++++++*++-::::::::                  ::::::::
               ++++++++*                ++++++         :::::                :::::::::
                   ++++++              +++++*          ::::::              ::::::
                    +++++++           ++++++            :::::::          :::::::
                      ++++++++    ++++++++               ::::::::::::::::::::::
                       *+++++++++++++++*+                  ::::::::::::::::::
                          *++++++++*+                         ::::::::::::
"@
Write-Host ""
Write-Host -ForegroundColor "Cyan" $Logo
Write-Host ""
Write-Host -ForegroundColor "Cyan" "Nerdio Manager for Enterprise - Deployment Readiness Pre-Flight"
Write-Host ""
Write-Host "This script checks whether this Azure environment can host a Nerdio Manager deployment."
Write-Host "It will:"
Write-Host ""
Write-Host "  1. Check your Entra directory roles and Azure subscription role (read-only)."
Write-Host "  2. Check required resource providers are registered (read-only)."
Write-Host "  3. Show you the exact resource names (and tags) it will use and let you customize them."
Write-Host "  4. Create a temporary resource group (or use an existing empty one you provide) and attempt to deploy"
Write-Host "     throwaway copies of the resources Nerdio Manager needs."
Write-Host "  5. Optionally test private endpoints, DNS resolution, and App Service VNet integration"
Write-Host "     outbound connectivity, in an existing VNet you name or a new one this script creates"
Write-Host "  6. DELETE everything it created, then provide a report you can send to your Nerdio sales team."
Write-Host ""
Write-Host -ForegroundColor "Cyan" "This script is publicly available for inspection at:`r`nhttps://raw.githubusercontent.com/Get-Nerdio/NME-SE/refs/heads/main/preflight/Test-NmeDeploymentReadiness.ps1"
Write-Host ""
Write-Host -ForegroundColor "Yellow" "This script will NOT modify anything outside the test resource group, other than (if you opt in)"
Write-Host -ForegroundColor "Yellow" "creating and then removing private endpoints in the existing subnet you specify."
Write-Host ""
Write-Host "Typical runtime: 2-10 minutes."
Write-Host ""

# Auth guard - a valid Az token is the only hard prerequisite.
try {
    $token = Get-AzAccessToken -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if ($null -eq $token) { throw "no token" }
}
catch {
    Write-Host -ForegroundColor "Red" "Not authenticated to Azure. Run 'Connect-AzAccount -UseDeviceAuthentication' first, then re-run this script."
    return
}

if (-not (Read-YesNo -Prompt "Proceed? [Y/n]" -Default "y")) {
    Write-Host -ForegroundColor "Cyan" "Aborted. No changes made."
    return
}
#endregion

# Everything below runs inside try/finally so cleanup always happens.
$CreatedResourceGroup = $false
$ConfigSummary = [ordered]@{}
$CustomResourceNames = [ordered]@{}   # Label -> final custom Value, only for entries the user changed
try {
    #region Intake -------------------------------------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        do { $SubscriptionId = Read-Host -Prompt "Enter the target Azure subscription id (GUID)" }
        while ($SubscriptionId -notmatch "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
    }
    try {
        $Context = Set-AzContext -Subscription $SubscriptionId -ErrorAction Stop
        Write-Host -ForegroundColor "Green" "[$([char]0x2713)] Subscription context set: '$($Context.Subscription.Name)'."
    }
    catch {
        Write-Host -ForegroundColor "Red" "Could not set context to subscription '$SubscriptionId': $($_.Exception.Message)"
        return
    }

    # Cloud environment (Commercial / Gov / China) drives Graph endpoint and DNS suffixes.
    $AzEnv = (Get-AzContext).Environment
    $GraphBase = switch ($AzEnv.Name) {
        "AzureUSGovernment" { "https://graph.microsoft.us" }
        "AzureChinaCloud" { "https://microsoftgraph.chinacloudapi.cn" }
        default { "https://graph.microsoft.com" }
    }
    $StorageSuffix = $AzEnv.StorageEndpointSuffix           # e.g. core.windows.net
    $SqlSuffix = $AzEnv.SqlDatabaseDnsSuffix                # e.g. .database.windows.net
    $KeyVaultSuffix = $AzEnv.AzureKeyVaultDnsSuffix         # e.g. vault.azure.net
    if ([string]::IsNullOrEmpty($StorageSuffix)) { $StorageSuffix = "core.windows.net" }
    if ([string]::IsNullOrEmpty($SqlSuffix)) { $SqlSuffix = ".database.windows.net" }
    if ([string]::IsNullOrEmpty($KeyVaultSuffix)) { $KeyVaultSuffix = "vault.azure.net" }

    # Resolve the true signed-in user's Entra identity via Graph. In Azure Cloud Shell,
    # (Get-AzContext).Account.Id reports the internal MSI token-broker reference (e.g. "MSI@50342"),
    # not the user's UPN, which breaks both the report's "Run by" field and Get-AzRoleAssignment
    # -SignInName lookups further down. Falls back to Account.Id for normal sessions where it's
    # already a valid UPN/object id.
    $meObjectId = $null
    $meUpn = $null
    try {
        $meResp = Invoke-AzRestMethod -Uri "$GraphBase/v1.0/me`?`$select=id,userPrincipalName" -Method GET -ErrorAction Stop
        if ($meResp.StatusCode -eq 200) {
            $meJson = $meResp.Content | ConvertFrom-Json
            $meObjectId = $meJson.id
            $meUpn = $meJson.userPrincipalName
        }
    }
    catch { }
    $SignedInAccount = if ($meUpn) { $meUpn } else { (Get-AzContext).Account.Id }
    $SignedInAccountMasked = Get-MaskedAccount $SignedInAccount
    $SqlSuffix = $SqlSuffix.TrimStart(".")

    # Private DNS zones the installer creates/links for a private deployment (suffixes are
    # environment-aware). Computed once here so both the intake questions and the later private
    # endpoint/DNS test can reference the same list.
    $RequiredPrivateDnsZones = @(
        @{ Purpose = "SQL"; Zone = "privatelink.$SqlSuffix" },
        @{ Purpose = "App Service"; Zone = $(if ($AzEnv.Name -eq "AzureUSGovernment") { "privatelink.azurewebsites.us" } elseif ($AzEnv.Name -eq "AzureChinaCloud") { "privatelink.chinacloudsites.cn" } else { "privatelink.azurewebsites.net" }) },
        @{ Purpose = "Key Vault"; Zone = $(if ($AzEnv.Name -eq "AzureUSGovernment") { "privatelink.vaultcore.usgovcloudapi.net" } elseif ($AzEnv.Name -eq "AzureChinaCloud") { "privatelink.vaultcore.azure.cn" } else { "privatelink.vaultcore.azure.net" }) },
        @{ Purpose = "Blob storage"; Zone = "privatelink.blob.$StorageSuffix" },
        @{ Purpose = "Automation"; Zone = $(if ($AzEnv.Name -eq "AzureUSGovernment") { "privatelink.azure-automation.us" } elseif ($AzEnv.Name -eq "AzureChinaCloud") { "privatelink.azure-automation.cn" } else { "privatelink.azure-automation.net" }) }
    )

    # Resource group: existing (must be empty - NME installs only into a new or empty RG), or a
    # temporary one this script creates (after the naming/tag confirmation below).
    $PendingRgCreate = $false
    $useExisting = $false
    if (-not [string]::IsNullOrWhiteSpace($ResourceGroupName)) {
        # Supplied via -ResourceGroupName; validated (and re-prompted if bad) in the loop below.
        $useExisting = $true
    }
    elseif (Read-YesNo -Prompt "Use an EXISTING (empty) resource group for the test resources? [y/N]" -Default "n" -Help "Nerdio Manager for Enterprise installs only into a new or completely empty resource group. Answering No has this script create a temporary resource group of its own, which it deletes (along with everything created inside it) at the end of the run.") {
        $useExisting = $true
        $ResourceGroupName = $null
    }

    if ($useExisting) {
        # NME requires a new or EMPTY resource group, so mirror that here: the RG must exist AND be
        # empty. Re-prompt on a name we can't find or one that already contains resources.
        $ResourceGroup = $null
        do {
            if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
                do { $ResourceGroupName = Read-Host -Prompt "  Existing resource group name (must be EMPTY - NME installs only into a new or empty RG)" } while ([string]::IsNullOrWhiteSpace($ResourceGroupName))
            }
            try { $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop }
            catch {
                Write-Host -ForegroundColor "Yellow" "  Could not find resource group '$ResourceGroupName' in this subscription. Try again."
                $ResourceGroup = $null; $ResourceGroupName = $null; continue
            }
            try {
                $existingResources = Get-AzResource -ResourceGroupName $ResourceGroupName -ErrorAction Stop
                if ($existingResources -and $existingResources.Count -gt 0) {
                    Write-Host -ForegroundColor "Yellow" "  Resource group '$ResourceGroupName' is not empty ($($existingResources.Count) resource(s)). NME requires a new or EMPTY resource group - choose an empty one, or answer 'n' next time to have this script create a temporary one."
                    $ResourceGroup = $null; $ResourceGroupName = $null
                }
            }
            catch {
                # Can't enumerate (e.g. permissions) - warn but don't block; accept the RG as-is.
                Write-Host -ForegroundColor "Yellow" "  Could not verify whether '$ResourceGroupName' is empty: $($_.Exception.Message)"
            }
        } while (-not $ResourceGroup)
        $Location = $ResourceGroup.Location
        Write-Host -ForegroundColor "Green" "[$([char]0x2713)] Using existing empty resource group '$ResourceGroupName' in '$Location'."
    }
    else {
        # Valid regions for this subscription - used to validate the region and re-prompt on a bad value.
        $validRegions = @()
        try { $validRegions = @((Get-AzLocation -ErrorAction Stop).Location) } catch {}
        $Location = ($Location -replace "\s", "").ToLower()
        if ([string]::IsNullOrWhiteSpace($Location) -or ($validRegions.Count -gt 0 -and $validRegions -notcontains $Location)) {
            if (-not [string]::IsNullOrWhiteSpace($Location) -and $validRegions.Count -gt 0) {
                Write-Host -ForegroundColor "Yellow" "  '$Location' is not a valid region for this subscription."
            }
            do {
                $regionRaw = (Read-Host -Prompt "Enter the Azure region for the temporary test resources (e.g. eastus, or '?' to list all)").Trim()
                if ($regionRaw -eq "?" -or $regionRaw -ieq "list") {
                    if ($validRegions.Count -gt 0) {
                        Write-Host ""
                        Write-Host -ForegroundColor "Cyan" "  Valid Azure regions for this subscription:"
                        $sortedRegions = $validRegions | Sort-Object
                        $colWidth = 28; $perRow = [Math]::Max(1, [Math]::Floor(110 / $colWidth))
                        for ($ri = 0; $ri -lt $sortedRegions.Count; $ri += $perRow) {
                            $row = $sortedRegions[$ri..([Math]::Min($ri + $perRow - 1, $sortedRegions.Count - 1))]
                            Write-Host ("    " + (($row | ForEach-Object { $_.PadRight($colWidth) }) -join ""))
                        }
                        Write-Host ""
                    }
                    else {
                        Write-Host -ForegroundColor "Yellow" "  Region list unavailable (could not query Get-AzLocation). Enter the region name, e.g. eastus."
                    }
                    $Location = $null
                    continue
                }
                $Location = ($regionRaw -replace "\s", "").ToLower()
                if ([string]::IsNullOrWhiteSpace($Location)) { continue }
                if ($validRegions.Count -gt 0 -and $validRegions -notcontains $Location) {
                    Write-Host -ForegroundColor "Yellow" "  '$Location' is not a valid region. Type '?' to list all valid regions."
                    $Location = $null
                }
            } while ([string]::IsNullOrWhiteSpace($Location))
        }
        $ResourceGroupName = "rg-nme-preflight-$(New-RandomString -Length 6)"
        $PendingRgCreate = $true
        $CreatedResourceGroup = $true
    }

    # Private-network scenario. A private NME deployment requires a VNet with two subnets: one for
    # private endpoints, one (delegated to Microsoft.Web/serverFarms) for App Service VNet
    # integration - so both are always requested together; there is no separate opt-in question.
    # The VNet can be one the user already has, or a new one this script creates and names.
    $TestPrivate = $false
    $TestVnetIntegration = $false
    $CreateNewVnet = $false
    $VnetInfoUnknown = $false
    $ExistingVnetRg = $null; $ExistingVnetName = $null; $PeSubnetName = $null; $AppSubnetName = $null
    $PrivateDnsZonesMode = $null; $PrivateDnsZoneSubId = $null; $PrivateDnsZoneRg = $null
    $privateChoice = Read-Choice -Prompt "Do you want to deploy Nerdio Manager with PRIVATE ENDPOINTS?" -Options @(
        "Yes - deploy with private endpoints (no public internet exposure)",
        "No - use public endpoints (default)"
    ) -Default 2 -Help "Private endpoints give NME's PaaS dependencies (SQL Database, Key Vault, Storage, and the App Service) private IPs on your VNet instead of public endpoints. `r`n`r`nPros: no public exposure of the NME data plane; meets network-isolation requirements. Note that public endpoints are still protected by Azure authentication and authorization requirements. `r`n`r`nCons: increases complexity and can extend the Nerdio Proof of Value timeline. `r`n`r`nNOTE: Private endpoints can be enabled after proving value and before going to production."
    if ($privateChoice -eq 1) {
        $TestPrivate = $true
        $TestVnetIntegration = $true

        $vnetChoice = Read-Choice -Prompt "Will you deploy to an EXISTING VNet?" -Options @(
            "Use an EXISTING VNet (you provide RG, VNet, and both subnet names)",
            "Create a NEW VNet for Nerdio Manager (this script creates and later deletes a vnet. You will be able to specify the address space for the actual deployment.)",
            "I don't know yet - the VNet hasn't been created yet"
        ) -Default 2 -Help "NME can be deployed to a new VNet created during deployment, which simplifies DNS and networking - this is the preferred/default deployment. Deploying into an EXISTING VNet is recommended when your organization requires routing all traffic through centralized firewalls. `r`n`r`nSelecting an EXISTING VNet tests against the real network NME will use - its subnets, DNS settings, and any private DNS zone links - so the result of this test reflects your production topology. You must provide the VNet's resource group, its name, a subnet for private endpoints, and a separate subnet delegated to Microsoft.Web/serverFarms for App Service integration. `r`n`r`nA NEW VNet lets the script prove the resources CAN be created (VNet, subnets, delegation, private endpoint) in a clean 10.60.0.0/16 space it creates and then deletes. `r`n`r`nIf you plan to use your own existing VNet but haven't created it yet, choose the third option - the script will skip private endpoint / VNet integration testing this run, but you must have the VNet's resource group, name, and subnet names ready before the actual NME POV installation."
        if ($vnetChoice -eq 1) {
            # Validate the VNet exists up front and re-prompt on a bad value, so the user isn't told the
            # name was wrong only after the deployability phase has already created resources.
            $intakeVnet = $null
            do {
                do { $ExistingVnetRg = Read-Host -Prompt "  Existing VNet's resource group name" } while ([string]::IsNullOrWhiteSpace($ExistingVnetRg))
                do { $ExistingVnetName = Read-Host -Prompt "  Existing VNet name" } while ([string]::IsNullOrWhiteSpace($ExistingVnetName))
                try { $intakeVnet = Get-AzVirtualNetwork -ResourceGroupName $ExistingVnetRg -Name $ExistingVnetName -ErrorAction Stop }
                catch { Write-Host -ForegroundColor "Yellow" "  Could not find VNet '$ExistingVnetName' in resource group '$ExistingVnetRg' in this subscription. Try again."; $intakeVnet = $null }
            } while (-not $intakeVnet)

            # Both subnets are validated against the VNet's actual subnets and must be distinct - a subnet
            # delegated to Microsoft.Web/serverFarms cannot also host private endpoints.
            $subnetNames = @($intakeVnet.Subnets.Name)
            Write-Host -ForegroundColor "Cyan" "`r`n  Subnets in '$ExistingVnetName': $($subnetNames -join ', ')`r`n"
            do {
                $PeSubnetName = Read-Host -Prompt "  Subnet name for private endpoints"
                if ([string]::IsNullOrWhiteSpace($PeSubnetName)) { continue }
                if ($subnetNames -notcontains $PeSubnetName) { Write-Host -ForegroundColor "Yellow" "  Subnet '$PeSubnetName' not found in '$ExistingVnetName'. Try again."; $PeSubnetName = $null }
            } while ([string]::IsNullOrWhiteSpace($PeSubnetName))
            do {
                $AppSubnetName = Read-Host -Prompt "  Subnet name for App Service VNet integration (should be delegated to Microsoft.Web/serverFarms)"
                if ([string]::IsNullOrWhiteSpace($AppSubnetName)) { continue }
                if ($subnetNames -notcontains $AppSubnetName) { Write-Host -ForegroundColor "Yellow" "  Subnet '$AppSubnetName' not found in '$ExistingVnetName'. Try again."; $AppSubnetName = $null }
                elseif ($AppSubnetName -eq $PeSubnetName) { Write-Host -ForegroundColor "Yellow" "  The App Service integration subnet must be different from the private endpoint subnet. Try again."; $AppSubnetName = $null }
            } while ([string]::IsNullOrWhiteSpace($AppSubnetName))

            # Consent gate: creating private endpoints + enabling App Service VNet integration on an
            # EXISTING VNet mutates real customer network resources (even though everything is removed
            # at cleanup), unlike the new-VNet path where the whole VNet is throwaway. Get explicit
            # confirmation before proceeding, and make clear this will NOT touch DNS configuration.
            Write-Host -ForegroundColor "Cyan" "`r`n  On the EXISTING VNet '$ExistingVnetName', this test will:"
            Write-HelpText -Text "1) Create TEMPORARY private endpoints in subnet '$PeSubnetName' for SQL, Key Vault, Storage, and Automation. `r`n`r`n2) Enable App Service VNet integration on subnet '$AppSubnetName'. `r`n`r`n3) Test DNS resolution and outbound/private connectivity from a temporary App Service. `r`n`r`n4) DELETE everything it created at the end. `r`n`r`nIt will NOT change any DNS settings - no Private DNS zone creation or linking, no VNet DNS-server changes - it only READS current configuration and TESTS resolution/connectivity."
            $peConsent = Read-YesNo -Prompt "Proceed with private endpoint + VNet integration testing on this existing VNet? [Y/n]" -Default "y"
            if (-not $peConsent) {
                $TestPrivate = $false
                $TestVnetIntegration = $false
                Write-Host -ForegroundColor "Cyan" "  Skipping private endpoint / VNet integration testing on existing VNet '$ExistingVnetName' by choice."
                $ConfigSummary["Private endpoint scenario"] = "Declined - user did not consent to private endpoint / VNet integration testing on existing VNet '$ExistingVnetName'"
            }
            else {
                # If the VNet resolves via custom DNS servers (rather than Azure DNS), Azure Private DNS
                # zones aren't how resolution works there, so the existing-vs-new zones question is noise -
                # skip it entirely. Same detection the verification region uses further down.
                $intakeUsesCustomDns = $intakeVnet.DhcpOptions.DnsServers -and $intakeVnet.DhcpOptions.DnsServers.Count -gt 0
                if ($intakeUsesCustomDns) {
                    $dnsServersStr = $intakeVnet.DhcpOptions.DnsServers -join ", "
                    Write-Host -ForegroundColor "Cyan" "  VNet '$ExistingVnetName' uses custom DNS servers ($dnsServersStr); Azure Private DNS zone questions are not applicable and will be skipped."
                    $ConfigSummary["Private DNS zones plan"] = "N/A - VNet '$ExistingVnetName' uses custom DNS servers ($dnsServersStr); resolution is handled by the custom DNS provider"
                }
                else {
                    # Existing-vs-new Private DNS zones question. Asked here even though we don't yet know
                    # whether this VNet actually uses Azure DNS (that's only detectable from its DhcpOptions,
                    # in the verification region below) - an existing VNet is the common case for this, and the
                    # verification step gates on the real detected mode, simply ignoring this answer if the
                    # VNet turns out to use custom/on-prem DNS.
                    $dnsZonesChoice = Read-Choice -Prompt "  Will you use EXISTING Azure Private DNS zones, or have NME/this script create NEW ones?" -Options @(
                        "Use EXISTING Private DNS zones (you will be asked to provide the subscription + resource group of the existing zones)",
                        "Create NEW Private DNS zones (the installer/runbook creates them at deploy time)",
                        "I don't know yet - will use EXISTING zones but the subscription/resource group aren't known yet"
                    ) -Default 2 -Help "NME's private endpoints need these Azure Private DNS zones, linked to the VNet, to resolve to private IPs: `r`n`r`nprivatelink.database.windows.net (SQL)`r`nprivatelink.vaultcore.azure.net (Key Vault)`r`nprivatelink.blob.core.windows.net (Storage)`r`nprivatelink.azurewebsites.net (App Service)`r`nprivatelink.azure-automation.net (Automation)`n`r`n`r`nEXISTING: your org already manages these zones centrally (common with hub/spoke + Azure Policy auto-registration) - you will be asked to provide the subscription and resource group that holds them, and this script reports which required zones are MISSING there. `r`n`r`nNEW: NME's deployment (or the Enable Private Endpoints runbook) will create and link the zones for you - this script only tests that the required zones CAN be created (in the throwaway test resource group) and does NOT link them to your VNet; the real installer/runbook creates and links them at deploy time. (Gov/China clouds use the equivalent .us/.cn zone names, derived automatically.) `r`n`r`nIf you'll use EXISTING zones but don't yet know their subscription/resource group, choose the third option - this script will skip the zone verification this run, but you must have that information ready before the actual NME POV installation."
                    if ($dnsZonesChoice -eq 1) {
                        $PrivateDnsZonesMode = "Existing"
                        do { $PrivateDnsZoneSubId = Read-Host -Prompt "    Subscription ID where the Azure Private DNS zones live" } while ($PrivateDnsZoneSubId -notmatch "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
                        do { $PrivateDnsZoneRg = Read-Host -Prompt "    Resource group name for the Azure Private DNS zones" } while ([string]::IsNullOrWhiteSpace($PrivateDnsZoneRg))
                        $ConfigSummary["Private DNS zones plan"] = "Existing (subscription '$PrivateDnsZoneSubId', resource group '$PrivateDnsZoneRg')"
                    }
                    elseif ($dnsZonesChoice -eq 2) {
                        $PrivateDnsZonesMode = "New"
                        $ConfigSummary["Private DNS zones plan"] = "New (created at install)"
                    }
                    else {
                        # Subscription/RG for the existing zones aren't known yet - nothing to prompt for
                        # and nothing this script can verify against. Note it clearly so it doesn't get
                        # missed before the actual NME POV installation, which needs this to link the zones.
                        $PrivateDnsZonesMode = "Unknown"
                        Write-Host -ForegroundColor "Yellow" "  Since the Private DNS zones' subscription/resource group aren't known yet, this script cannot verify the required Private DNS zones now. Have that information ready before the actual NME POV installation - NME's installer/runbook needs to know which existing zones to link."
                        $ConfigSummary["Private DNS zones plan"] = "Existing zones planned - subscription/resource group not yet known; NOT verified."
                    }
                }
            }
        }
        elseif ($vnetChoice -eq 3) {
            # User intends to use their own existing VNet, but hasn't created it yet - nothing to
            # validate against, so skip straight past the RG/VNet/subnet prompts and the
            # Get-AzVirtualNetwork lookup entirely rather than stalling the whole script on it.
            $TestPrivate = $false
            $TestVnetIntegration = $false
            $VnetInfoUnknown = $true
            Write-Host -ForegroundColor "Yellow" "  Since the VNet's details aren't known yet, private endpoint / VNet integration connectivity cannot be tested now. This will be noted in the report - re-run this script once you have the VNet's resource group, name, and subnet names to validate connectivity before deploying."
        }
        else {
            # New VNet, created by this script alongside the other test resources below. Its name and
            # its two subnets' names go through the same NamePlan editable-name flow as everything else.
            $CreateNewVnet = $true
            $PeSubnetName = "snet-pe"
            $AppSubnetName = "snet-appint"

            # A brand-new VNet has no real DNS configuration to inspect, so (unlike the existing-VNet
            # path, which detects this from the VNet's actual DhcpOptions) we have to ask directly.
            $dnsModeChoice = Read-Choice -Prompt "  Will this VNet use Azure Private DNS Zones to resolve the private endpoints?" -Options @(
                "Azure Private DNS Zones (Azure resolves the privatelink zones)",
                "Custom / on-prem DNS servers (your DNS resolves the privatelink names)"
            ) -Default 1 -Help "NME's private endpoints only work if the privatelink DNS names (e.g. privatelink.database.windows.net) resolve to the private IPs. `r`n`r`n`r`n`r`nAzure Private DNS Zones: Azure hosts those zones and, when linked to the VNet, resolves them automatically - simplest option. `r`n`r`n`r`n`r`nCustom / on-prem DNS: your own DNS servers (set on the VNet) must host or conditionally forward every required privatelink zone; the script will list the exact zones your DNS must resolve. Choose Azure Private DNS Zones unless your organization mandates centralized custom DNS."
            if ($dnsModeChoice -eq 1) {
                $NewVnetDnsMode = "Azure"

                # Existing-vs-new Private DNS zones question (same question/help as the existing-VNet
                # path; here the mode is already known to be Azure, so this always applies).
                $dnsZonesChoice = Read-Choice -Prompt "  Will you use EXISTING Azure Private DNS zones, or have NME/this script create NEW ones?" -Options @(
                    "Use EXISTING Private DNS zones (you provide the subscription + resource group)",
                    "Create NEW Private DNS zones (the installer/runbook creates them at deploy time)",
                    "I don't know yet - will use EXISTING zones but the subscription/resource group aren't known yet"
                ) -Default 2 -Help "NME's private endpoints need these Azure Private DNS zones, linked to the VNet, to resolve to private IPs: privatelink.database.windows.net (SQL), privatelink.vaultcore.azure.net (Key Vault), privatelink.blob.core.windows.net (Storage), privatelink.azurewebsites.net (App Service), privatelink.azure-automation.net (Automation). `r`n`r`n`r`n`r`nEXISTING: your org already manages these zones centrally (common with hub/spoke + Azure Policy auto-registration) - provide the subscription and resource group that holds them, and this script reports which required zones are MISSING there. `r`n`r`n`r`n`r`nNEW: NME's deployment (or the Enable Private Endpoints runbook) creates and links the zones for you - this script only tests that the required zones CAN be created (in the throwaway test resource group) and does NOT link them to your VNet; the real installer/runbook creates and links them at deploy time. (Gov/China clouds use the equivalent .us/.cn zone names, derived automatically.) `r`n`r`n`r`n`r`nIf you'll use EXISTING zones but don't yet know their subscription/resource group, choose the third option - this script will skip the zone verification this run, but you must have that information ready before the actual NME POV installation."
                if ($dnsZonesChoice -eq 1) {
                    $PrivateDnsZonesMode = "Existing"
                    do { $PrivateDnsZoneSubId = Read-Host -Prompt "    Subscription ID where the Azure Private DNS zones live" } while ($PrivateDnsZoneSubId -notmatch "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
                    do { $PrivateDnsZoneRg = Read-Host -Prompt "    Resource group name for the Azure Private DNS zones" } while ([string]::IsNullOrWhiteSpace($PrivateDnsZoneRg))
                    $ConfigSummary["Private DNS zones plan"] = "Existing (subscription '$PrivateDnsZoneSubId', resource group '$PrivateDnsZoneRg')"
                    $ConfigSummary["Private DNS resolution (new VNet)"] = "Azure Private DNS Zones - subscription '$PrivateDnsZoneSubId', resource group '$PrivateDnsZoneRg' (recorded only; not verified or modified by this script)"
                }
                elseif ($dnsZonesChoice -eq 2) {
                    $PrivateDnsZonesMode = "New"
                    $ConfigSummary["Private DNS zones plan"] = "New (created at install)"
                    $ConfigSummary["Private DNS resolution (new VNet)"] = "Azure Private DNS Zones - created at install (this script test-creates the required zones in the throwaway test resource group)"
                }
                else {
                    # Subscription/RG for the existing zones aren't known yet - nothing to prompt for
                    # and nothing this script can verify against. Note it clearly so it doesn't get
                    # missed before the actual NME POV installation, which needs this to link the zones.
                    $PrivateDnsZonesMode = "Unknown"
                    Write-Host -ForegroundColor "Yellow" "  Since the Private DNS zones' subscription/resource group aren't known yet, this script cannot verify the required Private DNS zones now. Have that information ready before the actual NME POV installation - NME's installer/runbook needs to know which existing zones to link."
                    $ConfigSummary["Private DNS zones plan"] = "Existing zones planned - subscription/resource group not yet known; NOT verified."
                    $ConfigSummary["Private DNS resolution (new VNet)"] = "Azure Private DNS Zones - existing zones planned, subscription/resource group not yet known (not verified by this script)"
                }
            }
            else {
                $NewVnetDnsMode = "Custom"
                $zoneList = ($RequiredPrivateDnsZones | ForEach-Object { "$($_.Zone) ($($_.Purpose))" }) -join "; "
                $ConfigSummary["Private DNS resolution (new VNet)"] = "Custom/on-prem DNS - the custom DNS server(s) must resolve: $zoneList"
            }
        }
    }

    Write-Host ""
    #endregion

    #region Resource naming and tags --------------------------------------------------------------
    $rand = New-RandomString -Length 8
    $locSlug = ($Location -replace "[^a-z0-9]", "").ToLower()
    # ZRS is used by the installer in these unpaired regions; GRS everywhere else.
    $ZrsRegions = @("austriaeast", "belgiumcentral", "chilecentral", "indonesiacentral", "israelcentral",
        "italynorth", "malaysiawest", "mexicocentral", "newzealandnorth", "polandcentral", "qatarcentral", "spaincentral")
    $StorageSku = if ($ZrsRegions -contains $locSlug) { "Standard_ZRS" } else { "Standard_GRS" }

    # SQL admin credential. NOTE: the real installer uses Entra-only SQL auth; for a throwaway test we
    # use a SQL admin login/password so we don't need to designate an AAD admin object.
    $sqlChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray()
    $sqlPwd = ((1..48 | ForEach-Object { $sqlChars | Get-Random }) -join "") + "aA1!"
    $sqlLogin = "nmepf$(New-RandomString -Length 8)"
    $sqlCred = New-Object System.Management.Automation.PSCredential($sqlLogin, (ConvertTo-SecureString -String $sqlPwd -AsPlainText -Force))

    # Default names for every resource this run will attempt to create. The resource group is only
    # editable if we're about to create it - an existing, user-supplied RG name is not renameable.
    $NamePlan = [ordered]@{}
    $NamePlan["ResourceGroup"] = [pscustomobject]@{ Label = "Resource Group"; Value = $ResourceGroupName; Editable = $PendingRgCreate }
    $NamePlan["LogAnalytics"] = [pscustomobject]@{ Label = "Log Analytics workspace"; Value = "log-nmepf-$locSlug-$rand"; Editable = $true }
    $NamePlan["Storage"] = [pscustomobject]@{ Label = "Storage account ($StorageSku)"; Value = ("nmepf$rand").Substring(0, [Math]::Min(24, ("nmepf$rand").Length)).ToLower(); Editable = $true }
    $NamePlan["SqlServer"] = [pscustomobject]@{ Label = "SQL Server"; Value = "nmepf-sql-$rand"; Editable = $true }
    $NamePlan["SqlDatabase"] = [pscustomobject]@{ Label = "SQL Database"; Value = "nmepfdb"; Editable = $true }
    $NamePlan["AppServicePlan"] = [pscustomobject]@{ Label = "App Service Plan (B3, Windows)"; Value = "asp-nmepf-$rand"; Editable = $true }
    $kvDefault = "kv-nmepf-$rand"; if ($kvDefault.Length -gt 24) { $kvDefault = $kvDefault.Substring(0, 24) }
    $NamePlan["KeyVault"] = [pscustomobject]@{ Label = "Key Vault"; Value = $kvDefault; Editable = $true }
    # NME deploys two Automation Accounts (an updater account and a scripted-actions account) - test both.
    $NamePlan["AutomationUpdater"] = [pscustomobject]@{ Label = "Automation Account (updater)"; Value = "aa-nmepf-updater-$rand"; Editable = $true }
    $NamePlan["AutomationScriptedActions"] = [pscustomobject]@{ Label = "Automation Account (scripted actions)"; Value = "aa-nmepf-actions-$rand"; Editable = $true }
    if ($CreateNewVnet) {
        $NamePlan["Vnet"] = [pscustomobject]@{ Label = "Virtual Network"; Value = "vnet-nmepf-$rand"; Editable = $true }
        $NamePlan["PeSubnet"] = [pscustomobject]@{ Label = "Subnet (private endpoints)"; Value = $PeSubnetName; Editable = $true }
        $NamePlan["AppSubnet"] = [pscustomobject]@{ Label = "Subnet (App Service VNet integration)"; Value = $AppSubnetName; Editable = $true }
    }
    if ($TestPrivate) {
        $NamePlan["PrivateEndpoint"] = [pscustomobject]@{ Label = "Private Endpoint"; Value = "pe-nmepf-$rand"; Editable = $true }
    }
    if ($TestVnetIntegration) {
        $NamePlan["ConnAsp"] = [pscustomobject]@{ Label = "App Service Plan for connectivity test"; Value = "asp-nmepfconn-$rand"; Editable = $true }
        $NamePlan["ConnWebApp"] = [pscustomobject]@{ Label = "Web App for connectivity test"; Value = "app-nmepfconn-$rand"; Editable = $true }
    }

    Write-Host -ForegroundColor "Cyan" "The following resource names will be used for this test run:"
    foreach ($k in $NamePlan.Keys) { Write-Host ("  {0,-45} {1}" -f $NamePlan[$k].Label, $NamePlan[$k].Value) }
    Write-Host ""

    if (-not (Read-YesNo -Prompt "Use these names? (Choosing 'n' will prompt for custom resource names) [Y/n]" -Default "y")) {
        $namePlanDefaults = [ordered]@{}
        foreach ($k in $NamePlan.Keys) { $namePlanDefaults[$k] = $NamePlan[$k].Value }
        foreach ($k in $NamePlan.Keys) {
            $item = $NamePlan[$k]
            if (-not $item.Editable) { continue }
            $custom = Read-Host -Prompt "  New name for $($item.Label) [default: $($item.Value)]"
            if (-not [string]::IsNullOrWhiteSpace($custom)) {
                # Storage accounts and Key Vaults have restricted, length-limited naming rules.
                if ($k -eq "Storage") { $custom = ($custom -replace "[^a-zA-Z0-9]", "").ToLower(); $custom = $custom.Substring(0, [Math]::Min(24, $custom.Length)) }
                if ($k -eq "KeyVault") { $custom = ($custom -replace "[^a-zA-Z0-9-]", ""); $custom = $custom.Substring(0, [Math]::Min(24, $custom.Length)) }
                $item.Value = $custom
            }
        }
        foreach ($k in $NamePlan.Keys) {
            if ($k -eq "ResourceGroup") { continue }
            if ($NamePlan[$k].Value -ne $namePlanDefaults[$k]) { $CustomResourceNames[$NamePlan[$k].Label] = $NamePlan[$k].Value }
        }
        Write-Host ""
    }

    $ResourceGroupName = $NamePlan["ResourceGroup"].Value
    $lawName = $NamePlan["LogAnalytics"].Value
    $stName = $NamePlan["Storage"].Value
    $sqlName = $NamePlan["SqlServer"].Value
    $dbName = $NamePlan["SqlDatabase"].Value
    $aspName = $NamePlan["AppServicePlan"].Value
    $kvName = $NamePlan["KeyVault"].Value
    $aaUpdaterName = $NamePlan["AutomationUpdater"].Value
    $aaScriptedActionsName = $NamePlan["AutomationScriptedActions"].Value
    if ($TestPrivate) { $peName = $NamePlan["PrivateEndpoint"].Value }
    if ($TestVnetIntegration) { $connAspName = $NamePlan["ConnAsp"].Value; $connWebName = $NamePlan["ConnWebApp"].Value }
    if ($CreateNewVnet) { $NewVnetName = $NamePlan["Vnet"].Value; $PeSubnetName = $NamePlan["PeSubnet"].Value; $AppSubnetName = $NamePlan["AppSubnet"].Value }

    # NmeNetworkTest.ps1 auto-derives Key Vault/SQL/DPS-storage FQDNs only when the App Service name
    # matches the standard "nmw-app-*" pattern. Our test App Service doesn't, so if it's ever run
    # manually against it, it needs -AdditionalTestUris with this run's own resource names.
    $AdditionalTestUrisList = @("$kvName.$KeyVaultSuffix", "$sqlName.$SqlSuffix", "$stName.blob.$StorageSuffix")
    $AdditionalTestUrisArg = ($AdditionalTestUrisList | ForEach-Object { "'$_'" }) -join ","
    $NmeNetworkTestHint = "Run NmeNetworkTest.ps1 with -AdditionalTestUris $AdditionalTestUrisArg (this test App Service's name doesn't match the standard nmw-app-* pattern NmeNetworkTest.ps1 expects)."

    # Tags applied to every resource this script creates (never to a pre-existing resource group).
    # Only user-specified tags are applied - none are added by default.
    $Tags = @{}
    if (Read-YesNo -Prompt "Add custom tags to all resources this script creates? [y/N]" -Default "n" -Help "Required-tag and tag-value Deny policies are a common deployment blocker in customer environments. Testing with the same tags your organization's Azure Policy mandates surfaces those policy blocks now, instead of during the real Nerdio Manager install.") {
        do {
            $tagName = Read-Host -Prompt "  Tag name"
            if ([string]::IsNullOrWhiteSpace($tagName)) { break }
            $tagValue = Read-Host -Prompt "  Tag value"
            $Tags[$tagName] = $tagValue
        } while (Read-YesNo -Prompt "  Add another tag? [y/N]" -Default "n")
    }
    Write-Host ""

    if ($PendingRgCreate) {
        Write-Host -ForegroundColor "Cyan" "Creating temporary resource group '$ResourceGroupName' in '$Location'."
        try {
            New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Tag $Tags -ErrorAction Stop | Out-Null
            $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
        }
        catch {
            # A Deny-effect policy (commonly a required-tag or tag-value policy) can block the resource
            # group creation itself - which is exactly the kind of block this pre-flight exists to
            # surface. Parse the blocking policy out of the ARM error and report it, then stop cleanly
            # (nothing was created, so there's nothing to deploy into). The finally block still prints
            # the report so the SE sees the named policy.
            $rgCreateStart = (Get-Date).ToUniversalTime().AddMinutes(-5)
            $rgErrMsg = $_.Exception.Message
            try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $rgErrMsg = "$rgErrMsg`n$($_.ErrorDetails.Message)" } } catch {}
            try { if ($_.Exception.Response -and $_.Exception.Response.Content) { $rgErrMsg = "$rgErrMsg`n$($_.Exception.Response.Content)" } } catch {}
            try { if ($_.Exception.Body) { $rgErrMsg = "$rgErrMsg`n$($_.Exception.Body | ConvertTo-Json -Depth 10 -Compress)" } } catch {}
            $policyInfo = Get-PolicyFromError -ExceptionMessage $rgErrMsg
            $armDisplayHint = if ($policyInfo.PolicyAssignmentDisplayName) { $policyInfo.PolicyAssignmentDisplayName } elseif ($policyInfo.PolicyDefinitionDisplayName) { $policyInfo.PolicyDefinitionDisplayName } else { $null }
            $policyName = Resolve-PolicyName -PolicyDefinitionId $policyInfo.PolicyDefinitionId -PolicyAssignmentId $policyInfo.PolicyAssignmentId -PolicySetDefinitionId $policyInfo.PolicySetDefinitionId -DisplayNameHint $armDisplayHint
            $policySource = if ($policyName -and $policyName -ne $policyInfo.PolicyDefinitionId -and $policyName -ne $policyInfo.PolicyAssignmentId) { "the ARM error" } else { $null }

            # New-AzResourceGroup's RequestDisallowedByPolicy error usually omits the policy identifiers,
            # so fall back to the Activity Log, which records the denied operation with the policy name.
            if (-not $policySource) {
                Write-Host -ForegroundColor "Yellow" "  Resource group creation was blocked by policy. Querying the Activity Log for the specific policy - this can take up to 5 minutes while Azure ingests the event..."
                $al = Get-PolicyFromActivityLog -ResourceGroupName $ResourceGroupName -StartTime $rgCreateStart
                if ($al.Found) {
                    $alDisplayHint = if ($al.PolicyAssignmentName) { $al.PolicyAssignmentName } elseif ($al.PolicyDefinitionName) { $al.PolicyDefinitionName } else { $null }
                    $alName = Resolve-PolicyName -PolicyDefinitionId $al.PolicyDefinitionId -PolicyAssignmentId $al.PolicyAssignmentId -PolicySetDefinitionId $al.PolicySetDefinitionId -DisplayNameHint $alDisplayHint
                    if ($alName -and $alName -ne $al.PolicyDefinitionId -and $alName -ne $al.PolicyAssignmentId) {
                        $policyName = $alName
                        $policySource = "the Activity Log"
                    }
                    if (-not $policyInfo.PolicyDefinitionId) { $policyInfo.PolicyDefinitionId = $al.PolicyDefinitionId }
                    if (-not $policyInfo.PolicyAssignmentId) { $policyInfo.PolicyAssignmentId = $al.PolicyAssignmentId }
                }
            }

            $detail = if ($policySource) {
                "Blocked by Azure Policy '$policyName' (identified via $policySource). The resource group could not be created$(if ($Tags.Count -gt 0) { ' - review the tags you supplied against required-tag/tag-value policies' })."
            }
            elseif ($policyName) {
                "Blocked by Azure Policy id '$policyName' (display name could not be resolved). The resource group could not be created$(if ($Tags.Count -gt 0) { ' - review the tags you supplied against required-tag/tag-value policies' })."
            }
            else {
                "The resource group could not be created$(if ($Tags.Count -gt 0) { ' (this often indicates a required-tag/tag-value Deny policy - review the supplied tags)' }). Could not identify the specific policy from the ARM error or the Activity Log after waiting up to 5 minutes for ingestion - check the Activity Log manually for '$ResourceGroupName'."
            }
            Add-Result -Category "Deployability" -Check "Resource group creation" -Result "Fail" -Detail $detail -PolicyName $policyName -Message (Get-ConciseErrorMessage -RawMessage $rgErrMsg) -RawMessage $rgErrMsg
            # We return before the ConfigSummary is normally populated, so record enough here that the
            # report still shows the SE what was attempted.
            $ConfigSummary["Run by (signed-in account)"] = $SignedInAccountMasked
            $ConfigSummary["Subscription"] = "$($Context.Subscription.Name) ($SubscriptionId)"
            $ConfigSummary["Cloud"] = $AzEnv.Name
            $ConfigSummary["Region"] = $Location
            $ConfigSummary["Resource group"] = "$ResourceGroupName (creation blocked)"
            $ConfigSummary["Tags applied"] = if ($Tags.Count -gt 0) { (($Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; ") } else { "(none specified)" }
            if ($policyName) { $ConfigSummary["Blocking policy"] = $policyName }
            if ($policyInfo.PolicyAssignmentId) { $ConfigSummary["Blocking policy assignment id"] = $policyInfo.PolicyAssignmentId }
            # Nothing was actually created, so don't offer to remove a resource group that doesn't exist.
            $CreatedResourceGroup = $false
            Write-Host -ForegroundColor "Red" "Cannot continue without a resource group. Skipping the remaining tests and printing the report."
            return
        }
    }
    Write-Host ""

    if ($CreateNewVnet) {
        Write-Host -ForegroundColor "Cyan" "Creating VNet '$NewVnetName' with a private endpoint subnet and an App Service integration subnet."
        $peSubnetConfig = New-AzVirtualNetworkSubnetConfig -Name $PeSubnetName -AddressPrefix "10.60.1.0/24"
        # Only the App Service integration subnet needs the serverFarms delegation - a subnet delegated
        # to it cannot also host private endpoints, which is why the two subnets are always distinct.
        $appDelegation = New-AzDelegation -Name "appServiceDelegation" -ServiceName "Microsoft.Web/serverFarms"
        $appSubnetConfig = New-AzVirtualNetworkSubnetConfig -Name $AppSubnetName -AddressPrefix "10.60.2.0/24" -Delegation $appDelegation
        $newVnet = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $NewVnetName -Location $Location -AddressPrefix "10.60.0.0/16" -Subnet $peSubnetConfig, $appSubnetConfig -Tag $Tags -ErrorAction Stop
        Add-TrackedResource -Type "vnet" -ResourceGroupName $ResourceGroupName -Name $NewVnetName -Id $newVnet.Id
        $ExistingVnetRg = $ResourceGroupName
        $ExistingVnetName = $NewVnetName
    }
    Write-Host ""

    # Record every input/response so the SE has a confirmed-working configuration to refer back to
    # once it's time to actually install NME.
    $ConfigSummary["Run by (signed-in account)"] = $SignedInAccountMasked
    $ConfigSummary["Subscription"] = "$($Context.Subscription.Name) ($SubscriptionId)"
    $ConfigSummary["Cloud"] = $AzEnv.Name
    $ConfigSummary["Region"] = $Location
    $ConfigSummary["Resource group"] = "$ResourceGroupName $(if ($PendingRgCreate) { '(created by this script)' } else { '(existing, user-supplied)' })"
    if ($Tags.Count -gt 0) { $ConfigSummary["Tags applied"] = (($Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; ") } else { $ConfigSummary["Tags applied"] = "(none specified)" }
    if ($PrivateEndpointOnly) { $ConfigSummary["Public network access on create"] = "Disabled (-PrivateEndpointOnly): Storage, SQL, and Key Vault created with public network access disabled" }
    if ($VnetInfoUnknown) {
        $ConfigSummary["Private endpoint scenario"] = "Planned - existing VNet, details not yet known; NOT tested. Re-run this script once VNet details are known."
    }
    elseif ($TestPrivate) {
        $ConfigSummary["Private endpoint scenario"] = "Yes - $(if ($CreateNewVnet) { 'new' } else { 'existing' }) VNet, 4 test private endpoints (SQL, Key Vault, Storage, Automation)"
        $ConfigSummary["$(if ($CreateNewVnet) { 'New' } else { 'Existing' }) VNet"] = "'$ExistingVnetName'"
        $ConfigSummary["VNet RG"] = "'$ExistingVnetRg'"
        $ConfigSummary["Private endpoint subnet"] = "'$PeSubnetName'"
    }
    else {
        $ConfigSummary["Private endpoint scenario"] = "Not tested"
    }
    $ConfigSummary["App Service VNet integration"] = if ($VnetInfoUnknown) { "Planned - existing VNet, details not yet known; NOT tested." } elseif ($TestVnetIntegration) { "Yes" } else { "Not tested" }
    if ($TestVnetIntegration) {
        $ConfigSummary["Web app subnet"] = "'$AppSubnetName'"
    }
    $ConfigSummary["VNet DNS configuration"] = "Not tested"
    #endregion

    #region Fast checks --------------------------------------------------------------------------
    Write-Host -ForegroundColor "Cyan" "Running permission check..."

    # Entra directory roles WITHOUT the Microsoft.Graph module.
    # Invoke-AzRestMethod (Az.Accounts) reuses the existing Connect-AzAccount token and calls Graph
    # REST directly, sidestepping the Microsoft.Graph module which is frequently blocked/broken.
    try {
        $uri = "$GraphBase/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?`$select=displayName,roleTemplateId"
        $resp = Invoke-AzRestMethod -Uri $uri -Method GET -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            $roles = ($resp.Content | ConvertFrom-Json).value
            $templateIds = @($roles.roleTemplateId)
            $GA = "62e90394-69f5-4237-9190-012177145e10"
            $PRA = "e8611ab8-c189-46e8-94e1-60213ab1f814"
            $CAA = "158c047a-c907-4556-b7ef-446551a6b5f7"
            $roleNames = ($roles.displayName | Sort-Object -Unique) -join ", "
            if ($templateIds -contains $GA) {
                Add-Result -Category "Permissions" -Check "Entra role for install" -Result "Pass" -Detail "User has Global Administrator."
            }
            elseif (($templateIds -contains $PRA) -and ($templateIds -contains $CAA)) {
                Add-Result -Category "Permissions" -Check "Entra role for install" -Result "Pass" -Detail "User has Privileged Role Administrator + Cloud Application Administrator."
            }
            else {
                Add-Result -Category "Permissions" -Check "Entra role for install" -Result "Warn" -Detail "Missing Global Administrator (or Privileged Role Administrator + Cloud Application Administrator). Roles found: $($roleNames)."
            }
        }
        else {
            Add-Result -Category "Permissions" -Check "Entra role for install" -Result "Warn" -Detail "Could not read Entra roles (Graph returned HTTP $($resp.StatusCode)). The tenant may restrict Microsoft Graph; verify roles manually." -Message ($resp.Content)
        }
    }
    catch {
        Add-Result -Category "Permissions" -Check "Entra role for install" -Result "Warn" -Detail "Could not read Entra roles via Graph REST. The tenant may restrict Microsoft Graph; verify roles manually." -Message $_.Exception.Message
    }

    # Azure Owner on the subscription (required to install).
    # Prefer the real Entra object id resolved via Graph above; Account.Id is unreliable in Cloud
    # Shell (reports "MSI@<port>" instead of the user's UPN), which would fail -SignInName lookups.
    $subScope = "/subscriptions/$SubscriptionId"
    $principalParam = if ($meObjectId) { @{ ObjectId = $meObjectId } } else { @{ SignInName = $SignedInAccount } }

    # Roles checked for: Owner (sufficient alone), or Contributor + User Access Administrator, which
    # together are functionally equivalent to Owner for install purposes (Contributor covers
    # resource create/manage, User Access Administrator covers the role-assignment writes NME needs).
    $relevantRoles = @("Owner", "Contributor", "User Access Administrator")

    $direct = $null
    $directError = $null
    try {
        $direct = Get-AzRoleAssignment @principalParam -Scope $subScope -ErrorAction Stop | Where-Object { $_.RoleDefinitionName -in $relevantRoles }
    }
    catch {
        $directError = $_.Exception.Message
    }

    $viaGroup = $null
    $viaGroupError = $null
    try {
        $viaGroup = Get-AzRoleAssignment @principalParam -Scope $subScope -ExpandPrincipalGroups -ErrorAction Stop | Where-Object { $_.RoleDefinitionName -in $relevantRoles }
    }
    catch {
        $viaGroupError = $_.Exception.Message
    }

    $directOwner = $direct | Where-Object { $_.RoleDefinitionName -eq "Owner" }
    $viaGroupOwner = $viaGroup | Where-Object { $_.RoleDefinitionName -eq "Owner" }

    if ($directOwner) {
        Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Pass" -Detail "Directly assigned Owner."
    }
    elseif ($viaGroupOwner) {
        Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Pass" -Detail "Owner via group membership."
    }
    elseif ($directError -and $viaGroupError) {
        Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Warn" -Detail "Could not evaluate subscription role assignments." -Message "$directError | $viaGroupError"
    }
    else {
        # Owner ruled out; at least one query returned data. Evaluate the Contributor + User Access
        # Administrator combo across whatever succeeded (both, or just the one that didn't error - a
        # partial failure, e.g. -ExpandPrincipalGroups needing extra rights, must not discard the
        # direct data). If only one query errored and the combo wasn't found, note the evaluation may
        # be incomplete rather than reporting a clean "not present".
        $allAssignments = @($direct) + @($viaGroup)
        $hasContributor = [bool]($allAssignments | Where-Object { $_.RoleDefinitionName -eq "Contributor" })
        $hasUaa = [bool]($allAssignments | Where-Object { $_.RoleDefinitionName -eq "User Access Administrator" })
        $partialErr = if ($directError) { $directError } elseif ($viaGroupError) { $viaGroupError } else { $null }
        $partialNote = if ($partialErr) { " One role query failed, so this may be incomplete." } else { "" }

        if ($hasContributor -and $hasUaa) {
            Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Pass" -Detail "Contributor + User Access Administrator (functionally equivalent to Owner for install).$partialNote" -Message $partialErr
        }
        elseif ($hasContributor) {
            Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Warn" -Detail "Have Contributor but missing User Access Administrator; need Owner, or Contributor + User Access Administrator, to install.$partialNote" -Message $partialErr
        }
        elseif ($hasUaa) {
            Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Warn" -Detail "Have User Access Administrator but missing Contributor; need Owner, or Contributor + User Access Administrator, to install.$partialNote" -Message $partialErr
        }
        else {
            Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Warn" -Detail "Owner not detected on the subscription (or you are a guest). Owner (or Contributor + User Access Administrator) is required to install Nerdio Manager.$partialNote" -Message $partialErr
        }
    }

    # Resource providers.
    # Providers the installer template deploys, plus the ones NME needs to operate post-install
    # (Compute = session-host VMs, DesktopVirtualization = AVD host pools, RecoveryServices = backup).
    Write-Host -ForegroundColor "Cyan" -NoNewline "Running resource provider check..."
    $ResourceProviders = @("Microsoft.KeyVault", "Microsoft.Automation", "Microsoft.Compute",
        "Microsoft.DesktopVirtualization", "Microsoft.Insights",
        "Microsoft.Network", "Microsoft.OperationalInsights", "Microsoft.RecoveryServices",
        "Microsoft.Storage", "Microsoft.Sql", "Microsoft.Web")
    # Fan the provider registration-state reads out concurrently (one ThreadJob per provider), then
    # process results on the main thread in the original order so console/report ordering stays stable.
    $rpJobs = @()
    foreach ($rp in $ResourceProviders) {
        $rpJobs += Start-ThreadJob -Name "Rp-$rp" -ScriptBlock {
            param($rp)
            try {
                $state = (Get-AzResourceProvider -ProviderNamespace $rp -ErrorAction Stop | Select-Object -First 1).RegistrationState
                @{ Rp = $rp; Ok = $true; State = $state }
            }
            catch {
                @{ Rp = $rp; Ok = $false; Error = $_.Exception.Message }
            }
        } -ArgumentList $rp
    }
    # Wait-Job blocks silently until every job finishes, which can take a while - poll instead so a
    # dot can be printed every couple seconds to show the check is still alive. Wait for every job to
    # reach a terminal state, not just to leave Running: ThreadJob's default throttle (5) leaves the
    # remaining providers queued in NotStarted, and right after creation none may be Running yet - so
    # a "while any Running" loop would exit immediately and Receive-Job would return nothing.
    while ($rpJobs | Where-Object { $_.State -notin @("Completed", "Failed", "Stopped") }) {
        Start-Sleep -Seconds 2
        Write-Host -ForegroundColor "Cyan" -NoNewline "."
    }
    Write-Host ""
    $rpJobResults = $rpJobs | Receive-Job
    $rpJobs | Remove-Job -Force -ErrorAction SilentlyContinue
    foreach ($rp in $ResourceProviders) {
        $rr = $rpJobResults | Where-Object { $_.Rp -eq $rp } | Select-Object -First 1
        if ($rr -and $rr.Ok) {
            if ($rr.State -eq "Registered") { Add-Result -Category "ResourceProviders" -Check $rp -Result "Pass" -Detail "Registered." }
            else { Add-Result -Category "ResourceProviders" -Check $rp -Result "Warn" -Detail "Not registered (state: $($rr.State)). Register before installing." }
        }
        else {
            $rpErr = if ($rr) { $rr.Error } else { "No result returned from the registration-state query job." }
            Add-Result -Category "ResourceProviders" -Check $rp -Result "Warn" -Detail "Could not query registration state." -Message $rpErr
        }
    }

    # NOTE: a read-only Azure Resource Graph scan for Deny-effect policy assignments used to run here.
    # It was removed - in practice it surfaced noise (Deny assignments that never targeted NME resource
    # types) without catching real blocks. Blocking policies are instead detected authoritatively by the
    # Deployability tests below, which report the actual blocking policy by name when a deploy is denied.
    Write-Host ""
    #endregion

    #region Deployability tests (parallel) -------------------------------------------------------
    Write-Host -ForegroundColor "Cyan" "Testing resource deployability. This will take several minutes..."

    # -PrivateEndpointOnly forces the resources that support a create-time public-access flag (Storage,
    # SQL, Key Vault) to deploy with public network access disabled from the start, for environments
    # that reject public-endpoint creation outright.
    $pna = if ($PrivateEndpointOnly) { "Disabled" } else { "Enabled" }

    # Each job returns @{ Target; Ok; Error }. Az context is shared into the thread via -UseNewRunspace:$false default of ThreadJob.
    $jobs = @()

    $jobs += Start-ThreadJob -Name "LogAnalytics" -ScriptBlock {
        param($rg, $name, $loc, $tags)
        try { New-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $name -Location $loc -Sku "PerGB2018" -RetentionInDays 30 -Tag $tags -ErrorAction Stop | Out-Null; @{ Target = "Log Analytics workspace"; Ok = $true; Name = $name; Kind = "law" } }
        catch {
            $errMsg = $_.Exception.Message
            try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errMsg = "$errMsg`n$($_.ErrorDetails.Message)" } } catch {}
            # Track1 SDK cmdlets (Microsoft.Rest.ClientRuntime, e.g. Az.Storage/Az.Websites/Az.Automation)
            # throw HttpOperationException with a generic "Operation returned an invalid status code"
            # Message - the actual JSON body (with the policy details) is only on .Response.Content/.Body.
            try { if ($_.Exception.Response -and $_.Exception.Response.Content) { $errMsg = "$errMsg`n$($_.Exception.Response.Content)" } } catch {}
            try { if ($_.Exception.Body) { $errMsg = "$errMsg`n$($_.Exception.Body | ConvertTo-Json -Depth 10 -Compress)" } } catch {}
            @{ Target = "Log Analytics workspace"; Ok = $false; Error = $errMsg; Name = $name; Kind = "law" }
        }
    } -ArgumentList $ResourceGroupName, $lawName, $Location, $Tags

    $jobs += Start-ThreadJob -Name "Storage" -ScriptBlock {
        param($rg, $name, $loc, $sku, $tags, $pna)
        try {
            New-AzStorageAccount -ResourceGroupName $rg -Name $name -Location $loc -SkuName $sku -Kind "StorageV2" -AccessTier "Hot" `
                -MinimumTlsVersion "TLS1_2" -AllowBlobPublicAccess $false -AllowSharedKeyAccess $true -EnableHttpsTrafficOnly $true -PublicNetworkAccess $pna -Tag $tags -ErrorAction Stop | Out-Null
            @{ Target = "Storage account ($sku)"; Ok = $true; Name = $name; Kind = "storage" }
        }
        catch {
            $errMsg = $_.Exception.Message
            try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errMsg = "$errMsg`n$($_.ErrorDetails.Message)" } } catch {}
            # Track1 SDK cmdlets (Microsoft.Rest.ClientRuntime, e.g. Az.Storage/Az.Websites/Az.Automation)
            # throw HttpOperationException with a generic "Operation returned an invalid status code"
            # Message - the actual JSON body (with the policy details) is only on .Response.Content/.Body.
            try { if ($_.Exception.Response -and $_.Exception.Response.Content) { $errMsg = "$errMsg`n$($_.Exception.Response.Content)" } } catch {}
            try { if ($_.Exception.Body) { $errMsg = "$errMsg`n$($_.Exception.Body | ConvertTo-Json -Depth 10 -Compress)" } } catch {}
            @{ Target = "Storage account ($sku)"; Ok = $false; Error = $errMsg; Name = $name; Kind = "storage" }
        }
    } -ArgumentList $ResourceGroupName, $stName, $Location, $StorageSku, $Tags, $pna

    $jobs += Start-ThreadJob -Name "Sql" -ScriptBlock {
        param($rg, $name, $loc, $cred, $tags, $pna)
        try {
            New-AzSqlServer -ResourceGroupName $rg -ServerName $name -Location $loc -ServerVersion "12.0" -MinimalTlsVersion "1.2" `
                -PublicNetworkAccess $pna -SqlAdministratorCredentials $cred -Tag $tags -ErrorAction Stop | Out-Null
            @{ Target = "SQL Server"; Ok = $true; Name = $name; Kind = "sqlserver" }
        }
        catch {
            $errMsg = $_.Exception.Message
            try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errMsg = "$errMsg`n$($_.ErrorDetails.Message)" } } catch {}
            # Track1 SDK cmdlets (Microsoft.Rest.ClientRuntime, e.g. Az.Storage/Az.Websites/Az.Automation)
            # throw HttpOperationException with a generic "Operation returned an invalid status code"
            # Message - the actual JSON body (with the policy details) is only on .Response.Content/.Body.
            try { if ($_.Exception.Response -and $_.Exception.Response.Content) { $errMsg = "$errMsg`n$($_.Exception.Response.Content)" } } catch {}
            try { if ($_.Exception.Body) { $errMsg = "$errMsg`n$($_.Exception.Body | ConvertTo-Json -Depth 10 -Compress)" } } catch {}
            @{ Target = "SQL Server"; Ok = $false; Error = $errMsg; Name = $name; Kind = "sqlserver" }
        }
    } -ArgumentList $ResourceGroupName, $sqlName, $Location, $sqlCred, $Tags, $pna

    $jobs += Start-ThreadJob -Name "AppServicePlan" -ScriptBlock {
        param($rg, $name, $loc, $tags)
        try {
            # B3 == Basic tier, Large worker, Windows (reserved = false). Match the installer's App Service Plan.
            New-AzAppServicePlan -ResourceGroupName $rg -Name $name -Location $loc -Tier "Basic" -WorkerSize "Large" -NumberOfWorkers 1 -Tag $tags -ErrorAction Stop | Out-Null
            @{ Target = "App Service Plan (B3, Windows)"; Ok = $true; Name = $name; Kind = "asp" }
        }
        catch {
            $errMsg = $_.Exception.Message
            try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errMsg = "$errMsg`n$($_.ErrorDetails.Message)" } } catch {}
            # Track1 SDK cmdlets (Microsoft.Rest.ClientRuntime, e.g. Az.Storage/Az.Websites/Az.Automation)
            # throw HttpOperationException with a generic "Operation returned an invalid status code"
            # Message - the actual JSON body (with the policy details) is only on .Response.Content/.Body.
            try { if ($_.Exception.Response -and $_.Exception.Response.Content) { $errMsg = "$errMsg`n$($_.Exception.Response.Content)" } } catch {}
            try { if ($_.Exception.Body) { $errMsg = "$errMsg`n$($_.Exception.Body | ConvertTo-Json -Depth 10 -Compress)" } } catch {}
            @{ Target = "App Service Plan (B3, Windows)"; Ok = $false; Error = $errMsg; Name = $name; Kind = "asp" }
        }
    } -ArgumentList $ResourceGroupName, $aspName, $Location, $Tags

    $jobs += Start-ThreadJob -Name "KeyVault" -ScriptBlock {
        param($rg, $name, $loc, $tags, $pna)
        try {
            $kvParams = @{ ResourceGroupName = $rg; VaultName = $name; Location = $loc; Sku = "Standard"; SoftDeleteRetentionInDays = 90; DisableRbacAuthorization = $true; Tag = $tags; ErrorAction = "Stop" }
            if ($pna -eq "Disabled") {
                try { New-AzKeyVault @kvParams -PublicNetworkAccess "Disabled" | Out-Null }
                catch {
                    # Only fall back for the specific "older Az.KeyVault has no -PublicNetworkAccess on
                    # create" case, identified by PowerShell's canonical parameter-binding error. Do NOT
                    # match on the bare property name "publicNetworkAccess" - an Azure Policy DENIAL message
                    # references that property too, and treating a real policy block as a missing-parameter
                    # would (briefly) create a public Key Vault instead of surfacing the block as a Fail.
                    if ($_.Exception -is [System.Management.Automation.ParameterBindingException] -or "$($_.Exception.Message)" -match "A parameter cannot be found that matches parameter name") {
                        New-AzKeyVault @kvParams | Out-Null
                        Update-AzKeyVault -VaultName $name -ResourceGroupName $rg -PublicNetworkAccess "Disabled" -ErrorAction Stop | Out-Null
                    }
                    else { throw }
                }
            }
            else { New-AzKeyVault @kvParams | Out-Null }
            @{ Target = "Key Vault"; Ok = $true; Name = $name; Kind = "kv" }
        }
        catch {
            $errMsg = $_.Exception.Message
            try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errMsg = "$errMsg`n$($_.ErrorDetails.Message)" } } catch {}
            # Track1 SDK cmdlets (Microsoft.Rest.ClientRuntime, e.g. Az.Storage/Az.Websites/Az.Automation)
            # throw HttpOperationException with a generic "Operation returned an invalid status code"
            # Message - the actual JSON body (with the policy details) is only on .Response.Content/.Body.
            try { if ($_.Exception.Response -and $_.Exception.Response.Content) { $errMsg = "$errMsg`n$($_.Exception.Response.Content)" } } catch {}
            try { if ($_.Exception.Body) { $errMsg = "$errMsg`n$($_.Exception.Body | ConvertTo-Json -Depth 10 -Compress)" } } catch {}
            @{ Target = "Key Vault"; Ok = $false; Error = $errMsg; Name = $name; Kind = "kv" }
        }
    } -ArgumentList $ResourceGroupName, $kvName, $Location, $Tags, $pna

    # NME deploys two Automation Accounts (an updater account with a system-assigned identity, and a
    # scripted-actions account with no identity) - test both, matching the installer template.
    $jobs += Start-ThreadJob -Name "AutomationUpdater" -ScriptBlock {
        param($rg, $name, $loc, $tags)
        try {
            New-AzAutomationAccount -ResourceGroupName $rg -Name $name -Location $loc -Plan "Basic" -AssignSystemIdentity -Tag $tags -ErrorAction Stop | Out-Null
            @{ Target = "Automation Account (updater)"; Ok = $true; Name = $name; Kind = "automation" }
        }
        catch {
            $errMsg = $_.Exception.Message
            try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errMsg = "$errMsg`n$($_.ErrorDetails.Message)" } } catch {}
            # Track1 SDK cmdlets (Microsoft.Rest.ClientRuntime, e.g. Az.Storage/Az.Websites/Az.Automation)
            # throw HttpOperationException with a generic "Operation returned an invalid status code"
            # Message - the actual JSON body (with the policy details) is only on .Response.Content/.Body.
            try { if ($_.Exception.Response -and $_.Exception.Response.Content) { $errMsg = "$errMsg`n$($_.Exception.Response.Content)" } } catch {}
            try { if ($_.Exception.Body) { $errMsg = "$errMsg`n$($_.Exception.Body | ConvertTo-Json -Depth 10 -Compress)" } } catch {}
            @{ Target = "Automation Account (updater)"; Ok = $false; Error = $errMsg; Name = $name; Kind = "automation" }
        }
    } -ArgumentList $ResourceGroupName, $aaUpdaterName, $Location, $Tags

    $jobs += Start-ThreadJob -Name "AutomationScriptedActions" -ScriptBlock {
        param($rg, $name, $loc, $tags)
        try {
            New-AzAutomationAccount -ResourceGroupName $rg -Name $name -Location $loc -Plan "Basic" -Tag $tags -ErrorAction Stop | Out-Null
            @{ Target = "Automation Account (scripted actions)"; Ok = $true; Name = $name; Kind = "automation" }
        }
        catch {
            $errMsg = $_.Exception.Message
            try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errMsg = "$errMsg`n$($_.ErrorDetails.Message)" } } catch {}
            # Track1 SDK cmdlets (Microsoft.Rest.ClientRuntime, e.g. Az.Storage/Az.Websites/Az.Automation)
            # throw HttpOperationException with a generic "Operation returned an invalid status code"
            # Message - the actual JSON body (with the policy details) is only on .Response.Content/.Body.
            try { if ($_.Exception.Response -and $_.Exception.Response.Content) { $errMsg = "$errMsg`n$($_.Exception.Response.Content)" } } catch {}
            try { if ($_.Exception.Body) { $errMsg = "$errMsg`n$($_.Exception.Body | ConvertTo-Json -Depth 10 -Compress)" } } catch {}
            @{ Target = "Automation Account (scripted actions)"; Ok = $false; Error = $errMsg; Name = $name; Kind = "automation" }
        }
    } -ArgumentList $ResourceGroupName, $aaScriptedActionsName, $Location, $Tags

    $jobResults = $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job -Force -ErrorAction SilentlyContinue

    foreach ($jr in $jobResults) {
        if ($jr.Ok) {
            Add-Result -Category "Deployability" -Check $jr.Target -Result "Pass" -Detail "Created successfully."
            Add-TrackedResource -Type $jr.Kind -ResourceGroupName $ResourceGroupName -Name $jr.Name
            if ($jr.Kind -eq "kv") {
                New-PreflightLock -ResourceId "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$($jr.Name)" -LockName "$($jr.Name)-lock" -Label "Key Vault"
            }
            elseif ($jr.Kind -eq "storage") {
                New-PreflightLock -ResourceId "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$($jr.Name)" -LockName "$($jr.Name)-lock" -Label "Storage account"
            }
        }
        else {
            $p = Get-PolicyFromError -ExceptionMessage $jr.Error
            $pDisplayHint = if ($p.PolicyAssignmentDisplayName) { $p.PolicyAssignmentDisplayName } elseif ($p.PolicyDefinitionDisplayName) { $p.PolicyDefinitionDisplayName } else { $null }
            $polName = Resolve-PolicyName -PolicyDefinitionId $p.PolicyDefinitionId -PolicyAssignmentId $p.PolicyAssignmentId -PolicySetDefinitionId $p.PolicySetDefinitionId -DisplayNameHint $pDisplayHint
            $concise = Get-ConciseErrorMessage -RawMessage $jr.Error
            $detail = if ($polName) { "Blocked by Azure Policy: '$polName'." } else { "Failed: $concise" }
            Add-Result -Category "Deployability" -Check $jr.Target -Result "Fail" -Detail $detail -PolicyName $polName -Message $concise -RawMessage $jr.Error
        }
    }

    # Simulate the brief Key Vault public-endpoint enable the standard install performs (to write
    # secrets) before locking it back down. An Azure Policy that denies enabling KV public network
    # access would block the install even though the final state is compliant - this surfaces that
    # up front. Runs whenever the KV was created (not gated on -TestPrivate): every standard install
    # does this toggle, and the check is cheap (two control-plane updates).
    $kvOk = ($jobResults | Where-Object { $_.Kind -eq "kv" -and $_.Ok })
    if ($kvOk) {
        # Put the KV in its hardened end-state first (best-effort; not the check we care about).
        try { Update-AzKeyVault -VaultName $kvName -ResourceGroupName $ResourceGroupName -PublicNetworkAccess "Disabled" -ErrorAction Stop | Out-Null } catch {}
        try {
            # The actual check: can the install's "briefly enable public access" step succeed.
            Update-AzKeyVault -VaultName $kvName -ResourceGroupName $ResourceGroupName -PublicNetworkAccess "Enabled" -ErrorAction Stop | Out-Null
            Add-Result -Category "Deployability" -Check "Key Vault temporary public access (confirmed allowed)" -Result "Pass"
        }
        catch {
            $kvToggleErrMsg = $_.Exception.Message
            try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $kvToggleErrMsg = "$kvToggleErrMsg`n$($_.ErrorDetails.Message)" } } catch {}
            try { if ($_.Exception.Response -and $_.Exception.Response.Content) { $kvToggleErrMsg = "$kvToggleErrMsg`n$($_.Exception.Response.Content)" } } catch {}
            try { if ($_.Exception.Body) { $kvToggleErrMsg = "$kvToggleErrMsg`n$($_.Exception.Body | ConvertTo-Json -Depth 10 -Compress)" } } catch {}
            if ($_.Exception -is [System.Management.Automation.ParameterBindingException] -or $kvToggleErrMsg -match "A parameter cannot be found") {
                Add-Result -Category "Deployability" -Check "Key Vault temporary public access (install step)" -Result "Warn" -Detail "Could not simulate - Update-AzKeyVault -PublicNetworkAccess not available in this Az version."
            }
            else {
                $p = Get-PolicyFromError -ExceptionMessage $kvToggleErrMsg
                $pDisplayHint = if ($p.PolicyAssignmentDisplayName) { $p.PolicyAssignmentDisplayName } elseif ($p.PolicyDefinitionDisplayName) { $p.PolicyDefinitionDisplayName } else { $null }
                $polName = Resolve-PolicyName -PolicyDefinitionId $p.PolicyDefinitionId -PolicyAssignmentId $p.PolicyAssignmentId -PolicySetDefinitionId $p.PolicySetDefinitionId -DisplayNameHint $pDisplayHint
                $concise = Get-ConciseErrorMessage -RawMessage $kvToggleErrMsg
                $detail = if ($polName) { "Blocked by Azure Policy: '$polName'." } else { "Failed: $concise" }
                Add-Result -Category "Deployability" -Check "Key Vault temporary public access (install step)" -Result "Fail" -Detail $detail -PolicyName $polName -Message $concise -RawMessage $kvToggleErrMsg
            }
        }
        # Revert to the hardened end-state (best-effort/cosmetic; the KV is deleted at cleanup anyway).
        try { Update-AzKeyVault -VaultName $kvName -ResourceGroupName $ResourceGroupName -PublicNetworkAccess "Disabled" -ErrorAction Stop | Out-Null } catch {}
    }

    # SQL database (depends on SQL server having been created).
    $sqlOk = ($jobResults | Where-Object { $_.Kind -eq "sqlserver" -and $_.Ok })
    if ($sqlOk) {
        try {
            New-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $sqlName -DatabaseName $dbName `
                -Edition "Standard" -RequestedServiceObjectiveName "S1" -CollationName "SQL_Latin1_General_CP1_CI_AS" -Tag $Tags -ErrorAction Stop | Out-Null
            Add-Result -Category "Deployability" -Check "SQL Database (Standard S1, DTU)" -Result "Pass" -Detail "Created successfully."
            Add-TrackedResource -Type "sqldatabase" -ResourceGroupName $ResourceGroupName -Name $dbName -Note $sqlName
            New-PreflightLock -ResourceId "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers/$sqlName/databases/$dbName" -LockName "$dbName-lock" -Label "SQL Database"
        }
        catch {
            $sqlErrMsg = $_.Exception.Message
            try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $sqlErrMsg = "$sqlErrMsg`n$($_.ErrorDetails.Message)" } } catch {}
            try { if ($_.Exception.Response -and $_.Exception.Response.Content) { $sqlErrMsg = "$sqlErrMsg`n$($_.Exception.Response.Content)" } } catch {}
            try { if ($_.Exception.Body) { $sqlErrMsg = "$sqlErrMsg`n$($_.Exception.Body | ConvertTo-Json -Depth 10 -Compress)" } } catch {}
            $p = Get-PolicyFromError -ExceptionMessage $sqlErrMsg
            $pDisplayHint = if ($p.PolicyAssignmentDisplayName) { $p.PolicyAssignmentDisplayName } elseif ($p.PolicyDefinitionDisplayName) { $p.PolicyDefinitionDisplayName } else { $null }
            $polName = Resolve-PolicyName -PolicyDefinitionId $p.PolicyDefinitionId -PolicyAssignmentId $p.PolicyAssignmentId -PolicySetDefinitionId $p.PolicySetDefinitionId -DisplayNameHint $pDisplayHint
            $concise = Get-ConciseErrorMessage -RawMessage $sqlErrMsg
            $detail = if ($polName) { "Blocked by Azure Policy: '$polName'." } else { "Failed: $concise" }
            Add-Result -Category "Deployability" -Check "SQL Database (Standard S1, DTU)" -Result "Fail" -Detail $detail -PolicyName $polName -Message $concise -RawMessage $sqlErrMsg
        }
    }
    else {
        Add-Result -Category "Deployability" -Check "SQL Database (Standard S1, DTU)" -Result "Warn" -Detail "Skipped - SQL Server was not created."
    }
    Write-Host ""
    #endregion

    # If the customer intends a private VNet but didn't have the VNet/subnet details at intake, the
    # private endpoint / DNS / VNet-integration checks can't run - surface that as WARN (not an
    # implicit PASS from simply skipping them) so the report flags the still-to-validate work.
    if ($VnetInfoUnknown) {
        Add-Result -Category "PrivateEndpoint" -Check "Private endpoint deployment" -Result "Warn" -Detail "Not validated - private VNet intended but VNet/subnet details were not known at test time. Re-run this script once the VNet exists to validate private endpoints."
        Add-Result -Category "PrivateDns" -Check "Private DNS zones" -Result "Warn" -Detail "Not validated - VNet details were not known at test time. Confirm the required private DNS zones exist and are linked once the VNet is available."
        Add-Result -Category "Connectivity" -Check "App Service VNet integration" -Result "Warn" -Detail "Not validated - VNet details were not known at test time. Re-run once the VNet/subnets are available."
    }

    #region Private endpoint + DNS ---------------------------------------------------------------
    if ($TestPrivate) {
        Write-Host -ForegroundColor "Cyan" "Testing private endpoint and private DNS configuration..."
        try {
            $vnet = Get-AzVirtualNetwork -ResourceGroupName $ExistingVnetRg -Name $ExistingVnetName -ErrorAction Stop
            if ($CreateNewVnet) {
                # A brand-new VNet has no real DhcpOptions to inspect and (being brand new) is never
                # linked to any pre-existing private DNS zone - use the DNS mode captured at intake
                # instead of inferring it, and only record/report, per that intake choice.
                $usesCustomDns = ($NewVnetDnsMode -eq "Custom")
                $dnsServers = if ($usesCustomDns) { "Custom/on-prem DNS (per intake answer)" } elseif ($PrivateDnsZonesMode -eq "Existing") { "Azure Private DNS Zones - subscription '$PrivateDnsZoneSubId', RG '$PrivateDnsZoneRg' (per intake answer)" } elseif ($PrivateDnsZonesMode -eq "Unknown") { "Azure Private DNS Zones - existing zones planned, subscription/RG not yet known (per intake answer)" } else { "Azure Private DNS Zones - created at install (per intake answer)" }
            }
            else {
                $usesCustomDns = $vnet.DhcpOptions.DnsServers -and $vnet.DhcpOptions.DnsServers.Count -gt 0
                $dnsServers = if ($usesCustomDns) { $vnet.DhcpOptions.DnsServers -join ", " } else { "Azure-provided default (168.63.129.16)" }
            }
            Add-Result -Category "PrivateDns" -Check "VNet DNS configuration" -Result "Info" -Detail "VNet '$ExistingVnetName' DNS servers: $dnsServers"
            $ConfigSummary["VNet DNS configuration"] = "VNet '$ExistingVnetName': $dnsServers"

            if ($usesCustomDns) {
                # VNet resolves names via its own (non-Azure) DNS servers rather than Azure-provided DNS,
                # so Azure private DNS zones linked to this VNet aren't how resolution works here - skip that check.
                $zoneList = ($RequiredPrivateDnsZones | ForEach-Object { "$($_.Zone) ($($_.Purpose))" }) -join "; "
                Add-Result -Category "PrivateDns" -Check "Private DNS zones" -Result "Info" -Detail "VNet uses custom DNS servers ($dnsServers); Azure private DNS zone checks are not applicable. The custom DNS server must resolve: $zoneList"
            }
            elseif ($PrivateDnsZonesMode -eq "Existing") {
                # The customer's private DNS zones may live in a DIFFERENT subscription than the one
                # under test (common with centralized hub/spoke DNS). Switch context to that
                # subscription for the read-only zone lookups below, then ALWAYS restore the test
                # subscription context in the finally so the private endpoint deployment that follows
                # still targets the correct subscription. $vnet.Id is a full resource id, so the
                # linkage comparison still works across the context switch.
                $dnsZoneCtxSwitched = $false
                if ($PrivateDnsZoneSubId -and $PrivateDnsZoneSubId -ne $SubscriptionId) {
                    try { Set-AzContext -Subscription $PrivateDnsZoneSubId -ErrorAction Stop | Out-Null; $dnsZoneCtxSwitched = $true }
                    catch { Add-Result -Category "PrivateDns" -Check "Private DNS zones subscription" -Result "Warn" -Detail "Could not switch to subscription '$PrivateDnsZoneSubId' to read the private DNS zones; results below are from the current subscription and may be inaccurate." -Message $_.Exception.Message }
                }
                try {
                if ($CreateNewVnet) {
                    # New-VNet + Existing zones: the real zones already exist in a subscription/RG the
                    # customer manages. Report which required zones are MISSING from that RG. Linkage
                    # can't be checked here (this VNet is throwaway) - that's handled at install.
                    $rgZones = @()
                    try { $rgZones = Get-AzPrivateDnsZone -ResourceGroupName $PrivateDnsZoneRg -ErrorAction Stop } catch {}
                    $missingZones = @()
                    foreach ($rz in $RequiredPrivateDnsZones) {
                        $match = $rgZones | Where-Object { $_.Name -eq $rz.Zone }
                        if (-not $match) {
                            $missingZones += $rz.Zone
                            Add-Result -Category "PrivateDns" -Check "Private DNS zone: $($rz.Zone)" -Result "Fail" -Detail "MISSING from resource group '$PrivateDnsZoneRg' - required for $($rz.Purpose) private endpoints. Linkage to the real VNet is handled at install (this test VNet is throwaway)."
                        }
                    }
                    if ($missingZones.Count -eq 0) {
                        Add-Result -Category "PrivateDns" -Check "Private DNS zones" -Result "Pass" -Detail "All required zones present in resource group '$PrivateDnsZoneRg'. Linkage to the real VNet is handled at install."
                    }
                    $ConfigSummary["Private DNS zones missing"] = if ($missingZones.Count -gt 0) { $missingZones -join "; " } else { "none - all required zones present" }
                }
                else {
                    # Existing-VNet + Existing zones: scope "missing" to the named resource group when
                    # one was supplied (a zone that exists only elsewhere in the subscription is still
                    # missing from the RG the customer told us they use), and separately report whether
                    # it's linked to this actual VNet. Per-zone Pass (present+linked) rows are suppressed
                    # from the console to reduce noise - only Fail/Warn rows are emitted per zone, plus a
                    # single rollup at the end. The full per-zone state is still accumulated below so it
                    # reaches the JSON output via the rollup's Message.
                    $allZones = @()
                    try { $allZones = Get-AzPrivateDnsZone -ErrorAction Stop } catch {}
                    $missingZones = @()
                    $dnsZoneReport = @()
                    foreach ($rz in $RequiredPrivateDnsZones) {
                        $match = $allZones | Where-Object { $_.Name -eq $rz.Zone }
                        if ($PrivateDnsZoneRg) { $match = $match | Where-Object { $_.ResourceGroupName -eq $PrivateDnsZoneRg } }
                        if (-not $match) {
                            $missingZones += $rz.Zone
                            $whereText = if ($PrivateDnsZoneRg) { "resource group '$PrivateDnsZoneRg'" } else { "this subscription" }
                            Add-Result -Category "PrivateDns" -Check "Private DNS zone: $($rz.Zone)" -Result "Fail" -Detail "MISSING from $whereText - required for $($rz.Purpose) private endpoints."
                            $dnsZoneReport += "$($rz.Zone) ($($rz.Purpose)): missing from $whereText"
                            continue
                        }
                        $linked = $false
                        foreach ($z in $match) {
                            try {
                                $links = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $z.ResourceGroupName -ZoneName $z.Name -ErrorAction Stop
                                if ($links | Where-Object { $_.VirtualNetworkId -eq $vnet.Id }) { $linked = $true; break }
                            }
                            catch {}
                        }
                        if ($linked) { $dnsZoneReport += "$($rz.Zone) ($($rz.Purpose)): present and linked" }
                        else {
                            Add-Result -Category "PrivateDns" -Check "Private DNS zone: $($rz.Zone)" -Result "Warn" -Detail "Present but NOT linked to '$ExistingVnetName' ($($rz.Purpose)). Add a virtual network link."
                            $dnsZoneReport += "$($rz.Zone) ($($rz.Purpose)): present but NOT linked"
                        }
                    }
                    $linkedCount = @($dnsZoneReport | Where-Object { $_ -like "*: present and linked" }).Count
                    if ($linkedCount -eq $RequiredPrivateDnsZones.Count) {
                        Add-Result -Category "PrivateDns" -Check "Private DNS zones" -Result "Pass" -Detail "All required private DNS zones present and linked to '$ExistingVnetName'."
                    }
                    else {
                        Add-Result -Category "PrivateDns" -Check "Private DNS zones summary" -Result "Info" -Detail "$linkedCount of $($RequiredPrivateDnsZones.Count) required private DNS zones present and linked to '$ExistingVnetName'." -Message ($dnsZoneReport -join "; ")
                    }
                    $ConfigSummary["Private DNS zones missing"] = if ($missingZones.Count -gt 0) { $missingZones -join "; " } else { "none - all required zones present" }
                }
                }
                finally {
                    if ($dnsZoneCtxSwitched) { try { Set-AzContext -Subscription $SubscriptionId -ErrorAction Stop | Out-Null } catch {} }
                }
            }
            elseif ($PrivateDnsZonesMode -eq "Unknown") {
                # The subscription/RG holding the existing zones weren't known at intake time, so there's
                # nothing to look up against - skip straight past the Get-AzPrivateDnsZone calls (which
                # would otherwise be called with a null resource group) rather than crashing or silently
                # reporting nothing.
                Add-Result -Category "PrivateDns" -Check "Private DNS zones" -Result "Info" -Detail "Not verified - the existing Private DNS zones' subscription/resource group weren't known at test time. Confirm the required zones exist and are linked before the actual NME POV installation."
            }
            else {
                # New zones (either VNet path): the installer/runbook is expected to create and link the
                # zones at deploy time. Prove Azure Policy/permissions allow zone creation by test-creating
                # each required zone in the throwaway TEST resource group; don't link them (linking is not
                # required to prove creation is allowed, and there's nothing meaningful to link them to on
                # the new-VNet path). These zones are tracked and removed during cleanup.
                # Fan the per-zone creates out concurrently (N=6 zones) instead of paying per-zone
                # create latency serially. Each job does ONLY the create and returns a plain hashtable -
                # Add-Result/Add-TrackedResource/Get-PolicyFromError/Resolve-PolicyName all touch
                # shared script state and are called on the main thread below, one result at a time.
                $zoneJobs = @()
                foreach ($rz in $RequiredPrivateDnsZones) {
                    $zoneJobs += Start-ThreadJob -Name "PrivateDnsZone-$($rz.Zone)" -ScriptBlock {
                        param($rg, $zoneName, $purpose)
                        $ErrorActionPreference = "Stop"
                        try {
                            New-AzPrivateDnsZone -ResourceGroupName $rg -Name $zoneName -ErrorAction Stop | Out-Null
                            @{ Zone = $zoneName; Purpose = $purpose; Ok = $true }
                        }
                        catch {
                            $zoneErrMsg = $_.Exception.Message
                            try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $zoneErrMsg = "$zoneErrMsg`n$($_.ErrorDetails.Message)" } } catch {}
                            try { if ($_.Exception.Response -and $_.Exception.Response.Content) { $zoneErrMsg = "$zoneErrMsg`n$($_.Exception.Response.Content)" } } catch {}
                            try { if ($_.Exception.Body) { $zoneErrMsg = "$zoneErrMsg`n$($_.Exception.Body | ConvertTo-Json -Depth 10 -Compress)" } } catch {}
                            @{ Zone = $zoneName; Purpose = $purpose; Ok = $false; Error = $zoneErrMsg }
                        }
                    } -ArgumentList $ResourceGroupName, $rz.Zone, $rz.Purpose
                }
                $zoneJobResults = $zoneJobs | Wait-Job | Receive-Job
                $zoneJobs | Remove-Job -Force -ErrorAction SilentlyContinue

                # Process results on the main thread, in the original zone order, so console output
                # stays stable and the report/cleanup are byte-for-byte equivalent to the sequential form.
                foreach ($rz in $RequiredPrivateDnsZones) {
                    $zr = $zoneJobResults | Where-Object { $_.Zone -eq $rz.Zone } | Select-Object -First 1
                    if ($zr -and $zr.Ok) {
                        Add-TrackedResource -Type "privatednszone" -ResourceGroupName $ResourceGroupName -Name $rz.Zone
                        Add-Result -Category "PrivateDns" -Check "Private DNS zone: $($rz.Zone)" -Result "Pass" -Detail "created successfully"
                    }
                    else {
                        $zoneErrMsg = if ($zr) { $zr.Error } else { "No result returned from the create job." }
                        $p = Get-PolicyFromError -ExceptionMessage $zoneErrMsg
                        $pDisplayHint = if ($p.PolicyAssignmentDisplayName) { $p.PolicyAssignmentDisplayName } elseif ($p.PolicyDefinitionDisplayName) { $p.PolicyDefinitionDisplayName } else { $null }
                        $polName = Resolve-PolicyName -PolicyDefinitionId $p.PolicyDefinitionId -PolicyAssignmentId $p.PolicyAssignmentId -PolicySetDefinitionId $p.PolicySetDefinitionId -DisplayNameHint $pDisplayHint
                        $concise = Get-ConciseErrorMessage -RawMessage $zoneErrMsg
                        $detail = if ($polName) { "Blocked by Azure Policy: '$polName'." } else { "Failed to test-create: $concise" }
                        Add-Result -Category "PrivateDns" -Check "Private DNS zone: $($rz.Zone)" -Result "Fail" -Detail $detail -PolicyName $polName -Message $concise -RawMessage $zoneErrMsg
                    }
                }
            }

            # Create one private endpoint per NME PaaS service, against the throwaway resources the
            # deployability phase already (attempted to) create in $ResourceGroupName. Only attempt a
            # service's PE if its target resource actually exists (it may have failed the deployability
            # create under policy). PE names are derived from the $peName base.
            $PeTargets = @()
            $subnet = $vnet.Subnets | Where-Object { $_.Name -eq $PeSubnetName }
            if (-not $subnet) {
                Add-Result -Category "PrivateEndpoint" -Check "Private endpoint deployment" -Result "Fail" -Detail "Subnet '$PeSubnetName' not found in VNet '$ExistingVnetName'."
            }
            else {
                $peServicePlan = @()
                $sqlResId = (Get-AzResource -ResourceGroupName $ResourceGroupName -Name $sqlName -ResourceType "Microsoft.Sql/servers" -ErrorAction SilentlyContinue).ResourceId
                if ($sqlResId) { $peServicePlan += @{ Service = "SQL Server"; PeName = "$peName-sql"; TargetId = $sqlResId; GroupId = "sqlServer"; Port = 1433 } }
                else { Add-Result -Category "PrivateEndpoint" -Check "Private endpoint: SQL Server" -Result "Info" -Detail "Skipped - SQL Server was not created." }

                $kvResId = (Get-AzResource -ResourceGroupName $ResourceGroupName -Name $kvName -ResourceType "Microsoft.KeyVault/vaults" -ErrorAction SilentlyContinue).ResourceId
                if ($kvResId) { $peServicePlan += @{ Service = "Key Vault"; PeName = "$peName-kv"; TargetId = $kvResId; GroupId = "vault"; Port = 443 } }
                else { Add-Result -Category "PrivateEndpoint" -Check "Private endpoint: Key Vault" -Result "Info" -Detail "Skipped - Key Vault was not created." }

                $stResId = (Get-AzResource -ResourceGroupName $ResourceGroupName -Name $stName -ResourceType "Microsoft.Storage/storageAccounts" -ErrorAction SilentlyContinue).ResourceId
                if ($stResId) { $peServicePlan += @{ Service = "Storage"; PeName = "$peName-blob"; TargetId = $stResId; GroupId = "blob"; Port = 443 } }
                else { Add-Result -Category "PrivateEndpoint" -Check "Private endpoint: Storage" -Result "Info" -Detail "Skipped - Storage account was not created." }

                $aaResId = (Get-AzResource -ResourceGroupName $ResourceGroupName -Name $aaUpdaterName -ResourceType "Microsoft.Automation/automationAccounts" -ErrorAction SilentlyContinue).ResourceId
                if ($aaResId) { $peServicePlan += @{ Service = "Automation"; PeName = "$peName-auto"; TargetId = $aaResId; GroupId = "Webhook"; Port = 443 } }
                else { Add-Result -Category "PrivateEndpoint" -Check "Private endpoint: Automation" -Result "Info" -Detail "Skipped - Automation Account was not created." }

                # Fan the four PE creates out concurrently instead of paying per-PE create latency
                # serially. Each job does ONLY the create and returns a plain hashtable -
                # Add-Result/Add-TrackedResource/Get-PolicyFromError/Resolve-PolicyName all touch shared
                # script state and are called on the main thread below, one result at a time.
                $peJobs = @()
                foreach ($svc in $peServicePlan) {
                    $peJobs += Start-ThreadJob -Name "PrivateEndpoint-$($svc.Service)" -ScriptBlock {
                        param($rg, $peName, $targetId, $groupId, $subnet, $loc, $tags, $label, $port)
                        $ErrorActionPreference = "Stop"
                        # All four PE creates run concurrently against the SAME subnet, and each PE
                        # create mutates the parent VNet (adds to the subnet's privateEndpoints
                        # collection). ARM can transiently reject concurrent writes to the same
                        # VNet/subnet with an in-progress/conflict error that is NOT a policy block -
                        # retry those a few times (with backoff) so they don't surface as spurious
                        # policy Fails. A real policy denial is not retryable and falls through quickly.
                        $pe = $null; $peErr = $null
                        for ($attempt = 1; $attempt -le 4; $attempt++) {
                            try {
                                $plsc = New-AzPrivateLinkServiceConnection -Name "$peName-conn" -PrivateLinkServiceId $targetId -GroupId $groupId -ErrorAction Stop
                                $pe = New-AzPrivateEndpoint -ResourceGroupName $rg -Name $peName -Location $loc -Subnet $subnet -PrivateLinkServiceConnection $plsc -Tag $tags -ErrorAction Stop
                                $peErr = $null
                                break
                            }
                            catch {
                                $peErr = $_
                                $m = "$($_.Exception.Message)"
                                if ($attempt -lt 4 -and ($m -match "AnotherOperationInProgress|RetryableError|Conflict|another operation|in progress|being provisioned|ReferencedResourceNotProvisioned|429|409")) {
                                    Start-Sleep -Seconds ($attempt * 5)
                                    continue
                                }
                                break
                            }
                        }
                        if ($pe) {
                            $privIp = $null
                            try { $nicId = $pe.NetworkInterfaces[0].Id; $privIp = (Get-AzNetworkInterface -ResourceId $nicId -ErrorAction Stop).IpConfigurations[0].PrivateIpAddress } catch {}
                            @{ Label = $label; Ok = $true; Name = $peName; Id = $pe.Id; PrivateIp = $privIp; Port = $port }
                        }
                        else {
                            $peErrMsg = $peErr.Exception.Message
                            try { if ($peErr.ErrorDetails -and $peErr.ErrorDetails.Message) { $peErrMsg = "$peErrMsg`n$($peErr.ErrorDetails.Message)" } } catch {}
                            try { if ($peErr.Exception.Response -and $peErr.Exception.Response.Content) { $peErrMsg = "$peErrMsg`n$($peErr.Exception.Response.Content)" } } catch {}
                            try { if ($peErr.Exception.Body) { $peErrMsg = "$peErrMsg`n$($peErr.Exception.Body | ConvertTo-Json -Depth 10 -Compress)" } } catch {}
                            @{ Label = $label; Ok = $false; Error = $peErrMsg; Name = $peName; Port = $port }
                        }
                    } -ArgumentList $ResourceGroupName, $svc.PeName, $svc.TargetId, $svc.GroupId, $subnet, $Location, $Tags, $svc.Service, $svc.Port
                }
                $peJobResults = $peJobs | Wait-Job | Receive-Job
                $peJobs | Remove-Job -Force -ErrorAction SilentlyContinue

                # Process results on the main thread, in service order, so console output stays stable.
                $PeTargets = @()
                foreach ($svc in $peServicePlan) {
                    $jr = $peJobResults | Where-Object { $_.Label -eq $svc.Service } | Select-Object -First 1
                    if ($jr -and $jr.Ok) {
                        Add-TrackedResource -Type "privateendpoint" -ResourceGroupName $ResourceGroupName -Name $jr.Name -Id $jr.Id
                        Add-Result -Category "PrivateEndpoint" -Check "Private endpoint: $($svc.Service)" -Result "Pass" -Detail "Deployed into subnet '$PeSubnetName'$(if ($jr.PrivateIp) { " (private IP $($jr.PrivateIp))" })."
                        if ($jr.PrivateIp) { $PeTargets += [pscustomobject]@{ Service = $svc.Service; PrivateIp = $jr.PrivateIp; Port = $jr.Port } }
                    }
                    else {
                        $peErrMsgOut = if ($jr) { $jr.Error } else { "No result returned from the create job." }
                        $p = Get-PolicyFromError -ExceptionMessage $peErrMsgOut
                        $pDisplayHint = if ($p.PolicyAssignmentDisplayName) { $p.PolicyAssignmentDisplayName } elseif ($p.PolicyDefinitionDisplayName) { $p.PolicyDefinitionDisplayName } else { $null }
                        $polName = Resolve-PolicyName -PolicyDefinitionId $p.PolicyDefinitionId -PolicyAssignmentId $p.PolicyAssignmentId -PolicySetDefinitionId $p.PolicySetDefinitionId -DisplayNameHint $pDisplayHint
                        $concise = Get-ConciseErrorMessage -RawMessage $peErrMsgOut
                        $detail = if ($polName) { "Blocked by Azure Policy: '$polName'." } else { "Failed: $concise" }
                        Add-Result -Category "PrivateEndpoint" -Check "Private endpoint: $($svc.Service)" -Result "Fail" -Detail $detail -PolicyName $polName -Message $concise -RawMessage $peErrMsgOut
                    }
                }
            }
        }
        catch {
            Add-Result -Category "PrivateEndpoint" -Check "Private endpoint / DNS test" -Result "Warn" -Detail "Could not complete private endpoint / DNS test." -Message $_.Exception.Message
        }
        Write-Host ""
    }
    #endregion

    #region App Service VNet integration + outbound connectivity ---------------------------------
    if ($TestVnetIntegration) {
        Write-Host -ForegroundColor "Cyan" "Testing App Service VNet-integration outbound connectivity; this takes some time..."
        try {
            $vnet = Get-AzVirtualNetwork -ResourceGroupName $ExistingVnetRg -Name $ExistingVnetName -ErrorAction Stop
            $appSubnet = $vnet.Subnets | Where-Object { $_.Name -eq $AppSubnetName }
            if (-not $appSubnet) {
                Add-Result -Category "Connectivity" -Check "App subnet delegation" -Result "Fail" -Detail "Subnet '$AppSubnetName' not found in VNet '$ExistingVnetName'."
            }
            else {
                $deleg = $appSubnet.Delegations | Where-Object { $_.ServiceName -eq "Microsoft.Web/serverFarms" }
                if (-not $deleg) {
                    Add-Result -Category "Connectivity" -Check "App subnet delegation" -Result "Warn" -Detail "Subnet '$AppSubnetName' lacks 'Microsoft.Web/serverFarms' delegation required for VNet integration. Skipping the live connectivity test."
                }
                else {
                    Add-Result -Category "Connectivity" -Check "App subnet delegation" -Result "Pass" -Detail "Subnet '$AppSubnetName' is delegated to Microsoft.Web/serverFarms."

                    # Ensure an App Service Plan + Web App exist to integrate.
                    $planName = $connAspName
                    New-AzAppServicePlan -ResourceGroupName $ResourceGroupName -Name $planName -Location $Location -Tier "Basic" -WorkerSize "Small" -NumberOfWorkers 1 -Tag $Tags -ErrorAction Stop | Out-Null
                    Add-TrackedResource -Type "asp" -ResourceGroupName $ResourceGroupName -Name $planName
                    $webName = $connWebName
                    $web = New-AzWebApp -ResourceGroupName $ResourceGroupName -Name $webName -Location $Location -AppServicePlan $planName -Tag $Tags -ErrorAction Stop
                    Add-TrackedResource -Type "webapp" -ResourceGroupName $ResourceGroupName -Name $webName -Id $web.Id

                    # Enable regional VNet integration via the swift-connection REST call.
                    $swiftUri = "$($AzEnv.ResourceManagerUrl.TrimEnd('/'))$($web.Id)/networkConfig/virtualNetwork?api-version=2023-01-01"
                    $swiftBody = @{ properties = @{ subnetResourceId = $appSubnet.Id; swiftSupported = $true } } | ConvertTo-Json -Depth 5
                    $swift = Invoke-AzRestMethod -Method PUT -Uri $swiftUri -Payload $swiftBody -ErrorAction Stop
                    if ($swift.StatusCode -ge 200 -and $swift.StatusCode -lt 300) {
                        Add-Result -Category "Connectivity" -Check "VNet integration" -Result "Pass" -Detail "Regional VNet integration enabled to '$AppSubnetName'."
                        # Route all traffic through the VNet so the test reflects NME behavior.
                        try { Set-AzWebApp -ResourceGroupName $ResourceGroupName -Name $webName -AppSettings @{ WEBSITE_VNET_ROUTE_ALL = "1" } -ErrorAction SilentlyContinue | Out-Null } catch {}

                    if ($CreateNewVnet) {
                        # On a brand-new VNet there's no existing outbound routing/DNS/firewall setup to validate -
                        # the resources above confirm the VNet, subnet delegation, and integration are configured
                        # correctly, but running the live Kudu outbound test here would only be testing Azure's
                        # default (wide-open) egress, not anything the customer will actually configure.
                        Add-Result -Category "Connectivity" -Check "Outbound connectivity test" -Result "Info" -Detail "Skipped - VNet '$ExistingVnetName' is brand-new with no customer-configured routing/firewall/DNS yet. VNet integration, subnet delegation, and the test App Service were created and confirmed configured correctly. Once the customer's real egress controls (firewall, UDRs, custom DNS) are in place, run NmeNetworkTest.ps1 against the real NME App Service to validate outbound connectivity."
                    }
                    else {
                        Start-Sleep -Seconds 20

                        # Build the standard outbound endpoint list (environment-aware), mirroring
                        # NmeNetworkTest.ps1 EXACTLY.
                        if ($AzEnv.Name -eq "AzureUSGovernment") {
                            # WEBSITE runs on azurewebsites.us in Gov; the gov variants of the auth/API
                            # endpoints per NmeNetworkTest.ps1. graph.microsoft.com is also included
                            # alongside graph.microsoft.us (both are used in Gov per NmeNetworkTest.ps1).
                            $endpoints = @(
                                [pscustomobject]@{ Uri = "nwp-web-app.azurewebsites.net"; Port = 443; Purpose = "Nerdio Licensing Servers" },
                                [pscustomobject]@{ Uri = "login.microsoftonline.us"; Port = 443; Purpose = "Microsoft API Authentication" },
                                [pscustomobject]@{ Uri = "graph.microsoft.us"; Port = 443; Purpose = "Graph API Authentication" },
                                [pscustomobject]@{ Uri = "graph.microsoft.com"; Port = 443; Purpose = "Graph API Authentication (commercial)" },
                                [pscustomobject]@{ Uri = "login.windows.net"; Port = 443; Purpose = "Entra ID SQL Authentication" },
                                [pscustomobject]@{ Uri = "management.usgovcloudapi.net"; Port = 443; Purpose = "Azure API" },
                                [pscustomobject]@{ Uri = "api.github.com"; Port = 443; Purpose = "Scripted Actions" },
                                [pscustomobject]@{ Uri = "api.loganalytics.us"; Port = 443; Purpose = "API Access for Log Analytics" },
                                [pscustomobject]@{ Uri = "api.applicationinsights.us"; Port = 443; Purpose = "API Access for Application Insights" }
                            )
                        }
                        else {
                            # Commercial list per NmeNetworkTest.ps1. Also used, best-effort, for
                            # AzureChinaCloud - out of scope to enumerate China endpoints precisely.
                            $endpoints = @(
                                [pscustomobject]@{ Uri = "nwp-web-app.azurewebsites.net"; Port = 443; Purpose = "Nerdio Licensing Servers" },
                                [pscustomobject]@{ Uri = "login.microsoftonline.com"; Port = 443; Purpose = "Microsoft API Authentication" },
                                [pscustomobject]@{ Uri = "graph.microsoft.com"; Port = 443; Purpose = "Graph API Authentication" },
                                [pscustomobject]@{ Uri = "login.windows.net"; Port = 443; Purpose = "Entra ID SQL Authentication" },
                                [pscustomobject]@{ Uri = "management.azure.com"; Port = 443; Purpose = "Azure API" },
                                [pscustomobject]@{ Uri = "api.github.com"; Port = 443; Purpose = "Scripted Actions" },
                                [pscustomobject]@{ Uri = "api.loganalytics.io"; Port = 443; Purpose = "API Access for Log Analytics" },
                                [pscustomobject]@{ Uri = "api.applicationinsights.io"; Port = 443; Purpose = "API Access for Application Insights" }
                            )
                        }

                        # Combined target list: the standard endpoints (tested by hostname, DNS + TCP)
                        # PLUS each Part (b) private endpoint's private IP (tested by IP, TCP only - PE
                        # privatelink FQDNs won't resolve without registering DNS records, which this
                        # script must not do). Kept as an ordered list so results can be attributed back
                        # per-target after the worker run.
                        $targets = @()
                        foreach ($ep in $endpoints) {
                            $targets += [pscustomobject]@{ Key = $ep.Uri; Port = $ep.Port; Label = "Outbound: $($ep.Uri)"; Purpose = $ep.Purpose; IsPe = $false; IsDns = $false; Service = $null; ExpectedIp = $null }
                        }
                        foreach ($pt in $PeTargets) {
                            $targets += [pscustomobject]@{ Key = $pt.PrivateIp; Port = $pt.Port; Label = "Private endpoint reachability: $($pt.Service)"; Purpose = $null; IsPe = $true; IsDns = $false; Service = $pt.Service; ExpectedIp = $null }
                        }

                        # Part (d): whether the existing VNet resolves via Azure DNS or custom DNS
                        # servers - same detection the verification region above uses. This gates
                        # whether PE-FQDN DNS resolution can be meaningfully tested (Azure DNS only)
                        # and always drives the DNS-unconfirmed summary flag emitted below.
                        $usesCustomDns = $vnet.DhcpOptions.DnsServers -and $vnet.DhcpOptions.DnsServers.Count -gt 0

                        # Part (d): only on Azure-DNS VNets, additionally probe whether each created
                        # PE's resource FQDN already resolves to that PE's private IP from inside the
                        # VNet - this only happens if private DNS auto-registration (an Azure Policy DINE
                        # assignment, or a pre-linked zone with a zone group) is already active. It is
                        # NOT expected out of the box and is purely informational - reachability above
                        # was already proven by private IP regardless of this result. Automation has no
                        # cleanly-derivable FQDN here, so it is skipped (it still gets reachability-by-IP
                        # from Part c).
                        if (-not $usesCustomDns) {
                            foreach ($pt in $PeTargets) {
                                $peFqdn = switch ($pt.Service) {
                                    "SQL Server" { "$sqlName.$SqlSuffix" }
                                    "Key Vault" { "$kvName.$KeyVaultSuffix" }
                                    "Storage" { "$stName.blob.$StorageSuffix" }
                                    default { $null }
                                }
                                if ($peFqdn) {
                                    $targets += [pscustomobject]@{ Key = $peFqdn; Port = $pt.Port; Label = "Private DNS resolution: $($pt.Service)"; Purpose = $null; IsPe = $false; IsDns = $true; Service = $pt.Service; ExpectedIp = $pt.PrivateIp }
                                }
                            }
                        }

                        # Run the outbound/PE reachability test FROM the worker via the Kudu/SCM command
                        # API so it uses the VNet's real routing and DNS - the same approach
                        # NmeNetworkTest.ps1 uses.
                        $scmHost = ($web.EnabledHostNames | Where-Object { $_ -match "\.scm\." } | Select-Object -First 1)
                        if (-not $scmHost) { $scmHost = "$webName.scm.$(if ($AzEnv.Name -eq 'AzureUSGovernment') { 'azurewebsites.us' } elseif ($AzEnv.Name -eq 'AzureChinaCloud') { 'chinacloudsites.cn' } else { 'azurewebsites.net' })" }
                        # Newer Az.Accounts returns the token as a SecureString; handle both forms.
                        $rawTok = (Get-AzAccessToken -ResourceUrl $AzEnv.ResourceManagerUrl -ErrorAction Stop).Token
                        $kuduToken = if ($rawTok -is [System.Security.SecureString]) { [System.Net.NetworkCredential]::new("", $rawTok).Password } else { $rawTok }
                        $epList = ($targets | ForEach-Object { "'$($_.Key)|$($_.Port)'" }) -join ","
                        $remoteCmd = "`$ProgressPreference='SilentlyContinue';foreach(`$e in @($epList)){`$pp=`$e -split '\|';`$u=`$pp[0];`$p=[int]`$pp[1];`$ip='';try{`$ip=(([System.Net.Dns]::GetHostAddresses(`$u))|Where-Object{`$_.AddressFamily -eq 'InterNetwork'}|Select-Object -First 1).IPAddressToString}catch{};`$ok=`$false;try{`$c=New-Object System.Net.Sockets.TcpClient;`$ar=`$c.BeginConnect(`$u,`$p,`$null,`$null);if(`$ar.AsyncWaitHandle.WaitOne(10000)){try{`$c.EndConnect(`$ar);`$ok=`$c.Connected}catch{}};`$c.Close()}catch{};`$sub='';if(`$p -eq 443 -and `$ok){try{`$sp=[System.Net.ServicePointManager]::FindServicePoint('https://'+`$u);`$null=Invoke-RestMethod -Uri ('https://'+`$u) -TimeoutSec 15 -ErrorAction SilentlyContinue;`$sub=`$sp.Certificate.Subject}catch{}};`$st=if(`$ok){'OK'}else{'BLOCKED'};Write-Output (`$u+'|'+`$st+'|'+`$ip+'|'+`$sub)}"
                        $kbody = @{ command = "powershell -NoProfile -Command `"$remoteCmd`""; dir = "site\wwwroot" } | ConvertTo-Json
                        $headers = @{ Authorization = "Bearer $kuduToken"; "Content-Type" = "application/json" }
                        $dnsProbeCount = 0
                        $dnsConfirmedCount = 0
                        try {
                            $kresp = Invoke-RestMethod -Method POST -Uri "https://$scmHost/api/command" -Headers $headers -Body $kbody -TimeoutSec 120 -ErrorAction Stop
                            $outLines = @()
                            if ($kresp.Output) { $outLines = $kresp.Output -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match "\|(OK|BLOCKED)\|" } }
                            foreach ($t in $targets) {
                                $line = $outLines | Where-Object { ($_ -split "\|")[0] -eq $t.Key } | Select-Object -First 1
                                if ($t.IsPe) {
                                    if ($line -and $line -match "\|OK\|") {
                                        Add-Result -Category "Connectivity" -Check $t.Label -Result "Pass" -Detail "$($t.Key):$($t.Port) reachable."
                                    }
                                    elseif ($line -and $line -match "\|BLOCKED\|") {
                                        Add-Result -Category "Connectivity" -Check $t.Label -Result "Warn" -Detail "NOT reachable at $($t.Key):$($t.Port) from the VNet-integrated worker - check NSG / UDR / routing between subnet '$AppSubnetName' and subnet '$PeSubnetName'."
                                    }
                                    else {
                                        Add-Result -Category "Connectivity" -Check $t.Label -Result "Warn" -Detail "No result returned from the worker for this target."
                                    }
                                }
                                elseif ($t.IsDns) {
                                    # Part (d): does the resource FQDN resolve to the PE's private IP from
                                    # inside the VNet? A match proves private DNS auto-registration is
                                    # active; anything else is informational only - Part (c) already
                                    # proved reachability by private IP regardless of this outcome.
                                    $dnsProbeCount++
                                    $resolvedIp = $null
                                    if ($line) { $resolvedIp = ($line -split "\|")[2] }
                                    if ($resolvedIp -and $resolvedIp -eq $t.ExpectedIp) {
                                        $dnsConfirmedCount++
                                        Add-Result -Category "Connectivity" -Check $t.Label -Result "Pass" -Detail "Resolves to private IP (auto-registered)."
                                    }
                                    elseif ($resolvedIp) {
                                        Add-Result -Category "Connectivity" -Check $t.Label -Result "Warn" -Detail "Resolves to public IP"
                                    }
                                    else {
                                        Add-Result -Category "Connectivity" -Check $t.Label -Result "Info" -Detail "Did not resolve - private DNS zone required at install."
                                    }
                                }
                                else {
                                    if ($line -and $line -match "\|OK\|") {
                                        Add-Result -Category "Connectivity" -Check $t.Label -Result "Pass" -Detail "$($t.Purpose)."
                                    }
                                    elseif ($line -and $line -match "\|BLOCKED\|") {
                                        $parts = $line -split "\|"
                                        $ip = $parts[2]
                                        Add-Result -Category "Connectivity" -Check $t.Label -Result "Warn" -Detail "$($t.Purpose) - NOT reachable from the VNet-integrated worker$(if ($ip) { " (resolved $ip)" } else { " (DNS did not resolve)" })."
                                    }
                                    else {
                                        Add-Result -Category "Connectivity" -Check $t.Label -Result "Warn" -Detail "No result returned from the worker for this target."
                                    }
                                }
                            }
                        }
                        catch {
                            Add-Result -Category "Connectivity" -Check "Kudu outbound test" -Result "Warn" -Detail "Could not run the in-worker connectivity test via Kudu. From the App Service Kudu console for '$webName': $NmeNetworkTestHint Endpoints to test: $(($endpoints | ForEach-Object { $_.Uri }) -join ', ')." -Message $_.Exception.Message
                        }

                        # Part (d): ALWAYS emit a summary flag (both custom-DNS and Azure-DNS
                        # existing-VNet paths) so the report never implies production DNS resolution of
                        # the privatelink FQDNs is proven when it isn't - reachability above is proven by
                        # private IP only unless private DNS auto-registration was just confirmed.
                        if ($usesCustomDns) {
                            Add-Result -Category "Connectivity" -Check "Private endpoint DNS resolution (overall)" -Result "Info" -Detail "Custom DNS - not tested; reachability confirmed by private IP only."
                        }
                        elseif ($dnsConfirmedCount -eq 0) {
                            Add-Result -Category "Connectivity" -Check "Private endpoint DNS resolution (overall)" -Result "Info" -Detail "All public - private DNS zones required at install."
                        }
                        else {
                            Add-Result -Category "Connectivity" -Check "Private endpoint DNS resolution (overall)" -Result "Info" -Detail "$dnsConfirmedCount of $dnsProbeCount resolve privately; rest require private DNS zone config at install."
                        }
                    }
                    }
                    else {
                        Add-Result -Category "Connectivity" -Check "VNet integration" -Result "Warn" -Detail "Could not enable VNet integration (HTTP $($swift.StatusCode)) on the test App Service. After the real NME install has working VNet integration, verify outbound access with NmeNetworkTest.ps1." -Message $swift.Content
                    }
                }
            }
        }
        catch {
            Add-Result -Category "Connectivity" -Check "App Service connectivity test" -Result "Warn" -Detail "Could not complete the App Service connectivity test." -Message $_.Exception.Message
        }
        Write-Host ""
    }
    #endregion
}
finally {
    #region Reporting ----------------------------------------------------------------------------
    $summaryMeta = [pscustomobject]@{
        TimestampUtc    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
        SubscriptionId  = $SubscriptionId
        Cloud           = $(try { (Get-AzContext).Environment.Name } catch { "unknown" })
        Region          = $Location
        ResourceGroup   = $ResourceGroupName
    }
    $rawJson = $null
    try {
        $rawJson = [pscustomobject]@{ Metadata = $summaryMeta; Configuration = $ConfigSummary; Results = $Results; CreatedResources = $Tracker } |
            ConvertTo-Json -Depth 8
        $rawJson | Out-File -FilePath $OutFile -Force
    }
    catch { Write-Host -ForegroundColor "Yellow" "Could not write JSON output: $($_.Exception.Message)" }

    # HTML report - the colour-coded, human-facing deliverable to hand to the SE. Same palette and
    # data as the console table below, so the two match; recipients can open it in any browser
    # (and Ctrl+P -> Save as PDF if they want a PDF, no extra tooling required).
    $HtmlOutFile = [System.IO.Path]::ChangeExtension($OutFile, ".html")
    try {
        $html = New-ReadinessHtmlReport -Results $Results -ConfigSummary $ConfigSummary -CustomResourceNames $CustomResourceNames -Meta $summaryMeta -CreatedResources $Tracker -RawJson $rawJson
        $html | Out-File -FilePath $HtmlOutFile -Force -Encoding utf8
    }
    catch { Write-Host -ForegroundColor "Yellow" "Could not write HTML report: $($_.Exception.Message)"; $HtmlOutFile = $null }

    # Copy/paste report.
    $counts = $Results | Group-Object Result | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Write-Host ""
    Write-Host -ForegroundColor "Green" "====== BEGIN REPORT ======"
    Write-Host ""
    Write-Host "## Nerdio Manager Deployment Readiness Report"
    Write-Host "- Date: $($summaryMeta.TimestampUtc)"
    Write-Host "- Subscription: $($summaryMeta.SubscriptionId)"
    Write-Host "- Cloud / Region: $($summaryMeta.Cloud) / $($summaryMeta.Region)"
    Write-Host "- Summary: $($counts -join '  ')"
    Write-Host ""
    Write-Host "Configuration used (reference for install)"
    Write-Host ("-" * 60)
    $cfgKeyCap = 34
    $cfgKeyWidth = [Math]::Min($cfgKeyCap, (($ConfigSummary.Keys | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum))
    foreach ($ck in $ConfigSummary.Keys) {
        $cv = ($ConfigSummary[$ck] -replace "[`r`n]+", " ")
        if ($ck.Length -gt $cfgKeyCap) {
            Write-Host $ck
            Write-Host ("   {0}" -f $cv)
        }
        else {
            Write-Host ("{0}{1}" -f $ck.PadRight($cfgKeyWidth), "   $cv")
        }
    }
    if ($CustomResourceNames.Count -gt 0) {
        Write-Host ""
        Write-Host "Custom resource names"
        Write-Host ("-" * 60)
        $nameKeyCap = 34
        $nameKeyWidth = [Math]::Min($nameKeyCap, (($CustomResourceNames.Keys | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum))
        foreach ($nk in $CustomResourceNames.Keys) {
            $nv = $CustomResourceNames[$nk]
            if ($nk.Length -gt $nameKeyCap) {
                Write-Host $nk
                Write-Host ("   {0}" -f $nv)
            }
            else {
                Write-Host ("{0}{1}" -f $nk.PadRight($nameKeyWidth), "   $nv")
            }
        }
    }
    Write-Host ""
    Write-Host "Check results"
    Write-Host ("-" * 60)
    # Colour-coded ANSI table, driven by the same palette as the HTML report so the two match.
    Write-ConsoleResultsTable -Results $Results
    Write-Host ""
    Write-Host -ForegroundColor "Green" "====== END REPORT ======"
    Write-Host ""
    Write-Host -ForegroundColor "Cyan" "Detailed results written to: $OutFile"
    Write-Host -ForegroundColor "Cyan" "HTML report written to:      $HtmlOutFile"
    Write-Host ""
    if ($script:IsCloudShell) {
        Invoke-CloudShellDownload -Path $HtmlOutFile
        Write-Host -ForegroundColor "Cyan" "You should now see an option to download the html report. If you do not, you can download the html from from the current session or copy the above report. Send the report to your Nerdio SE for validation."
    }
    elseif ($HtmlOutFile) {
        Write-Host -ForegroundColor "Cyan" "The HTML report was written to the current directory: $HtmlOutFile"
        Write-Host -ForegroundColor "Cyan" "Send that file to your Nerdio SE for validation."
    }
    #endregion

    #region Cleanup ------------------------------------------------------------------------------
    $removeAll = Read-YesNo -Prompt "Remove all resources created by this test? [Y/n]" -Default "y"
    if ($removeAll) {
        Write-Host -ForegroundColor "Cyan" "Removing created resources (reverse order)..."
        # Locks first, in their own pass: a lock can be created (during the parallel checks)
        # before the resource that later depends on it being gone (e.g. the private endpoint,
        # whose removal deletes a privateEndpointConnectionProxies sub-resource on the storage
        # account) is even created, so strict reverse-creation order can hit a locked scope.
        for ($i = $Tracker.Count - 1; $i -ge 0; $i--) {
            $t = $Tracker[$i]
            if ($t.Type -ne "lock") { continue }
            try {
                Remove-AzResourceLock -LockId $t.Id -Force -ErrorAction Continue | Out-Null
                Write-Host "  removed $($t.Type): $($t.Name)"
            }
            catch { Write-Host -ForegroundColor "Yellow" "  could not remove $($t.Type) '$($t.Name)': $($_.Exception.Message)" }
        }
        # Reverse the tracker so dependents are removed before dependencies.
        for ($i = $Tracker.Count - 1; $i -ge 0; $i--) {
            $t = $Tracker[$i]
            if ($t.Type -eq "lock") { continue }
            try {
                switch ($t.Type) {
                    "privateendpoint" { Remove-AzPrivateEndpoint -ResourceGroupName $t.ResourceGroupName -Name $t.Name -Force -ErrorAction Continue | Out-Null }
                    "webapp" { Remove-AzWebApp -ResourceGroupName $t.ResourceGroupName -Name $t.Name -Force -ErrorAction Continue | Out-Null }
                    "asp" { Remove-AzAppServicePlan -ResourceGroupName $t.ResourceGroupName -Name $t.Name -Force -ErrorAction Continue | Out-Null }
                    "automation" { Remove-AzAutomationAccount -ResourceGroupName $t.ResourceGroupName -Name $t.Name -Force -ErrorAction Continue | Out-Null }
                    "kv" {
                        Remove-AzKeyVault -ResourceGroupName $t.ResourceGroupName -VaultName $t.Name -Force -ErrorAction Continue | Out-Null
                        try { Remove-AzKeyVault -VaultName $t.Name -Location $Location -InRemovedState -Force -ErrorAction Continue | Out-Null } catch {}
                    }
                    "sqldatabase" { Remove-AzSqlDatabase -ResourceGroupName $t.ResourceGroupName -ServerName $t.Note -DatabaseName $t.Name -Force -ErrorAction Continue | Out-Null }
                    "sqlserver" { Remove-AzSqlServer -ResourceGroupName $t.ResourceGroupName -ServerName $t.Name -Force -ErrorAction Continue | Out-Null }
                    "storage" { Remove-AzStorageAccount -ResourceGroupName $t.ResourceGroupName -Name $t.Name -Force -ErrorAction Continue | Out-Null }
                    "law" { Remove-AzOperationalInsightsWorkspace -ResourceGroupName $t.ResourceGroupName -Name $t.Name -Force -ForceDelete -ErrorAction Continue | Out-Null }
                    "vnet" { Remove-AzVirtualNetwork -ResourceGroupName $t.ResourceGroupName -Name $t.Name -Force -ErrorAction Continue | Out-Null }
                    "privatednszone" { Remove-AzPrivateDnsZone -ResourceGroupName $t.ResourceGroupName -Name $t.Name -Confirm:$false -ErrorAction Continue | Out-Null }
                    default { }
                }
                Write-Host "  removed $($t.Type): $($t.Name)"
            }
            catch { Write-Host -ForegroundColor "Yellow" "  could not remove $($t.Type) '$($t.Name)': $($_.Exception.Message)" }
        }
        if ($CreatedResourceGroup) {
            if (Read-YesNo -Prompt "Also remove the temporary resource group '$ResourceGroupName'? [Y/n]" -Default "y") {
                Write-Host -ForegroundColor "Cyan" "Removing resource group '$ResourceGroupName' (runs in background)."
                Remove-AzResourceGroup -Name $ResourceGroupName -Force -AsJob -ErrorAction Continue | Out-Null
            }
        }
        Write-Host -ForegroundColor "Cyan" "Cleanup complete. Verify the resource group to confirm."
    }
    else {
        Write-Host -ForegroundColor "Yellow" "Left the following resources in resource group '$ResourceGroupName':"
        $Tracker | ForEach-Object { Write-Host "  - $($_.Type): $($_.Name)" }
    }
    #endregion
}
