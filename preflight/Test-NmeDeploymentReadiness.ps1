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
        Path for the JSON results file. Defaults to NmeReadinessOutput.json in the working directory.

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
    [System.String] $OutFile = (Join-Path -Path $PWD -ChildPath "NmeReadinessOutput.json")
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"

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
        [string] $Message = $null
    )
    $obj = [pscustomobject]@{
        Category   = $Category
        Check      = $Check
        Result     = $Result
        Detail     = $Detail
        PolicyName = $PolicyName
        Message    = $Message
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
    $out = [pscustomobject]@{ Message = $ExceptionMessage; PolicyDefinitionId = $null; PolicyAssignmentId = $null }
    if ([string]::IsNullOrEmpty($ExceptionMessage)) { return $out }

    if ($ExceptionMessage -match "({.*}$)") {
        try {
            $parsed = $Matches[0] | ConvertFrom-Json
            if ($parsed.error.message) { $out.Message = $parsed.error.message }
        }
        catch {}
    }
    # ARM policy denials embed the definition and assignment resource ids in the text.
    if ($out.Message -match "policyDefinitionId'?:?\s*'?(/[^',\s\}]+)") { $out.PolicyDefinitionId = $Matches[1] }
    elseif ($ExceptionMessage -match "policyDefinitionId'?:?\s*'?(/[^',\s\}]+)") { $out.PolicyDefinitionId = $Matches[1] }
    if ($out.Message -match "policyAssignmentId'?:?\s*'?(/[^',\s\}]+)") { $out.PolicyAssignmentId = $Matches[1] }
    elseif ($ExceptionMessage -match "policyAssignmentId'?:?\s*'?(/[^',\s\}]+)") { $out.PolicyAssignmentId = $Matches[1] }
    return $out
}

# Resolve a policy definition/assignment id to a friendly display name.
function Resolve-PolicyName {
    param(
        [string] $PolicyDefinitionId,
        [string] $PolicyAssignmentId
    )
    $name = $null
    if ($PolicyAssignmentId) {
        try { $name = (Get-AzPolicyAssignment -Id $PolicyAssignmentId -ErrorAction Stop).Properties.DisplayName } catch {}
    }
    if (-not $name -and $PolicyDefinitionId) {
        try { $name = (Get-AzPolicyDefinition -Id $PolicyDefinitionId -ErrorAction Stop).Properties.DisplayName } catch {}
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
        PolicyDefinitionId   = $null
        PolicyAssignmentId   = $null
        PolicyDefinitionName = $null
        PolicyAssignmentName = $null
        Found                = $false
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
                        $out.PolicyDefinitionName = $(if ($info.policyDefinitionDisplayName) { $info.policyDefinitionDisplayName } else { $info.policyDefinitionName })
                        $out.PolicyAssignmentName = $(if ($info.policyAssignmentDisplayName) { $info.policyAssignmentDisplayName } else { $info.policyAssignmentName })
                    }
                }
                catch {}
            }
            # Fallback: regex the blob for anything the structured parse didn't fill in.
            if (-not $out.PolicyDefinitionId -and $blob -match 'policyDefinitionId"?\s*:\s*"?(/[^",\s}]+)') { $out.PolicyDefinitionId = $Matches[1] }
            if (-not $out.PolicyAssignmentId -and $blob -match 'policyAssignmentId"?\s*:\s*"?(/[^",\s}]+)') { $out.PolicyAssignmentId = $Matches[1] }
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

function Read-YesNo {
    param([string] $Prompt, [string] $Default = "y")
    do {
        $r = Read-Host -Prompt $Prompt
        if ([string]::IsNullOrWhiteSpace($r)) { $r = $Default }
    } while ($r -notmatch "^[YyNn]$")
    return ($r -match "^[Yy]$")
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
Write-Host "  1. Check your Entra directory roles and Azure subscription role (read-only)."
Write-Host "  2. Check required resource providers are registered (read-only)."
Write-Host "  3. Show you the exact resource names (and tags) it will use and let you customize them."
Write-Host "  4. Create a TEMPORARY resource group (or use an existing EMPTY one you name) and attempt to deploy"
Write-Host "     throwaway copies of the resources Nerdio Manager needs, to detect policy blocks."
Write-Host "  5. Optionally test a private endpoint + private DNS, and App Service VNet integration"
Write-Host "     outbound connectivity, in an existing VNet you name or a new one this script creates"
Write-Host "     (both subnets are required together)."
Write-Host "  6. DELETE everything it created, then print a report you can copy/paste to your Nerdio SE."
Write-Host ""
Write-Host -ForegroundColor "Yellow" "It will NOT modify anything outside the test resource group, other than (if you opt in)"
Write-Host -ForegroundColor "Yellow" "creating and then removing a private endpoint in the existing subnet you specify."
Write-Host "Typical runtime: 2-3 minutes."
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

if (-not (Read-YesNo -Prompt "Proceed? [y/N]" -Default "n")) {
    Write-Host -ForegroundColor "Cyan" "Aborted. No changes made."
    return
}
#endregion

# Everything below runs inside try/finally so cleanup always happens.
$CreatedResourceGroup = $false
$ConfigSummary = [ordered]@{}
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
    $SqlSuffix = $SqlSuffix.TrimStart(".")

    # Private DNS zones the installer creates/links for a private deployment (suffixes are
    # environment-aware). Computed once here so both the intake questions and the later private
    # endpoint/DNS test can reference the same list.
    $RequiredPrivateDnsZones = @(
        @{ Purpose = "SQL"; Zone = "privatelink.$SqlSuffix" },
        @{ Purpose = "App Service"; Zone = $(if ($AzEnv.Name -eq "AzureUSGovernment") { "privatelink.azurewebsites.us" } elseif ($AzEnv.Name -eq "AzureChinaCloud") { "privatelink.chinacloudsites.cn" } else { "privatelink.azurewebsites.net" }) },
        @{ Purpose = "Key Vault"; Zone = $(if ($AzEnv.Name -eq "AzureUSGovernment") { "privatelink.vaultcore.usgovcloudapi.net" } elseif ($AzEnv.Name -eq "AzureChinaCloud") { "privatelink.vaultcore.azure.cn" } else { "privatelink.vaultcore.azure.net" }) },
        @{ Purpose = "Blob storage"; Zone = "privatelink.blob.$StorageSuffix" },
        @{ Purpose = "File storage"; Zone = "privatelink.file.$StorageSuffix" },
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
    elseif (Read-YesNo -Prompt "Use an EXISTING (empty) resource group for the test resources? (Selecting 'N' will create a temporary rg. You will be prompted to confirm the name.) [y/N]" -Default "n") {
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
                $Location = ((Read-Host -Prompt "Enter the Azure region for the temporary test resources (e.g. eastus)") -replace "\s", "").ToLower()
                if ([string]::IsNullOrWhiteSpace($Location)) { continue }
                if ($validRegions.Count -gt 0 -and $validRegions -notcontains $Location) {
                    Write-Host -ForegroundColor "Yellow" "  '$Location' is not a valid region. Examples: $((($validRegions | Sort-Object | Select-Object -First 8) -join ', '))..."
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
    $ExistingVnetRg = $null; $ExistingVnetName = $null; $PeSubnetName = $null; $AppSubnetName = $null
    if (Read-YesNo -Prompt "Do you want to deploy Nerdio Manager with PRIVATE ENDPOINTS? [y/N]" -Default "n") {
        $TestPrivate = $true
        $TestVnetIntegration = $true

        if (Read-YesNo -Prompt "Will you deploy to an EXISTING VNet? (Choosing 'n' creates a new VNet; you'll get the option to provide a custom name.) [y/N]" -Default "n") {
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
            Write-Host -ForegroundColor "Cyan" "  Subnets in '$ExistingVnetName': $($subnetNames -join ', ')"
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
        }
        else {
            # New VNet, created by this script alongside the other test resources below. Its name and
            # its two subnets' names go through the same NamePlan editable-name flow as everything else.
            $CreateNewVnet = $true
            $PeSubnetName = "snet-pe"
            $AppSubnetName = "snet-appint"

            # A brand-new VNet has no real DNS configuration to inspect, so (unlike the existing-VNet
            # path, which detects this from the VNet's actual DhcpOptions) we have to ask directly.
            if (Read-YesNo -Prompt "  Will this VNet use Azure Private DNS Zones to resolve the private endpoints (vs. custom/on-prem DNS servers)? [Y/n]" -Default "y") {
                $NewVnetDnsMode = "Azure"
                do { $PrivateDnsZoneSubId = Read-Host -Prompt "    Subscription ID where the Azure Private DNS zones live (or will be created)" } while ([string]::IsNullOrWhiteSpace($PrivateDnsZoneSubId))
                do { $PrivateDnsZoneRg = Read-Host -Prompt "    Resource group name for the Azure Private DNS zones" } while ([string]::IsNullOrWhiteSpace($PrivateDnsZoneRg))
                $ConfigSummary["Private DNS resolution plan (new VNet)"] = "Azure Private DNS Zones - subscription '$PrivateDnsZoneSubId', resource group '$PrivateDnsZoneRg' (recorded only; not verified or modified by this script)"
            }
            else {
                $NewVnetDnsMode = "Custom"
                $zoneList = ($RequiredPrivateDnsZones | ForEach-Object { "$($_.Zone) ($($_.Purpose))" }) -join "; "
                $ConfigSummary["Private DNS resolution plan (new VNet)"] = "Custom/on-prem DNS - the custom DNS server(s) must resolve: $zoneList"
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
        $peStorageDefault = "nmepfpe$(New-RandomString -Length 6)"
        $NamePlan["PeStorage"] = [pscustomobject]@{ Label = "Storage account for private endpoint test"; Value = $peStorageDefault.Substring(0, [Math]::Min(24, $peStorageDefault.Length)).ToLower(); Editable = $true }
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
        foreach ($k in $NamePlan.Keys) {
            $item = $NamePlan[$k]
            if (-not $item.Editable) { continue }
            $custom = Read-Host -Prompt "  New name for $($item.Label) [default: $($item.Value)]"
            if (-not [string]::IsNullOrWhiteSpace($custom)) {
                # Storage accounts and Key Vaults have restricted, length-limited naming rules.
                if ($k -in @("Storage", "PeStorage")) { $custom = ($custom -replace "[^a-zA-Z0-9]", "").ToLower(); $custom = $custom.Substring(0, [Math]::Min(24, $custom.Length)) }
                if ($k -eq "KeyVault") { $custom = ($custom -replace "[^a-zA-Z0-9-]", ""); $custom = $custom.Substring(0, [Math]::Min(24, $custom.Length)) }
                $item.Value = $custom
            }
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
    if ($TestPrivate) { $peStorageName = $NamePlan["PeStorage"].Value; $peName = $NamePlan["PrivateEndpoint"].Value }
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
    if (Read-YesNo -Prompt "Add custom tags to all resources this script creates? [y/N]" -Default "n") {
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
            $policyInfo = Get-PolicyFromError -ExceptionMessage $_.Exception.Message
            $policyName = Resolve-PolicyName -PolicyDefinitionId $policyInfo.PolicyDefinitionId -PolicyAssignmentId $policyInfo.PolicyAssignmentId
            $policySource = if ($policyName -and $policyName -ne $policyInfo.PolicyDefinitionId -and $policyName -ne $policyInfo.PolicyAssignmentId) { "the ARM error" } else { $null }

            # New-AzResourceGroup's RequestDisallowedByPolicy error usually omits the policy identifiers,
            # so fall back to the Activity Log, which records the denied operation with the policy name.
            if (-not $policySource) {
                Write-Host -ForegroundColor "Yellow" "  Resource group creation was blocked by policy. Querying the Activity Log for the specific policy - this can take up to 5 minutes while Azure ingests the event..."
                $al = Get-PolicyFromActivityLog -ResourceGroupName $ResourceGroupName -StartTime $rgCreateStart
                if ($al.Found) {
                    $alName = if ($al.PolicyAssignmentName) { $al.PolicyAssignmentName } elseif ($al.PolicyDefinitionName) { $al.PolicyDefinitionName } else { $null }
                    if (-not $alName) { $alName = Resolve-PolicyName -PolicyDefinitionId $al.PolicyDefinitionId -PolicyAssignmentId $al.PolicyAssignmentId }
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
            Add-Result -Category "Deployability" -Check "Resource group creation" -Result "Fail" -Detail $detail -PolicyName $policyName -Message $policyInfo.Message
            # We return before the ConfigSummary is normally populated, so record enough here that the
            # report still shows the SE what was attempted.
            $ConfigSummary["Run by (signed-in account)"] = $SignedInAccount
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
    $ConfigSummary["Run by (signed-in account)"] = (Get-AzContext).Account.Id
    $ConfigSummary["Subscription"] = "$($Context.Subscription.Name) ($SubscriptionId)"
    $ConfigSummary["Cloud"] = $AzEnv.Name
    $ConfigSummary["Region"] = $Location
    $ConfigSummary["Resource group"] = "$ResourceGroupName $(if ($PendingRgCreate) { '(created by this script)' } else { '(existing, user-supplied)' })"
    foreach ($k in $NamePlan.Keys) {
        if ($k -eq "ResourceGroup") { continue }
        $ConfigSummary["Resource name - $($NamePlan[$k].Label)"] = $NamePlan[$k].Value
    }
    if ($Tags.Count -gt 0) { $ConfigSummary["Tags applied"] = (($Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; ") } else { $ConfigSummary["Tags applied"] = "(none specified)" }
    $ConfigSummary["Private endpoint scenario"] = if ($TestPrivate) { "Yes - $(if ($CreateNewVnet) { 'new' } else { 'existing' }) VNet '$ExistingVnetName' (RG '$ExistingVnetRg'), private endpoint subnet '$PeSubnetName'" } else { "Not tested" }
    $ConfigSummary["App Service VNet integration scenario"] = if ($TestVnetIntegration) { "Yes - app integration subnet '$AppSubnetName' in VNet '$ExistingVnetName'" } else { "Not tested" }
    $ConfigSummary["VNet DNS configuration"] = "Not tested"
    #endregion

    #region Fast checks --------------------------------------------------------------------------
    Write-Host -ForegroundColor "Cyan" "Running permission and resource provider checks..."

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
                Add-Result -Category "Permissions" -Check "Entra role for install" -Result "Pass" -Detail "You have Global Administrator."
            }
            elseif (($templateIds -contains $PRA) -and ($templateIds -contains $CAA)) {
                Add-Result -Category "Permissions" -Check "Entra role for install" -Result "Pass" -Detail "You have Privileged Role Administrator + Cloud Application Administrator."
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

    $direct = $null
    $directError = $null
    try {
        $direct = Get-AzRoleAssignment @principalParam -Scope $subScope -ErrorAction Stop | Where-Object { $_.RoleDefinitionName -eq "Owner" }
    }
    catch {
        $directError = $_.Exception.Message
    }

    $viaGroup = $null
    $viaGroupError = $null
    try {
        $viaGroup = Get-AzRoleAssignment @principalParam -Scope $subScope -ExpandPrincipalGroups -ErrorAction Stop | Where-Object { $_.RoleDefinitionName -eq "Owner" }
    }
    catch {
        $viaGroupError = $_.Exception.Message
    }

    if ($direct) {
        Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Pass" -Detail "Directly assigned Owner."
    }
    elseif ($viaGroup) {
        Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Pass" -Detail "Owner via group membership."
    }
    elseif ($directError -and $viaGroupError) {
        Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Warn" -Detail "Could not evaluate subscription role assignments." -Message "$directError | $viaGroupError"
    }
    elseif ($viaGroupError) {
        Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Warn" -Detail "Owner not detected directly; could not evaluate group-based Owner assignments." -Message $viaGroupError
    }
    else {
        Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Warn" -Detail "Owner not detected on the subscription (or you are a guest). Owner is required to install Nerdio Manager."
    }

    # Resource providers.
    # Providers the installer template deploys, plus the ones NME needs to operate post-install
    # (Compute = session-host VMs, DesktopVirtualization = AVD host pools, RecoveryServices = backup).
    $ResourceProviders = @("Microsoft.KeyVault", "Microsoft.Automation", "Microsoft.Compute",
        "Microsoft.DesktopVirtualization", "Microsoft.Insights",
        "Microsoft.Network", "Microsoft.OperationalInsights", "Microsoft.RecoveryServices",
        "Microsoft.Storage", "Microsoft.Sql", "Microsoft.Web")
    foreach ($rp in $ResourceProviders) {
        try {
            $state = (Get-AzResourceProvider -ProviderNamespace $rp -ErrorAction Stop | Select-Object -First 1).RegistrationState
            if ($state -eq "Registered") { Add-Result -Category "ResourceProviders" -Check $rp -Result "Pass" -Detail "Registered." }
            else { Add-Result -Category "ResourceProviders" -Check $rp -Result "Warn" -Detail "Not registered (state: $state). Register before installing." }
        }
        catch {
            Add-Result -Category "ResourceProviders" -Check $rp -Result "Warn" -Detail "Could not query registration state." -Message $_.Exception.Message
        }
    }

    # NOTE: a read-only Azure Resource Graph scan for Deny-effect policy assignments used to run here.
    # It was removed - in practice it surfaced noise (Deny assignments that never targeted NME resource
    # types) without catching real blocks. Blocking policies are instead detected authoritatively by the
    # Deployability tests below, which report the actual blocking policy by name when a deploy is denied.
    Write-Host ""
    #endregion

    #region Deployability tests (parallel) -------------------------------------------------------
    Write-Host -ForegroundColor "Cyan" "Testing resource deployability (in parallel). This will take several minutes..."

    # Each job returns @{ Target; Ok; Error }. Az context is shared into the thread via -UseNewRunspace:$false default of ThreadJob.
    $jobs = @()

    $jobs += Start-ThreadJob -Name "LogAnalytics" -ScriptBlock {
        param($rg, $name, $loc, $tags)
        try { New-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $name -Location $loc -Sku "PerGB2018" -RetentionInDays 30 -Tag $tags -ErrorAction Stop | Out-Null; @{ Target = "Log Analytics workspace"; Ok = $true; Name = $name; Kind = "law" } }
        catch { @{ Target = "Log Analytics workspace"; Ok = $false; Error = $_.Exception.Message; Name = $name; Kind = "law" } }
    } -ArgumentList $ResourceGroupName, $lawName, $Location, $Tags

    $jobs += Start-ThreadJob -Name "Storage" -ScriptBlock {
        param($rg, $name, $loc, $sku, $tags)
        try {
            New-AzStorageAccount -ResourceGroupName $rg -Name $name -Location $loc -SkuName $sku -Kind "StorageV2" -AccessTier "Hot" `
                -MinimumTlsVersion "TLS1_2" -AllowBlobPublicAccess $false -AllowSharedKeyAccess $true -EnableHttpsTrafficOnly $true -PublicNetworkAccess "Enabled" -Tag $tags -ErrorAction Stop | Out-Null
            @{ Target = "Storage account ($sku)"; Ok = $true; Name = $name; Kind = "storage" }
        }
        catch { @{ Target = "Storage account ($sku)"; Ok = $false; Error = $_.Exception.Message; Name = $name; Kind = "storage" } }
    } -ArgumentList $ResourceGroupName, $stName, $Location, $StorageSku, $Tags

    $jobs += Start-ThreadJob -Name "Sql" -ScriptBlock {
        param($rg, $name, $loc, $cred, $tags)
        try {
            New-AzSqlServer -ResourceGroupName $rg -ServerName $name -Location $loc -ServerVersion "12.0" -MinimalTlsVersion "1.2" `
                -PublicNetworkAccess "Enabled" -SqlAdministratorCredentials $cred -Tag $tags -ErrorAction Stop | Out-Null
            @{ Target = "SQL Server"; Ok = $true; Name = $name; Kind = "sqlserver" }
        }
        catch { @{ Target = "SQL Server"; Ok = $false; Error = $_.Exception.Message; Name = $name; Kind = "sqlserver" } }
    } -ArgumentList $ResourceGroupName, $sqlName, $Location, $sqlCred, $Tags

    $jobs += Start-ThreadJob -Name "AppServicePlan" -ScriptBlock {
        param($rg, $name, $loc, $tags)
        try {
            # B3 == Basic tier, Large worker, Windows (reserved = false). Match the installer's App Service Plan.
            New-AzAppServicePlan -ResourceGroupName $rg -Name $name -Location $loc -Tier "Basic" -WorkerSize "Large" -NumberOfWorkers 1 -Tag $tags -ErrorAction Stop | Out-Null
            @{ Target = "App Service Plan (B3, Windows)"; Ok = $true; Name = $name; Kind = "asp" }
        }
        catch { @{ Target = "App Service Plan (B3, Windows)"; Ok = $false; Error = $_.Exception.Message; Name = $name; Kind = "asp" } }
    } -ArgumentList $ResourceGroupName, $aspName, $Location, $Tags

    $jobs += Start-ThreadJob -Name "KeyVault" -ScriptBlock {
        param($rg, $name, $loc, $tags)
        try {
            New-AzKeyVault -ResourceGroupName $rg -VaultName $name -Location $loc -Sku "Standard" -SoftDeleteRetentionInDays 90 -DisableRbacAuthorization -Tag $tags -ErrorAction Stop | Out-Null
            @{ Target = "Key Vault"; Ok = $true; Name = $name; Kind = "kv" }
        }
        catch { @{ Target = "Key Vault"; Ok = $false; Error = $_.Exception.Message; Name = $name; Kind = "kv" } }
    } -ArgumentList $ResourceGroupName, $kvName, $Location, $Tags

    # NME deploys two Automation Accounts (an updater account with a system-assigned identity, and a
    # scripted-actions account with no identity) - test both, matching the installer template.
    $jobs += Start-ThreadJob -Name "AutomationUpdater" -ScriptBlock {
        param($rg, $name, $loc, $tags)
        try {
            New-AzAutomationAccount -ResourceGroupName $rg -Name $name -Location $loc -Plan "Basic" -AssignSystemIdentity -Tag $tags -ErrorAction Stop | Out-Null
            @{ Target = "Automation Account (updater)"; Ok = $true; Name = $name; Kind = "automation" }
        }
        catch { @{ Target = "Automation Account (updater)"; Ok = $false; Error = $_.Exception.Message; Name = $name; Kind = "automation" } }
    } -ArgumentList $ResourceGroupName, $aaUpdaterName, $Location, $Tags

    $jobs += Start-ThreadJob -Name "AutomationScriptedActions" -ScriptBlock {
        param($rg, $name, $loc, $tags)
        try {
            New-AzAutomationAccount -ResourceGroupName $rg -Name $name -Location $loc -Plan "Basic" -Tag $tags -ErrorAction Stop | Out-Null
            @{ Target = "Automation Account (scripted actions)"; Ok = $true; Name = $name; Kind = "automation" }
        }
        catch { @{ Target = "Automation Account (scripted actions)"; Ok = $false; Error = $_.Exception.Message; Name = $name; Kind = "automation" } }
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
            $polName = Resolve-PolicyName -PolicyDefinitionId $p.PolicyDefinitionId -PolicyAssignmentId $p.PolicyAssignmentId
            $detail = if ($polName) { "Blocked by policy: '$polName'. $($p.Message)" } else { "Failed: $($p.Message)" }
            Add-Result -Category "Deployability" -Check $jr.Target -Result "Fail" -Detail $detail -PolicyName $polName -Message $p.Message
        }
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
            $p = Get-PolicyFromError -ExceptionMessage $_.Exception.Message
            $polName = Resolve-PolicyName -PolicyDefinitionId $p.PolicyDefinitionId -PolicyAssignmentId $p.PolicyAssignmentId
            $detail = if ($polName) { "Blocked by policy: '$polName'. $($p.Message)" } else { "Failed: $($p.Message)" }
            Add-Result -Category "Deployability" -Check "SQL Database (Standard S1, DTU)" -Result "Fail" -Detail $detail -PolicyName $polName -Message $p.Message
        }
    }
    else {
        Add-Result -Category "Deployability" -Check "SQL Database (Standard S1, DTU)" -Result "Warn" -Detail "Skipped - SQL Server was not created."
    }
    Write-Host ""
    #endregion

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
                $dnsServers = if ($usesCustomDns) { "Custom/on-prem DNS (per intake answer)" } else { "Azure Private DNS Zones - subscription '$PrivateDnsZoneSubId', RG '$PrivateDnsZoneRg' (per intake answer)" }
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
            elseif ($CreateNewVnet) {
                # Azure Private DNS Zones chosen for a brand-new VNet - those zones/links belong to a
                # subscription and resource group the user provided at intake. Record and report only;
                # don't check existence/linkage (a fresh VNet won't be linked yet) or modify anything.
                $zoneList = ($RequiredPrivateDnsZones | ForEach-Object { "$($_.Zone) ($($_.Purpose))" }) -join "; "
                Add-Result -Category "PrivateDns" -Check "Private DNS zones" -Result "Info" -Detail "Azure Private DNS Zones selected (subscription '$PrivateDnsZoneSubId', RG '$PrivateDnsZoneRg'). Required zones: $zoneList. Not verified or modified by this script."
            }
            else {
                $allZones = @()
                try { $allZones = Get-AzPrivateDnsZone -ErrorAction Stop } catch {}
                foreach ($rz in $RequiredPrivateDnsZones) {
                    $match = $allZones | Where-Object { $_.Name -eq $rz.Zone }
                    if (-not $match) {
                        Add-Result -Category "PrivateDns" -Check "Private DNS zone: $($rz.Zone)" -Result "Fail" -Detail "MISSING - required for $($rz.Purpose) private endpoints. Create it and link it to '$ExistingVnetName'."
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
                    if ($linked) { Add-Result -Category "PrivateDns" -Check "Private DNS zone: $($rz.Zone)" -Result "Pass" -Detail "Exists and linked to '$ExistingVnetName' ($($rz.Purpose))." }
                    else { Add-Result -Category "PrivateDns" -Check "Private DNS zone: $($rz.Zone)" -Result "Warn" -Detail "Exists but NOT linked to '$ExistingVnetName' ($($rz.Purpose)). Add a virtual network link." }
                }
            }

            # Deploy a private endpoint to a storage account's blob subresource in the named subnet.
            $peStorage = $stName
            $stAcct = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $peStorage -ErrorAction SilentlyContinue
            if (-not $stAcct) {
                $peStorage = $peStorageName
                $stAcct = New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $peStorage -Location $Location -SkuName $StorageSku -Kind "StorageV2" -AccessTier "Hot" -MinimumTlsVersion "TLS1_2" -AllowBlobPublicAccess $false -PublicNetworkAccess "Enabled" -Tag $Tags -ErrorAction Stop
                Add-TrackedResource -Type "storage" -ResourceGroupName $ResourceGroupName -Name $peStorage
            }
            $subnet = $vnet.Subnets | Where-Object { $_.Name -eq $PeSubnetName }
            if (-not $subnet) {
                Add-Result -Category "PrivateEndpoint" -Check "Private endpoint deployment" -Result "Fail" -Detail "Subnet '$PeSubnetName' not found in VNet '$ExistingVnetName'."
            }
            else {
                $plsc = New-AzPrivateLinkServiceConnection -Name "$peName-conn" -PrivateLinkServiceId $stAcct.Id -GroupId "blob" -ErrorAction Stop
                $pe = New-AzPrivateEndpoint -ResourceGroupName $ResourceGroupName -Name $peName -Location $Location -Subnet $subnet -PrivateLinkServiceConnection $plsc -Tag $Tags -ErrorAction Stop
                Add-TrackedResource -Type "privateendpoint" -ResourceGroupName $ResourceGroupName -Name $peName -Id $pe.Id
                Add-Result -Category "PrivateEndpoint" -Check "Private endpoint deployment" -Result "Pass" -Detail "Deployed a private endpoint (blob) into subnet '$PeSubnetName'."

                # Resolution check.
                $peFqdn = "$peStorage.privatelink.blob.$StorageSuffix"
                try {
                    $r = Resolve-DnsName -Name $peFqdn -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
                    if ($r) {
                        $ip = $r.IPAddress
                        $isPrivate = $ip -match "^10\." -or $ip -match "^192\.168\." -or $ip -match "^172\.(1[6-9]|2[0-9]|3[0-1])\."
                        if ($isPrivate) { Add-Result -Category "PrivateEndpoint" -Check "Private DNS resolution" -Result "Pass" -Detail "$peFqdn resolves to private IP $ip." }
                        else { Add-Result -Category "PrivateEndpoint" -Check "Private DNS resolution" -Result "Warn" -Detail "$peFqdn resolves to $ip (not a private IP). This shell may not use the VNet's DNS; verify from within the VNet." }
                    }
                }
                catch {
                    Add-Result -Category "PrivateEndpoint" -Check "Private DNS resolution" -Result "Info" -Detail "Could not resolve $peFqdn from this shell (expected if the shell isn't on the VNet)." -Message $_.Exception.Message
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
                    $swiftUri = "https://management.azure.com$($web.Id)/networkConfig/virtualNetwork?api-version=2023-01-01"
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

                        # Build the outbound endpoint list (environment-aware).
                        if ($AzEnv.Name -eq "AzureUSGovernment") {
                            $endpoints = @("nwp-web-app.azurewebsites.net", "login.microsoftonline.us", "graph.microsoft.us",
                                "login.windows.net", "management.usgovcloudapi.net", "api.github.com", "api.loganalytics.us", "api.applicationinsights.us")
                        }
                        else {
                            $endpoints = @("nwp-web-app.azurewebsites.net", "login.microsoftonline.com", "graph.microsoft.com",
                                "login.windows.net", "management.azure.com", "api.github.com", "api.loganalytics.io", "api.applicationinsights.io")
                        }

                        # Run the outbound test FROM the worker via the Kudu/SCM command API so it uses
                        # the VNet's real routing and DNS - the same approach NmeNetworkTest.ps1 uses.
                        $scmHost = ($web.EnabledHostNames | Where-Object { $_ -match "\.scm\." } | Select-Object -First 1)
                        if (-not $scmHost) { $scmHost = "$webName.scm.azurewebsites.net" }
                        # Newer Az.Accounts returns the token as a SecureString; handle both forms.
                        $rawTok = (Get-AzAccessToken -ResourceUrl "https://management.azure.com" -ErrorAction Stop).Token
                        $kuduToken = if ($rawTok -is [System.Security.SecureString]) { [System.Net.NetworkCredential]::new("", $rawTok).Password } else { $rawTok }
                        $epList = ($endpoints | ForEach-Object { "'$_'" }) -join ","
                        $remoteCmd = "`$ProgressPreference='SilentlyContinue';foreach(`$u in @($epList)){try{`$null=Invoke-RestMethod -Uri (\`"https://`$u\`") -TimeoutSec 15 -ErrorAction SilentlyContinue}catch{};`$sp=[System.Net.ServicePointManager]::FindServicePoint(\`"https://`$u\`");`$sub=try{`$sp.Certificate.Subject}catch{''};Write-Output (\`"`$u|OK|`$sub\`")}"
                        $kbody = @{ command = "powershell -NoProfile -Command `"$remoteCmd`""; dir = "site\\wwwroot" } | ConvertTo-Json
                        $headers = @{ Authorization = "Bearer $kuduToken"; "Content-Type" = "application/json" }
                        try {
                            $kresp = Invoke-RestMethod -Method POST -Uri "https://$scmHost/api/command" -Headers $headers -Body $kbody -TimeoutSec 120 -ErrorAction Stop
                            $outLines = @()
                            if ($kresp.Output) { $outLines = $kresp.Output -split "`n" | Where-Object { $_ -match "\|OK\|" } }
                            foreach ($ep in $endpoints) {
                                $line = $outLines | Where-Object { $_ -like "$ep*" } | Select-Object -First 1
                                if ($line) {
                                    $subject = ($line -split "\|")[2]
                                    Add-Result -Category "Connectivity" -Check "Outbound: $ep" -Result "Pass" -Detail "Reachable from the VNet-integrated worker. Cert: $subject"
                                }
                                else {
                                    Add-Result -Category "Connectivity" -Check "Outbound: $ep" -Result "Warn" -Detail "No confirmation from the worker - may be blocked. $NmeNetworkTestHint"
                                }
                            }
                        }
                        catch {
                            Add-Result -Category "Connectivity" -Check "Kudu outbound test" -Result "Warn" -Detail "Could not run the in-worker connectivity test via Kudu. From the App Service Kudu console for '$webName': $NmeNetworkTestHint Endpoints to test: $($endpoints -join ', ')." -Message $_.Exception.Message
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
    try {
        [pscustomobject]@{ Metadata = $summaryMeta; Configuration = $ConfigSummary; Results = $Results; CreatedResources = $Tracker } |
            ConvertTo-Json -Depth 8 | Out-File -FilePath $OutFile -Force
        Write-Host -ForegroundColor "Cyan" "Detailed results written to: $OutFile"
    }
    catch { Write-Host -ForegroundColor "Yellow" "Could not write JSON output: $($_.Exception.Message)" }

    # Copy/paste report.
    $counts = $Results | Group-Object Result | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Write-Host ""
    Write-Host -ForegroundColor "Green" "====== COPY EVERYTHING BELOW AND SEND TO YOUR NERDIO SE ======"
    Write-Host ""
    Write-Host "## Nerdio Manager Deployment Readiness Report"
    Write-Host "- Date: $($summaryMeta.TimestampUtc)"
    Write-Host "- Subscription: $($summaryMeta.SubscriptionId)"
    Write-Host "- Cloud / Region: $($summaryMeta.Cloud) / $($summaryMeta.Region)"
    Write-Host "- Summary: $($counts -join '  ')"
    Write-Host ""
    Write-Host "### Configuration used (reference for install)"
    Write-Host "| Setting | Value |"
    Write-Host "|---|---|"
    foreach ($ck in $ConfigSummary.Keys) {
        $cv = ($ConfigSummary[$ck] -replace "\|", "/") -replace "[\r\n]+", " "
        Write-Host "| $ck | $cv |"
    }
    Write-Host ""
    Write-Host "### Check results"
    Write-Host "| Category | Check | Result | Detail |"
    Write-Host "|---|---|---|---|"
    foreach ($r in $Results) {
        $d = ($r.Detail -replace "\|", "/") -replace "[\r\n]+", " "
        Write-Host "| $($r.Category) | $(($r.Check -replace '\|','/')) | $($r.Result) | $d |"
    }
    Write-Host ""
    Write-Host -ForegroundColor "Green" "====== END - COPY EVERYTHING ABOVE ======"
    Write-Host ""
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
