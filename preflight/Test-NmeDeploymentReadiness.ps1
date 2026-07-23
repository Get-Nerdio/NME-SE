<#
    .SYNOPSIS
        Nerdio Manager for Enterprise (NME) deployment readiness pre-flight.

    .DESCRIPTION
        Validates that a target Azure environment can host a Nerdio Manager for Enterprise
        deployment. It runs, in parallel where possible:
          * Permission checks   - Entra directory roles (WITHOUT the Microsoft.Graph module) and
                                   Azure Owner on the subscription.
          * Resource providers  - registration state of the providers NME requires.
          * Policy scan          - Azure Resource Graph query for Deny-effect policy assignments.
          * Deployability tests  - deploys throwaway copies of the exact resources (matching SKUs)
                                   NME's installer creates, to surface Azure Policy blocks. Reports
                                   the blocking policy by name where possible.
          * Private endpoint/DNS - (optional) deploys a private endpoint into an existing VNet and
                                   reports which required private DNS zones are missing / not linked.
          * Outbound connectivity- (optional) tests App Service VNet-integration outbound access to
                                   the endpoints NME requires, from inside an App Service worker.

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
    [System.String] $OutFile = $(if ($Env:AZD_IN_CLOUDSHELL -eq 1) { Join-Path -Path $PWD -ChildPath "NmeReadinessOutput.json" } else { Join-Path -Path $PWD -ChildPath "NmeReadinessOutput.json" })
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
        [Parameter(Mandatory = $true)][ValidateSet("Permissions", "ResourceProviders", "Policy", "Deployability", "PrivateDns", "PrivateEndpoint", "Connectivity", "Info")][string] $Category,
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

# Resolve a policy definition/assignment id (or the deny-scan cache) to a friendly display name.
function Resolve-PolicyName {
    param(
        [string] $PolicyDefinitionId,
        [string] $PolicyAssignmentId,
        [hashtable] $DenyCache
    )
    $name = $null
    if ($PolicyAssignmentId) {
        try { $name = (Get-AzPolicyAssignment -Id $PolicyAssignmentId -ErrorAction Stop).Properties.DisplayName } catch {}
    }
    if (-not $name -and $PolicyDefinitionId) {
        if ($DenyCache -and $DenyCache.ContainsKey($PolicyDefinitionId)) { $name = $DenyCache[$PolicyDefinitionId] }
        if (-not $name) {
            try { $name = (Get-AzPolicyDefinition -Id $PolicyDefinitionId -ErrorAction Stop).Properties.DisplayName } catch {}
        }
    }
    if (-not $name) { $name = $PolicyAssignmentId; if (-not $name) { $name = $PolicyDefinitionId } }
    return $name
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
Write-Host "  2. Check required resource providers and scan for Deny-effect Azure Policies (read-only)."
Write-Host "  3. Create a TEMPORARY resource group (or use one you name) and attempt to deploy"
Write-Host "     throwaway copies of the resources Nerdio Manager needs, to detect policy blocks."
Write-Host "  4. Optionally test a private endpoint + private DNS in an EXISTING VNet you name."
Write-Host "  5. Optionally test App Service VNet-integration outbound connectivity."
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

if (-not (Read-YesNo -Prompt "Proceed? [y/n]" -Default "n")) {
    Write-Host -ForegroundColor "Cyan" "Aborted. No changes made."
    return
}
#endregion

# Everything below runs inside try/finally so cleanup always happens.
$CreatedResourceGroup = $false
try {
    #region Intake -------------------------------------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        do { $SubscriptionId = Read-Host -Prompt "Enter the target Azure subscription id (GUID)" }
        while ($SubscriptionId -notmatch "^[0-9a-fA-F-]{36}$")
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
    $SqlSuffix = $SqlSuffix.TrimStart(".")

    # Resource group: existing or temporary.
    if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
        if ([string]::IsNullOrWhiteSpace($Location)) {
            do { $Location = Read-Host -Prompt "Enter the Azure region for the temporary test resources (e.g. eastus)" }
            while ([string]::IsNullOrWhiteSpace($Location))
        }
        $ResourceGroupName = "rg-nme-preflight-$(New-RandomString -Length 6)"
        Write-Host -ForegroundColor "Cyan" "Creating temporary resource group '$ResourceGroupName' in '$Location'."
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Tag @{ Application = "Nerdio Manager"; Environment = "Preflight" } -ErrorAction Stop | Out-Null
        $CreatedResourceGroup = $true
        $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
    }
    else {
        $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
        $Location = $ResourceGroup.Location
        Write-Host -ForegroundColor "Green" "[$([char]0x2713)] Using existing resource group '$ResourceGroupName' in '$Location'."
    }

    # Private-network scenarios.
    $TestPrivate = $false
    $TestVnetIntegration = $false
    $ExistingVnetRg = $null; $ExistingVnetName = $null; $PeSubnetName = $null; $AppSubnetName = $null
    if (Read-YesNo -Prompt "Will you deploy NME into an EXISTING VNet using PRIVATE ENDPOINTS? [y/n]" -Default "n") {
        $TestPrivate = $true
        do { $ExistingVnetRg = Read-Host -Prompt "  Existing VNet's resource group name" } while ([string]::IsNullOrWhiteSpace($ExistingVnetRg))
        do { $ExistingVnetName = Read-Host -Prompt "  Existing VNet name" } while ([string]::IsNullOrWhiteSpace($ExistingVnetName))
        do { $PeSubnetName = Read-Host -Prompt "  Subnet name for private endpoints" } while ([string]::IsNullOrWhiteSpace($PeSubnetName))
        if (Read-YesNo -Prompt "Will the Nerdio Manager App Service use regional VNet INTEGRATION into that network? [y/n]" -Default "n") {
            $TestVnetIntegration = $true
            do { $AppSubnetName = Read-Host -Prompt "  Subnet name for App Service integration (delegated to Microsoft.Web/serverFarms)" } while ([string]::IsNullOrWhiteSpace($AppSubnetName))
        }
    }

    $IncludeAutomation = Read-YesNo -Prompt "Include the Automation Account deployability test? (subscriptions have Automation account limits) [y/n]" -Default "y"
    Write-Host ""
    #endregion

    #region Fast checks --------------------------------------------------------------------------
    Write-Host -ForegroundColor "Cyan" "Running permission and policy checks..."

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
    try {
        $subScope = "/subscriptions/$SubscriptionId"
        $acct = (Get-AzContext).Account.Id
        $direct = Get-AzRoleAssignment -SignInName $acct -Scope $subScope -ErrorAction SilentlyContinue | Where-Object { $_.RoleDefinitionName -eq "Owner" }
        $viaGroup = Get-AzRoleAssignment -SignInName $acct -Scope $subScope -ExpandPrincipalGroups -ErrorAction SilentlyContinue | Where-Object { $_.RoleDefinitionName -eq "Owner" }
        if ($direct) {
            Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Pass" -Detail "Directly assigned Owner."
        }
        elseif ($viaGroup) {
            Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Pass" -Detail "Owner via group membership."
        }
        else {
            Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Warn" -Detail "Owner not detected on the subscription (or you are a guest). Owner is required to install Nerdio Manager."
        }
    }
    catch {
        Add-Result -Category "Permissions" -Check "Azure Owner on subscription" -Result "Warn" -Detail "Could not evaluate subscription role assignments." -Message $_.Exception.Message
    }

    # Resource providers.
    $ResourceProviders = @("Microsoft.KeyVault", "Microsoft.Automation", "Microsoft.Compute",
        "Microsoft.DocumentDB", "Microsoft.DesktopVirtualization", "Microsoft.Insights",
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

    # Deny-effect policy scan via Azure Resource Graph. Cache definition id -> display name.
    $DenyCache = @{}
    try {
        $kqlPath = Join-Path -Path $PSScriptRoot -ChildPath "deny-policyassignments.kql"
        if ($PSScriptRoot -and (Test-Path -Path $kqlPath)) {
            $kql = Get-Content -Path $kqlPath -Raw
        }
        else {
            $kql = @"
policyresources
| where type == "microsoft.authorization/policyassignments"
| extend definitionId = tostring(properties.policyDefinitionId),
         assignmentEffect = tostring(properties.parameters.effect.value)
| join kind=leftouter (
    policyresources
    | where type == "microsoft.authorization/policydefinitions"
    | extend defaultEffect = tostring(properties.parameters.effect.defaultValue),
             hardCodedEffect = tostring(properties.policyRule.then.effect),
             policyDisplayName = tostring(properties.displayName)
    | project definitionId = id, policyDisplayName, hardCodedEffect, defaultEffect
) on definitionId
| extend resolvedEffect = case(
    isnotempty(assignmentEffect), assignmentEffect,
    isnotempty(hardCodedEffect) and hardCodedEffect !~ "[parameters('effect')]", hardCodedEffect,
    isnotempty(defaultEffect), defaultEffect, "unknown")
| where resolvedEffect == "Deny"
| project assignmentId = id, assignmentName = name, scope = tostring(properties.scope), policyDisplayName, definitionId, resolvedEffect
"@
        }
        $deny = Search-AzGraph -Query $kql -ErrorAction Stop
        if ($deny -and $deny.Count -gt 0) {
            foreach ($d in $deny) {
                if ($d.definitionId -and -not $DenyCache.ContainsKey($d.definitionId)) { $DenyCache[$d.definitionId] = $d.policyDisplayName }
            }
            Add-Result -Category "Policy" -Check "Deny-effect policy assignments" -Result "Warn" -Detail "$($deny.Count) Deny policy assignment(s) in scope. Review the ones that target NME resource types (see JSON output)."
            foreach ($d in ($deny | Select-Object -First 25)) {
                Add-Result -Category "Policy" -Check "Deny policy: $($d.policyDisplayName)" -Result "Info" -Detail "Scope: $($d.scope)" -PolicyName $d.policyDisplayName
            }
        }
        else {
            Add-Result -Category "Policy" -Check "Deny-effect policy assignments" -Result "Pass" -Detail "No Deny-effect policy assignments found in accessible scope."
        }
    }
    catch {
        Add-Result -Category "Policy" -Check "Deny-effect policy assignments" -Result "Warn" -Detail "Resource Graph scan failed (Az.ResourceGraph / Resource Policy Reader may be unavailable)." -Message $_.Exception.Message
    }
    Write-Host ""
    #endregion

    #region Deployability tests (parallel) -------------------------------------------------------
    Write-Host -ForegroundColor "Cyan" "Testing resource deployability (in parallel). This is the slow part..."

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

    # Names
    $lawName = "log-nmepf-$locSlug-$rand"
    $stName = ("nmepf$rand").Substring(0, [Math]::Min(24, ("nmepf$rand").Length)).ToLower()
    $sqlName = "nmepf-sql-$rand"
    $dbName = "nmepfdb"
    $aspName = "asp-nmepf-$rand"
    $kvName = ("kv-nmepf-$rand"); if ($kvName.Length -gt 24) { $kvName = $kvName.Substring(0, 24) }
    $aaName = "aa-nmepf-$rand"

    # Each job returns @{ Target; Ok; Error }. Az context is shared into the thread via -UseNewRunspace:$false default of ThreadJob.
    $jobs = @()

    $jobs += Start-ThreadJob -Name "LogAnalytics" -ScriptBlock {
        param($rg, $name, $loc)
        try { New-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $name -Location $loc -Sku "PerGB2018" -RetentionInDays 30 -ErrorAction Stop | Out-Null; @{ Target = "Log Analytics workspace"; Ok = $true; Name = $name; Kind = "law" } }
        catch { @{ Target = "Log Analytics workspace"; Ok = $false; Error = $_.Exception.Message; Name = $name; Kind = "law" } }
    } -ArgumentList $ResourceGroupName, $lawName, $Location

    $jobs += Start-ThreadJob -Name "Storage" -ScriptBlock {
        param($rg, $name, $loc, $sku)
        try {
            New-AzStorageAccount -ResourceGroupName $rg -Name $name -Location $loc -SkuName $sku -Kind "StorageV2" -AccessTier "Hot" `
                -MinimumTlsVersion "TLS1_2" -AllowBlobPublicAccess $false -AllowSharedKeyAccess $true -EnableHttpsTrafficOnly $true -PublicNetworkAccess "Enabled" -ErrorAction Stop | Out-Null
            @{ Target = "Storage account ($sku)"; Ok = $true; Name = $name; Kind = "storage" }
        }
        catch { @{ Target = "Storage account ($sku)"; Ok = $false; Error = $_.Exception.Message; Name = $name; Kind = "storage" } }
    } -ArgumentList $ResourceGroupName, $stName, $Location, $StorageSku

    $jobs += Start-ThreadJob -Name "Sql" -ScriptBlock {
        param($rg, $name, $loc, $cred)
        try {
            New-AzSqlServer -ResourceGroupName $rg -ServerName $name -Location $loc -ServerVersion "12.0" -MinimalTlsVersion "1.2" `
                -PublicNetworkAccess "Enabled" -SqlAdministratorCredentials $cred -ErrorAction Stop | Out-Null
            @{ Target = "SQL Server"; Ok = $true; Name = $name; Kind = "sqlserver" }
        }
        catch { @{ Target = "SQL Server"; Ok = $false; Error = $_.Exception.Message; Name = $name; Kind = "sqlserver" } }
    } -ArgumentList $ResourceGroupName, $sqlName, $Location, $sqlCred

    $jobs += Start-ThreadJob -Name "AppServicePlan" -ScriptBlock {
        param($rg, $name, $loc)
        try {
            # B3 == Basic tier, Large worker, Windows (reserved = false). Match the installer's App Service Plan.
            New-AzAppServicePlan -ResourceGroupName $rg -Name $name -Location $loc -Tier "Basic" -WorkerSize "Large" -NumberOfWorkers 1 -ErrorAction Stop | Out-Null
            @{ Target = "App Service Plan (B3, Windows)"; Ok = $true; Name = $name; Kind = "asp" }
        }
        catch { @{ Target = "App Service Plan (B3, Windows)"; Ok = $false; Error = $_.Exception.Message; Name = $name; Kind = "asp" } }
    } -ArgumentList $ResourceGroupName, $aspName, $Location

    $jobs += Start-ThreadJob -Name "KeyVault" -ScriptBlock {
        param($rg, $name, $loc)
        try {
            New-AzKeyVault -ResourceGroupName $rg -VaultName $name -Location $loc -Sku "Standard" -SoftDeleteRetentionInDays 90 -DisableRbacAuthorization -ErrorAction Stop | Out-Null
            @{ Target = "Key Vault"; Ok = $true; Name = $name; Kind = "kv" }
        }
        catch { @{ Target = "Key Vault"; Ok = $false; Error = $_.Exception.Message; Name = $name; Kind = "kv" } }
    } -ArgumentList $ResourceGroupName, $kvName, $Location

    if ($IncludeAutomation) {
        $jobs += Start-ThreadJob -Name "Automation" -ScriptBlock {
            param($rg, $name, $loc)
            try {
                New-AzAutomationAccount -ResourceGroupName $rg -Name $name -Location $loc -Plan "Basic" -ErrorAction Stop | Out-Null
                @{ Target = "Automation Account"; Ok = $true; Name = $name; Kind = "automation" }
            }
            catch { @{ Target = "Automation Account"; Ok = $false; Error = $_.Exception.Message; Name = $name; Kind = "automation" } }
        } -ArgumentList $ResourceGroupName, $aaName, $Location
    }

    $jobResults = $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job -Force -ErrorAction SilentlyContinue

    foreach ($jr in $jobResults) {
        if ($jr.Ok) {
            Add-Result -Category "Deployability" -Check $jr.Target -Result "Pass" -Detail "Created successfully."
            Add-TrackedResource -Type $jr.Kind -ResourceGroupName $ResourceGroupName -Name $jr.Name
        }
        else {
            $p = Get-PolicyFromError -ExceptionMessage $jr.Error
            $polName = Resolve-PolicyName -PolicyDefinitionId $p.PolicyDefinitionId -PolicyAssignmentId $p.PolicyAssignmentId -DenyCache $DenyCache
            $detail = if ($polName) { "Blocked by policy: '$polName'." } else { "Failed - see message." }
            Add-Result -Category "Deployability" -Check $jr.Target -Result "Fail" -Detail $detail -PolicyName $polName -Message $p.Message
        }
    }

    # SQL database (depends on SQL server having been created).
    $sqlOk = ($jobResults | Where-Object { $_.Kind -eq "sqlserver" -and $_.Ok })
    if ($sqlOk) {
        try {
            New-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $sqlName -DatabaseName $dbName `
                -Edition "Standard" -RequestedServiceObjectiveName "S1" -CollationName "SQL_Latin1_General_CP1_CI_AS" -ErrorAction Stop | Out-Null
            Add-Result -Category "Deployability" -Check "SQL Database (Standard S1, DTU)" -Result "Pass" -Detail "Created successfully."
            Add-TrackedResource -Type "sqldatabase" -ResourceGroupName $ResourceGroupName -Name $dbName -Note $sqlName
        }
        catch {
            $p = Get-PolicyFromError -ExceptionMessage $_.Exception.Message
            $polName = Resolve-PolicyName -PolicyDefinitionId $p.PolicyDefinitionId -PolicyAssignmentId $p.PolicyAssignmentId -DenyCache $DenyCache
            $detail = if ($polName) { "Blocked by policy: '$polName'." } else { "Failed - see message." }
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
            $dnsServers = if ($vnet.DhcpOptions.DnsServers -and $vnet.DhcpOptions.DnsServers.Count -gt 0) { $vnet.DhcpOptions.DnsServers -join ", " } else { "Azure-provided default (168.63.129.16)" }
            Add-Result -Category "PrivateDns" -Check "VNet DNS configuration" -Result "Info" -Detail "VNet '$ExistingVnetName' custom DNS servers: $dnsServers"

            # Required private DNS zones the installer creates/links (suffixes are environment-aware).
            $requiredZones = @(
                @{ Purpose = "SQL"; Zone = "privatelink.$SqlSuffix" },
                @{ Purpose = "App Service"; Zone = $(if ($AzEnv.Name -eq "AzureUSGovernment") { "privatelink.azurewebsites.us" } elseif ($AzEnv.Name -eq "AzureChinaCloud") { "privatelink.chinacloudsites.cn" } else { "privatelink.azurewebsites.net" }) },
                @{ Purpose = "Key Vault"; Zone = "privatelink.$KeyVaultSuffix" },
                @{ Purpose = "Blob storage"; Zone = "privatelink.blob.$StorageSuffix" },
                @{ Purpose = "File storage"; Zone = "privatelink.file.$StorageSuffix" },
                @{ Purpose = "Automation"; Zone = $(if ($AzEnv.Name -eq "AzureUSGovernment") { "privatelink.azure-automation.us" } elseif ($AzEnv.Name -eq "AzureChinaCloud") { "privatelink.azure-automation.cn" } else { "privatelink.azure-automation.net" }) }
            )
            $allZones = @()
            try { $allZones = Get-AzPrivateDnsZone -ErrorAction Stop } catch {}
            foreach ($rz in $requiredZones) {
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

            # Deploy a private endpoint to a storage account's blob subresource in the named subnet.
            $peStorage = $stName
            $stAcct = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $peStorage -ErrorAction SilentlyContinue
            if (-not $stAcct) {
                $peStorage = ("nmepfpe$(New-RandomString -Length 6)").Substring(0, 24).ToLower()
                $stAcct = New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $peStorage -Location $Location -SkuName $StorageSku -Kind "StorageV2" -AccessTier "Hot" -MinimumTlsVersion "TLS1_2" -AllowBlobPublicAccess $false -PublicNetworkAccess "Enabled" -ErrorAction Stop
                Add-TrackedResource -Type "storage" -ResourceGroupName $ResourceGroupName -Name $peStorage
            }
            $subnet = $vnet.Subnets | Where-Object { $_.Name -eq $PeSubnetName }
            if (-not $subnet) {
                Add-Result -Category "PrivateEndpoint" -Check "Private endpoint deployment" -Result "Fail" -Detail "Subnet '$PeSubnetName' not found in VNet '$ExistingVnetName'."
            }
            else {
                $peName = "pe-nmepf-$rand"
                $plsc = New-AzPrivateLinkServiceConnection -Name "$peName-conn" -PrivateLinkServiceId $stAcct.Id -GroupId "blob" -ErrorAction Stop
                $pe = New-AzPrivateEndpoint -ResourceGroupName $ResourceGroupName -Name $peName -Location $Location -Subnet $subnet -PrivateLinkServiceConnection $plsc -ErrorAction Stop
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
        Write-Host -ForegroundColor "Cyan" "Testing App Service VNet-integration outbound connectivity..."
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
                    $planName = "asp-nmepfconn-$rand"
                    New-AzAppServicePlan -ResourceGroupName $ResourceGroupName -Name $planName -Location $Location -Tier "Basic" -WorkerSize "Small" -NumberOfWorkers 1 -ErrorAction Stop | Out-Null
                    Add-TrackedResource -Type "asp" -ResourceGroupName $ResourceGroupName -Name $planName
                    $webName = "app-nmepfconn-$rand"
                    $web = New-AzWebApp -ResourceGroupName $ResourceGroupName -Name $webName -Location $Location -AppServicePlan $planName -ErrorAction Stop
                    Add-TrackedResource -Type "webapp" -ResourceGroupName $ResourceGroupName -Name $webName -Id $web.Id

                    # Enable regional VNet integration via the swift-connection REST call.
                    $swiftUri = "https://management.azure.com$($web.Id)/networkConfig/virtualNetwork?api-version=2023-01-01"
                    $swiftBody = @{ properties = @{ subnetResourceId = $appSubnet.Id; swiftSupported = $true } } | ConvertTo-Json -Depth 5
                    $swift = Invoke-AzRestMethod -Method PUT -Uri $swiftUri -Payload $swiftBody -ErrorAction Stop
                    if ($swift.StatusCode -ge 200 -and $swift.StatusCode -lt 300) {
                        Add-Result -Category "Connectivity" -Check "VNet integration" -Result "Pass" -Detail "Regional VNet integration enabled to '$AppSubnetName'."
                        # Route all traffic through the VNet so the test reflects NME behavior.
                        try { Set-AzWebApp -ResourceGroupName $ResourceGroupName -Name $webName -AppSettings @{ WEBSITE_VNET_ROUTE_ALL = "1" } -ErrorAction SilentlyContinue | Out-Null } catch {}
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
                                    Add-Result -Category "Connectivity" -Check "Outbound: $ep" -Result "Warn" -Detail "No confirmation from the worker - may be blocked. Verify with NmeNetworkTest.ps1 after install."
                                }
                            }
                        }
                        catch {
                            Add-Result -Category "Connectivity" -Check "Kudu outbound test" -Result "Warn" -Detail "Could not run the in-worker connectivity test via Kudu. After installing NME, run NmeNetworkTest.ps1 from the App Service Kudu console to test these endpoints: $($endpoints -join ', ')." -Message $_.Exception.Message
                        }
                    }
                    else {
                        Add-Result -Category "Connectivity" -Check "VNet integration" -Result "Warn" -Detail "Could not enable VNet integration (HTTP $($swift.StatusCode)). After install, verify outbound access with NmeNetworkTest.ps1." -Message $swift.Content
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
        [pscustomobject]@{ Metadata = $summaryMeta; Results = $Results; CreatedResources = $Tracker } |
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
        # Reverse the tracker so dependents are removed before dependencies.
        for ($i = $Tracker.Count - 1; $i -ge 0; $i--) {
            $t = $Tracker[$i]
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
