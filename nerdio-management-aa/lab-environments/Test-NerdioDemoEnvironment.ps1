<#
.SYNOPSIS
  Validates that the NME demo environment is configured correctly.

.DESCRIPTION
  This runbook runs periodically to ensure that the shared demo NME environment
  has the expected configuration. Currently it checks:

  1. FSLogix profile "DemoEnvironmentFslConfig" exists, is set as default, and
     has the correct properties (profile container location, Entra ID Kerberos, etc.).
     If missing, it is created. If misconfigured, it is corrected.

  2. The Azure Files share used by FSLogix is linked in NME. If not linked, the
     storage account is looked up in Azure and the share is re-linked.

  Additional checks can be added to this runbook over time.

.PARAMETER VariablePrefix
  Prefix for automation account variables. Defaults to 'CustomerDemo'.

.EXAMPLE
  .\Test-NerdioDemoEnvironment.ps1
  .\Test-NerdioDemoEnvironment.ps1 -VariablePrefix 'Prod'
#>

[CmdletBinding()]
param(
    [string]$VariablePrefix = 'CustomerDemo'
)

$ErrorActionPreference = 'Stop'

#region Helpers

function Write-Log {
    param(
        [string] $Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string] $Level = 'INFO'
    )
    $stamp = (Get-Date).ToString('u')
    switch ($Level) {
        'INFO'  { Write-Output  "[$stamp] [INFO]  $Message" }
        'WARN'  { Write-Output  "[$stamp] [WARN]  $Message"; Write-Warning "[$stamp] [WARN]  $Message" }
        'ERROR' { Write-Error   "[$stamp] [ERROR] $Message" }
    }
}

#endregion

#region Variables

$NmeTenantId     = Get-AutomationVariable -Name "${VariablePrefix}TenantId"
$NmeClientId     = Get-AutomationVariable -Name "${VariablePrefix}ClientId"
$NmeClientSecret = Get-AutomationVariable -Name "${VariablePrefix}ClientSecret"
$NmeScope        = Get-AutomationVariable -Name "${VariablePrefix}Scope"
$NmeUri          = Get-AutomationVariable -Name "${VariablePrefix}Uri"
$SubscriptionId  = Get-AutomationVariable -Name "${VariablePrefix}SubscriptionId"

$FslStorageAccountName = Get-AutomationVariable -Name "${VariablePrefix}-FslStorageAccount"
$FslShareName          = Get-AutomationVariable -Name "${VariablePrefix}-FslShareName"

#endregion

#region Authentication

# Connect to Azure using automation account managed identity
Disable-AzContextAutosave -Scope Process | Out-Null
Connect-AzAccount -Identity -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
Write-Log "Connected to Azure subscription $SubscriptionId."

# Connect to NME API
Import-Module NerdioManagerPowerShell -Force
Connect-Nme -ClientId $NmeClientId -ClientSecret $NmeClientSecret -TenantId $NmeTenantId -ApiScope $NmeScope -NmeUri $NmeUri | Out-Null
Write-Log "Connected to NME API at $NmeUri."

#endregion

#region Expected FSLogix configuration

$ExpectedFslProfileName = 'DemoEnvironmentFslConfig'
$ExpectedProfileContainerLocation = "\\$FslStorageAccountName.file.core.windows.net\$FslShareName"

#endregion

#region 1. Validate FSLogix profile

Write-Log "Checking FSLogix profiles..."
$fslProfiles = Get-NmeFslogixProfile
$demoProfile = $fslProfiles | Where-Object { $_.Name -eq $ExpectedFslProfileName }

if (-not $demoProfile) {
    Write-Log "FSLogix profile '$ExpectedFslProfileName' not found. Creating it..." 'WARN'

    $installer = New-NmeInstaller -Version '' -ForceUpdate $false
    $profileContainer = New-NmeRegistry -Locations @($ExpectedProfileContainerLocation) -Options ''
    $officeContainer = New-NmeRegistry -Locations @() -Options ''
    $exclusions = New-NmeExclusions -ExclusionMode 'None'
    $appServiceRegistryOptions = New-NmeOptionalRegistrySettings -RegistryOptionsMode 'None' -RegistryOptions ''
    $logRegistryOptions = New-NmeOptionalRegistrySettings -RegistryOptionsMode 'None' -RegistryOptions ''

    $properties = New-NmeProperties `
        -Installer $installer `
        -ProfileContainer $profileContainer `
        -OfficeContainer $officeContainer `
        -CloudCache $false `
        -PageBlobs $false `
        -EntraIdKerberos $true `
        -RedirectionsXml '' `
        -Exclusions $exclusions `
        -AppServiceRegistryOptions $appServiceRegistryOptions `
        -LogRegistryOptions $logRegistryOptions

    $newProfile = New-NmeFsLogixParamsRest_POST -Name $ExpectedFslProfileName -IsDefault $true -Properties $properties
    New-NmeFslogixProfile -NmeFsLogixParamsRest_POST $newProfile
    Write-Log "FSLogix profile '$ExpectedFslProfileName' created and set as default."
} else {
    Write-Log "FSLogix profile '$ExpectedFslProfileName' found (Id: $($demoProfile.Id))."
    $needsUpdate = $false
    $issues = @()

    # Check IsDefault
    if (-not $demoProfile.IsDefault) {
        $issues += 'IsDefault is false (expected true)'
        $needsUpdate = $true
    }

    # Check profile container location
    $currentLocations = $demoProfile.Properties.profileContainer.locations
    if (-not $currentLocations -or $currentLocations[0] -ne $ExpectedProfileContainerLocation) {
        $issues += "Profile container location is '$($currentLocations -join ', ')' (expected '$ExpectedProfileContainerLocation')"
        $needsUpdate = $true
    }

    # Check Entra ID Kerberos
    if (-not $demoProfile.Properties.entraIdKerberos) {
        $issues += 'EntraIdKerberos is false (expected true)'
        $needsUpdate = $true
    }

    # Check cloud cache is disabled
    if ($demoProfile.Properties.cloudCache) {
        $issues += 'CloudCache is true (expected false)'
        $needsUpdate = $true
    }

    # Check page blobs is disabled
    if ($demoProfile.Properties.pageBlobs) {
        $issues += 'PageBlobs is true (expected false)'
        $needsUpdate = $true
    }

    if ($needsUpdate) {
        Write-Log "FSLogix profile has configuration issues: $($issues -join '; '). Correcting..." 'WARN'

        $installer = New-NmeInstaller -Version '' -ForceUpdate $false
        $profileContainer = New-NmeRegistry -Locations @($ExpectedProfileContainerLocation) -Options ''
        $officeContainer = New-NmeRegistry -Locations @() -Options ''
        $exclusions = New-NmeExclusions -ExclusionMode 'None'
        $appServiceRegistryOptions = New-NmeOptionalRegistrySettings -RegistryOptionsMode 'None' -RegistryOptions ''
        $logRegistryOptions = New-NmeOptionalRegistrySettings -RegistryOptionsMode 'None' -RegistryOptions ''

        $properties = New-NmeProperties `
            -Installer $installer `
            -ProfileContainer $profileContainer `
            -OfficeContainer $officeContainer `
            -CloudCache $false `
            -PageBlobs $false `
            -EntraIdKerberos $true `
            -RedirectionsXml '' `
            -Exclusions $exclusions `
            -AppServiceRegistryOptions $appServiceRegistryOptions `
            -LogRegistryOptions $logRegistryOptions

        $patchObj = New-NmeFsLogixParamsRest_PATCH -Name $ExpectedFslProfileName -IsDefault $true -Properties $properties
        Set-NmeFslogixProfileById -Id $demoProfile.Id -NmeFsLogixParamsRest_PATCH $patchObj
        Write-Log "FSLogix profile '$ExpectedFslProfileName' corrected."
    } else {
        Write-Log "FSLogix profile '$ExpectedFslProfileName' is correctly configured."
    }
}

#endregion

#region 2. Validate Azure Files link

Write-Log "Checking Azure Files link for '$FslStorageAccountName/$FslShareName'..."
$linkedShares = Get-NmeAzureFiles
$isLinked = $linkedShares | Where-Object {
    $_.Id -match "/storageAccounts/$FslStorageAccountName/fileServices/default/shares/$FslShareName$"
}

if (-not $isLinked) {
    Write-Log "Azure Files share '$FslStorageAccountName/$FslShareName' is not linked in NME. Re-linking..." 'WARN'

    # Look up storage account in Azure to get its resource group
    $storageAccount = Get-AzStorageAccount | Where-Object { $_.StorageAccountName -eq $FslStorageAccountName }
    if (-not $storageAccount) {
        Write-Log "Storage account '$FslStorageAccountName' not found in subscription '$SubscriptionId'." 'ERROR'
    } else {
        $saResourceGroup = $storageAccount.ResourceGroupName
        New-NmeAzureFilesLink -SubscriptionId $SubscriptionId -ResourceGroup $saResourceGroup -AccountName $FslStorageAccountName -ShareName $FslShareName
        Write-Log "Azure Files share '$FslStorageAccountName/$FslShareName' linked (RG: $saResourceGroup)."
    }
} else {
    Write-Log "Azure Files share '$FslStorageAccountName/$FslShareName' is already linked."
}

#endregion

#region Summary

Write-Log ""
Write-Log "=== DEMO ENVIRONMENT VALIDATION COMPLETE ==="

#endregion
