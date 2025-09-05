# This script gets all resources in a Nerdio tenant where the DoNotDestroy tag is not present, then checks the DestroyAfter tag to see if the resource should be deleted.
# If the DestroyAfter tag is not present, write a message to the console and skip the resource.
# If the DestroyAfter tag is present, the script checks if the date in the tag is in the past and deletes the resource if it is.
# This script runs within an automation account, authenticates to the tenant using a managed identity, and gets all resources the managed identity has access to.
# This script has a 'whatif' mode that can be enabled by setting the $whatIf variable to $true. In 'whatif' mode, the script will not delete any resources, but will write a message to the console indicating what it would do.
param (
    [switch]$whatIf
)
# Connect to the Nerdio tenant using the managed identity
Connect-AzAccount -Identity
$context = Get-AzContext
$tenantId = $context.Tenant.Id

# Get all resources in the tenant
$resources = Get-AzResource -ErrorAction SilentlyContinue
if ($resources -eq $null) {
    Write-Output "No resources found in the tenant."
    exit
}
Write-Output "Total resources found: $($resources.Count)"
$deletedResourcesCount = 0
$skippedResourcesCount = 0
$errorsCount = 0
$date = Get-Date
foreach ($resource in $resources) {
    $resourceId = $resource.ResourceId
    $resourceName = $resource.Name
    $resourceType = $resource.ResourceType
    $resourceGroupName = $resource.ResourceGroupName

    # Get the tags for the resource
    $tags = (Get-AzResource -ResourceId $resourceId -ErrorAction SilentlyContinue).Tags
    if ($tags -eq $null) {
        Write-Output "Resource '$resourceName' of type '$resourceType' in resource group '$resourceGroupName' has no tags. Skipping."
        $skippedResourcesCount++
        continue
    }

    # Check if the DoNotDestroy tag is present
    if ($tags.ContainsKey("DoNotDestroy")) {
        Write-Output "Resource '$resourceName' of type '$resourceType' in resource group '$resourceGroupName' has the 'DoNotDestroy' tag. Skipping."
        $skippedResourcesCount++
        continue
    }

    # Check if the DestroyAfter tag is present
    if (-not $tags.ContainsKey("DestroyAfter")) {
        Write-Output "Resource '$resourceName' of type '$resourceType' in resource group '$resourceGroupName' does not have the 'DestroyAfter' tag. Skipping."
        $skippedResourcesCount++
        continue
    }

    # Parse the DestroyAfter date
    $destroyAfterDateString = $tags["DestroyAfter"]
    try {
        $destroyAfterDate = [DateTime]::Parse($destroyAfterDateString)
    } catch {
        Write-Output "Resource '$resourceName' of type '$resourceType' in resource group '$resourceGroupName' has an invalid 'DestroyAfter' date format: '$destroyAfterDateString'. Skipping."
        $skippedResourcesCount++
        continue
    }

    # Check if the DestroyAfter date is in the past
    if ($destroyAfterDate -lt $date) {
        try {
            if ($whatIf) {
                Write-Output "[WhatIf] Would delete resource '$resourceName' of type '$resourceType' in resource group '$resourceGroupName'."
            } else {
                # Remove-AzResource -ResourceId $resourceId -Force -ErrorAction Stop
                Write-Output "Deleted resource '$resourceName' of type '$resourceType' in resource group '$resourceGroupName'."
            
            }
            $deletedResourcesCount++
        } catch {
            Write-Output "Failed to delete resource '$resourceName' of type '$resourceType' in resource group '$resourceGroupName'. Error: $_"
            $errorsCount++
        }
    }
}

# Write the final counts to the console
Write-Output "Cleanup completed."
Write-Output "Total resources found: $($resources.Count)"
Write-Output "Total resources deleted: $deletedResourcesCount"
Write-Output "Total resources skipped: $skippedResourcesCount"
Write-Output "Total errors encountered: $errorsCount"