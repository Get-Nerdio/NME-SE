<#
.SYNOPSIS
Tests connectivity to endpoints required for the proper functioning of the Nerdio Manager application.

.DESCRIPTION
This script is designed to be executed in the Azure App Service debug console for the Nerdio Manager app. 
It verifies network connectivity to critical endpoints that are necessary for the application to operate correctly.
If the script detects a custom name for the app service, it will prompt the user for the FQDNs of the Nerdio Manager Key Vault, SQL Server, and DPS Storage Account.
It also allows for additional URIs to be tested by passing them as parameters.

.PARAMETER AdditionalTestUris
An array of additional URIs to test connectivity against. This is useful for testing custom endpoints or services.

.PARAMETER TlsVersion
The TLS version to use for the connection tests. Default is 'Tls12'. Use 'Tls13' as needed.


.EXAMPLE
To access the Kudu console, select the app service in the Azure portal, go to Development Tools, select Advanced Tools, and then select Go. 
In the Kudu service page, select Tools > Debug Console > PowerShell.

Upload this script to the debug console. Set the $ProgressPreference to 'SilentlyContinue' before executing.

$ProgressPreference = 'SilentlyContinue'
.\NmeNetworkTest.ps1

.NOTES
- Ensure that the script is executed in the Debug console of the Azure App Service hosting the Nerdio Manager app.
- This script is intended for diagnostic purposes to identify potential connectivity issues.
- The script will output the results to a file named NmeNetworkTestOutput.txt in the current directory.
- For further assistance, please contact Nerdio support and supply the output of this test.

.AUTHOR
Nick Wagner

#>

param(
    [string[]]$AdditionalTestUris = @(),
    [string]$TlsVersion = 'Tls12'
)

if ($ProgressPreference -ne 'SilentlyContinue') {
    # we cannot set $ProgressPreference to 'SilentlyContinue' in the Azure Web App environment, so we tell user to set before running the script
    Write-Output "Please set `$ProgressPreference = 'SilentlyContinue' before running this script in the Azure Web App environment."
    Exit
}
$WarningPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'


$DnsServers = $Env:WEBSITE_DNS_SERVER_FROM_VNET -split ','
if ($DnsServers){
    if ($DnsServers[0] -eq '168.63.129.16'){
        $LocalDns = 'AzureDefaultDns'
    }
    else {$LocalDns = $DnsServers[0]}
}
else {
    $LocalDns = 'AzureDefaultDns'
}
if ($Env:WEBSITE_VNET_ROUTE_ALL) {
    $RemoteDns = $LocalDns
}
else {
    $RemoteDns = 'AzureDefaultDns'
}

# set powershell tls version to $TlsVersion
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::$TlsVersion
$ApiEndpoints = @(
    [PSCustomObject]@{ URI = "nwp-web-app.azurewebsites.net"; Port = 443; Purpose = "Nerdio Licensing Servers"; Exceptions = @(); DnsServer = $RemoteDns },
    [PSCustomObject]@{ URI = "login.microsoftonline.com"; Port = 443; Purpose = "Microsoft API Authentication"; Exceptions = @(); DnsServer = $RemoteDns },
    [PSCustomObject]@{ URI = "graph.microsoft.com"; Port = 443; Purpose = "Graph API Authentication"; Exceptions = @(); DnsServer = $RemoteDns },
    [PSCustomObject]@{ URI = "login.windows.net"; Port = 443; Purpose = "Entra ID SQL Authentication"; Exceptions = @(); DnsServer = $RemoteDns },
    [PSCustomObject]@{ URI = "management.azure.com"; Port = 443; Purpose = "Azure API"; Exceptions = @(); DnsServer = $RemoteDns },
    [PSCustomObject]@{ URI = "api.github.com"; Port = 443; Purpose = "Scripted Actions"; Exceptions = @(); DnsServer = $RemoteDns },
    [PSCustomObject]@{ URI = "api.loganalytics.io"; Port = 443; Purpose = "API Access for Log Analytics"; Exceptions = @(); DnsServer = $RemoteDns },
    [PSCustomObject]@{ URI = "api.applicationinsights.io"; Port = 443; Purpose = "API Access for Application Insights"; Exceptions = @(); DnsServer = $RemoteDns }
)

# check if $Env:WEBSITE_HOSTNAME starts with 'nmw-app' and ends with '.azurewebsites.net'
if ($Env:WEBSITE_HOSTNAME -notmatch '^nmw-app.*\.azurewebsites\.net$') {
    # prompt user for fqdns to test
    $KeyVaultUri = Read-Host -Prompt "Enter the FQDN for the Nerdio Manager Key Vault (e.g. nmw-app-kv-<unique string>.vault.azure.net)"
    $ApiEndpoints += [PSCustomObject]@{ URI = $KeyVaultUri; Port = 443; Purpose = "Nerdio Manager Key Vault"; Exceptions = @(); DnsServer = $LocalDns } # key vault uri
    $SqlServerUri = Read-Host -Prompt "Enter the FQDN for the Nerdio Manager SQL Server (e.g. nmw-app-sql-<unique string>.database.windows.net)"
    $ApiEndpoints += [PSCustomObject]@{ URI = $SqlServerUri; Port = 1433; Purpose = "Nerdio Manager SQL Server"; Exceptions = @(); DnsServer = $LocalDns } # sql server uri
    $DpsStorageAccountUri = Read-Host -Prompt "Enter the FQDN for the Nerdio Manager DPS Storage Account (e.g. dps<unique string>.blob.core.windows.net)"
    $ApiEndpoints += [PSCustomObject]@{ URI = $DpsStorageAccountUri; Port = 443; Purpose = "Nerdio Manager DPS Storage Account"; Exceptions = @(); DnsServer = $LocalDns } # dps storage account uri

}
else {
    # transform the $Env:WEBSITE_HOSTNAME from format like nmw-app-<unique string>.azurewebsites.net to a list of FQDNs for each app resource to test
    # key vault uri
    $KeyVaultUri = "nmw-app-kv-$((($Env:WEBSITE_HOSTNAME -split '-')[2] -split '\.')[0]).vault.azure.net"
    $ApiEndpoints += [PSCustomObject]@{ URI = $KeyVaultUri; Port = 443; Purpose = "Nerdio Manager Key Vault"; Exceptions = @(); DnsServer = $LocalDns } # key vault uri
    # sql server uri
    $SqlServerUri = "nmw-app-sql-$((($Env:WEBSITE_HOSTNAME -split '-')[2] -split '\.')[0]).database.windows.net"
    $ApiEndpoints += [PSCustomObject]@{ URI = $SqlServerUri; Port = 1433; Purpose = "Nerdio Manager SQL Server"; Exceptions = @(); DnsServer = $LocalDns } # sql server uri
    # dps storage account uri
    $DpsStorageAccountUri = "dps$((($Env:WEBSITE_HOSTNAME -split '-')[2] -split '\.')[0]).blob.core.windows.net"
    $ApiEndpoints += [PSCustomObject]@{ URI = $DpsStorageAccountUri; Port = 443; Purpose = "Nerdio Manager DPS Storage Account"; Exceptions = @(); DnsServer = $LocalDns } # dps storage account uri

}
foreach ($uri in $AdditionalTestUris) {
    $ApiEndpoints += [PSCustomObject]@{ URI = $uri; Port = 443; Purpose = "Additional Test URI"; Exceptions = @(); DnsServer = $RemoteDns }
}


foreach ($endpoint in $ApiEndpoints) {
    try{
        $dnsresult = $null
        
        # use resolve-dnsname to get the ip address of the endpoint
        if ($endpoint.DnsServer -eq 'AzureDefaultDns') {
            $dnsResult = Resolve-DnsName -Name $endpoint.URI -Type A -QuickTimeout -ErrorAction Stop
        }
        else {$dnsResult = Resolve-DnsName -Name $endpoint.URI -Server $endpoint.DnsServer -Type A -QuickTimeout -ErrorAction Stop}
        $endpoint | Add-Member -MemberType NoteProperty -Name RemoteAddress -Value $dnsResult.IP4Address
    }
    catch {
        $endpoint | Add-Member -MemberType NoteProperty -Name RemoteAddress -Value $dnsResult.IP4Address
        $endpoint.Exceptions += $_.Exception.Message
    }
    try {
        $uri = "https://$($endpoint.URI)"
        $servicePoint = $null 
        $response = Invoke-RestMethod -Method Get -Uri $uri -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($uri)
        $endpoint | Add-Member -MemberType NoteProperty -Name SSLCertificateSubject -Value $servicePoint.Certificate.Subject
        $endpoint | Add-Member -MemberType NoteProperty -Name SSLCertificateIssuer -Value $servicePoint.Certificate.Issuer
    } catch [System.Net.WebException]{
        # we expect response exception for some endpoints, so we will not add it to the exceptions list
        try{$servicePoint = [System.Net.ServicePointManager]::FindServicePoint($uri)}catch{}
        $endpoint | Add-Member -MemberType NoteProperty -Name SSLCertificateSubject -Value $servicePoint.Certificate.Subject
        $endpoint | Add-Member -MemberType NoteProperty -Name SSLCertificateIssuer -Value $servicePoint.Certificate.Issuer
    }
    catch{
        try{$servicePoint = [System.Net.ServicePointManager]::FindServicePoint($uri)}catch{}
        $endpoint | Add-Member -MemberType NoteProperty -Name SSLCertificateSubject -Value $servicePoint.Certificate.Subject
        $endpoint | Add-Member -MemberType NoteProperty -Name SSLCertificateIssuer -Value $servicePoint.Certificate.Issuer
        $endpoint.Exceptions += "SSL Check: $($_.Exception.Message)"
    }
    <#
    $nameResolverOutput = nameresolver $endpoint.uri
    # Parse the Server field from the output
    $serverAddress = ($nameResolverOutput | Select-String -Pattern "Server:\s*(\S+)" | ForEach-Object { $_.Matches.Groups[1].Value }) -join ''
    if ($serverAddress) {
        $endpoint | Add-Member -MemberType NoteProperty -Name DnsServer -Value $serverAddress
    }
    #>
    $Endpoint  | Select-Object URI, Port, Purpose, RemoteAddress, DnsServer, SSLCertificateSubject, SSLCertificateIssuer, Exceptions 
}
$ApiEndpoints | Select-Object URI, Port, Purpose, RemoteAddress, DnsServer, NextHops, SSLCertificateSubject, SSLCertificateIssuer, Exceptions | Format-List > NmeNetworkTestOutput.txt
#$ApiEndpoints | Select-Object URI, Port, Purpose, RemoteAddress, DnsServer, TcpTestSucceeded, NextHops, SSLCertificateSubject, SSLCertificateIssuer, Exceptions 