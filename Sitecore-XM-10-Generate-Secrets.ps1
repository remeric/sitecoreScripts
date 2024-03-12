###############################################
#Script that can be used to gerneate sercrets needed for setting up a Sitecore 10.X XM Environment
###############################################

#Params include 
# 1. keyvault name for the scripts to be uploaded to
# 2. URL of the Solr instance
param (

#Validate Platform Paramters
    [parameter(Mandatory = $true)]
    [string]$kvname,
    [parameter(Mandatory = $true)]
    [string]$solrURL #Dont include anything after domain such as port
    )

#Functions
#-----------------------------------------------------------------------------------------------

#Database Passwords
##SQL Allowed Special Chracters !@#%^*_
function New-Password {

$validPass = $false

while (!$validPass) {

$password = New-Object -TypeName PSObject

$password | Add-Member -MemberType ScriptProperty -Name "Password" -Value { ("!@#%^*0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz".tochararray() | Sort-Object {Get-Random})[0..31] -join '' }

$validpass = $password -cmatch "[a-z]" -and `
$password -cmatch "[A-Z]" -and `
$password -match "[!@#%^*_]" -and `
$password -match "[/D]"
$password.password
}
}
#64 character password with special characters based off of:
##SQL Allowed Special Chracters !@#%^*_
##Media Protection allowed characters abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-|\.,#^)(;
function New-Password64 {

$validPass = $false

while (!$validPass) {

$password = New-Object -TypeName PSObject

$password | Add-Member -MemberType ScriptProperty -Name "Password" -Value { ("#^0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz".tochararray() | Sort-Object {Get-Random})[0..63] -join '' }

$validpass = $password -cmatch "[a-z]" -and `
$password -cmatch "[A-Z]" -and `
#Can't have '#' at beginning of -match or it fails to validate
$password -match "[^#_]" -and `
$password -match "[/D]"
$password.password
}
}

#Generate Password 64 characters no special characters
function New-Password64NoSpecial {

$validPass = $false

while (!$validPass) {

$password = New-Object -TypeName PSObject

$password | Add-Member -MemberType ScriptProperty -Name "Password" -Value { ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".tochararray() | Sort-Object {Get-Random})[0..63] -join '' }

$validpass = $password -cmatch "[a-z]" -and `
$password -cmatch "[A-Z]" -and `
$password -match "[/D]"
$password.password
}
}

function ConvertTo-CompressedBase64String {
[CmdletBinding()]
Param (
[Parameter(Mandatory)]
[ValidateScript( {
if (-Not ($_ | Test-Path) ) {
throw "The file or folder $_ does not exist"
}
if (-Not ($_ | Test-Path -PathType Leaf) ) {
throw "The Path argument must be a file. Folder paths are not allowed."
}
return $true
})]
[string] $Path
)
$fileBytes = [System.IO.File]::ReadAllBytes($Path)
[System.IO.MemoryStream] $memoryStream = New-Object System.IO.MemoryStream
$gzipStream = New-Object System.IO.Compression.GzipStream $memoryStream, ([IO.Compression.CompressionMode]::Compress)
$gzipStream.Write($fileBytes, 0, $fileBytes.Length)
$gzipStream.Close()
$memoryStream.Close()
$compressedFileBytes = $memoryStream.ToArray()
$encodedCompressedFileData = [Convert]::ToBase64String($compressedFileBytes)
$gzipStream.Dispose()
$memoryStream.Dispose()
return $encodedCompressedFileData
}

function ConvertTo-Base64String {
    [CmdletBinding()]
    Param (
    [Parameter(Mandatory)]
    [ValidateScript( {
    if (-Not ($_ | Test-Path) ) {
    throw "The file or folder $_ does not exist"
    }
    if (-Not ($_ | Test-Path -PathType Leaf) ) {
    throw "The Path argument must be a file. Folder paths are not allowed."
    }
    return $true
    })]
    [string] $Path
    )
$fileContentBytes = get-content $Path -AsByteStream #As byte stream only works in powershell 6 and above
$Base64Cert = [System.Convert]::ToBase64String($fileContentBytes)
$Base64Cert = ConvertTo-SecureString $Base64Cert -AsPlainText -Force
}

#-----------------------------------------------------------------------------------------------
#End Functions

#Create an array for database and solr vm usernames in XM
$XMusernames = @(
    [pscustomobject]@{name="sql-database-username";value="sqlserveradmin"}
    [pscustomobject]@{name="sitecore-core-database-username";value="coreuser"}
    [pscustomobject]@{name="sitecore-master-database-username";value="masteruser"}
    [pscustomobject]@{name="sitecore-web-database-username";value="webuser"}
    [pscustomobject]@{name="sitecore-forms-database-username";value="formsuser"}
    [pscustomobject]@{name="sitecore-security-database-username";value="securityuser"}
    [pscustomobject]@{name="solr-vm-username";value="solradmin"}
)

#### Create Database Usernames Passwords ####

foreach ($XMusername in $XMusernames) {
    az keyvault secret set --name $XMusername.name --vault-name $kvname --value $XMusername.value
    $validPass = $false

    #Loop through username key values and replace -username with -password, then generate a password per SQL rules and upload
    
    while (!$validPass) {
            $password = New-Object -TypeName PSObject
            $password | Add-Member -MemberType ScriptProperty -Name "Password" -Value { ("!@#%^*0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz".tochararray() | Sort-Object {Get-Random})[0..32] -join '' }

            $validpass = $password -cmatch "[a-z]" -and `
            $password -cmatch "[A-Z]" -and `
            $password -match "[!@#%^*_]" -and `
            $password -match "[/D]"

    }
    $secretname = $XMUsername.name.Replace("-username","-password")
    az keyvault secret set --name $secretname --vault-name $kvname --value $password.Password --output none
}


#Create an array for Additional secrets that you need

$Secrets = @(
    [pscustomobject]@{name="siClientSecret"}
    [pscustomobject]@{name="sitecoreAdminPassword"}
    [pscustomobject]@{name="sitecore-telerikencryptionkey"}
)

#### Create those secrets ####

foreach ($secret in $Secrets) {
    $validPass = $false

    while (!$validPass) {
        $password = New-Object -TypeName PSObject
        $password | Add-Member -MemberType ScriptProperty -Name "Password" -Value { ("!#%^*0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz".tochararray() | Sort-Object {Get-Random})[0..32] -join '' }

        $validpass = $password -cmatch "[a-z]" -and `
        $password -cmatch "[A-Z]" -and `
        $password -match "[!@#%^*_]" -and `
        $password -match "[/D]"

    }
     az keyvault secret set --name $secret.name --vault-name $kvname --value $password.Password --output none
}


## special block that will also create the solr connection string
$solrSecrets = @(
    [pscustomobject]@{name="SolrPassword"}
)

foreach ($secret in $solrSecrets) {
    $validPass = $false

    while (!$validPass) {
        $password = New-Object -TypeName PSObject
        $password | Add-Member -MemberType ScriptProperty -Name "Password" -Value { ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz".tochararray() | Sort-Object {Get-Random})[0..32] -join '' }
        
        $validpass = $password -cmatch "[a-z]" -and `
        $password -cmatch "[A-Z]" -and `
        # $password -match "[_]" -and ` #Regex verification fails if _ is the only character it seems
        $password -match "[/D]"
        write-host "ending password validation"

    }
     $finalPassword = $password.Password
     $connectionString = "https://solr:" + $finalPassword + "@" + $solrURL + ":8984" + "/solr;solrCloud=true"
     az keyvault secret set --name $secret.name --vault-name $kvname --value $finalPassword --output none
     az keyvault secret set --name solrConnectionString --vault-name $kvname --value $connectionString --output none
}

##Create Identity Certificate

$certificatePassword = New-Password64NoSpecial
$filePath = ".\SitecoreIdentityTokenSigning.pfx"
$newCert = New-SelfSignedCertificate -DnsName "localhost" -FriendlyName "Sitecore Identity Token Signing" -NotAfter (Get-Date).AddYears(30)
Export-PfxCertificate -Cert $newCert -FilePath $filePath -Password (ConvertTo-SecureString -String $certificatePassword -Force -AsPlainText)

# $base64 = ConvertTo-Base64String $filepath
$base64 = [system.convert]::ToBase64String([system.IO.File]::ReadAllBytes((get-item $filePath)))
Start-Sleep 5
Remove-Item .\SitecoreIdentityTokenSigning.pfx

az keyvault secret set --name identitycertificate --vault-name $kvname --value $base64 --output none
az keyvault secret set --name identitycertificatepassword --vault-name $kvname --value $certificatePassword --output none