<#PSScriptInfo
.VERSION 1.0
.GUID 729ebf90-26fe-4795-92dc-ca8f570cdd22
.AUTHOR AndrewTaylor
.DESCRIPTION Sets user outlook signature using details from AzureAD
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune outlook signature azureAD
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES azureAD
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
  Creates user outlook signature from hosted template using Azure AD details
.DESCRIPTION
Creates user outlook signature from hosted template using Azure AD details

.INPUTS
None required
.OUTPUTS
Within Azure
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  05-11-2021
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>

#################################################### EDIT THESE SETTINGS ####################################################

#Custom variables
$templateurl = "https://github.com/andrew-s-taylor/public/raw/main/Powershell%20Scripts/Signature-Script/template.docx"
$SignatureName = 'CompanyName' #insert the company name (no spaces) - could be signature name if more than one sig needed
$SignatureVersion = "1" #Change this if you have updated the signature. If you do not change it, the script will quit after checking for the version already on the machine
$ForceSignature = '0' #Set to 1 if you don't want the users to be able to change signature in Outlook



#################################################### DO NOT EDIT BELOW THIS LINE ####################################################

$appdataf = $env:APPDATA
$outlookf = $appdataf+"\Microsoft"

if((Test-Path -Path $outlookf )){
    #New-Item -ItemType directory -Path $TARGETDIR

#Environment variables
$AppData=(Get-Item env:appdata).value
$SigPath = '\Microsoft\Signatures\' #Path to signatures. Might need to be changed to correspond language, i.e Swedish '\Microsoft\Signaturer'
$LocalSignaturePath = $AppData+$SigPath
$SigSource = $SignatureName+'.docx' #Path to the *.docx file, i.e "c:\temp\template.docx"

#Copy version file
If (-not(Test-Path -Path $LocalSignaturePath\$SignatureVersion))
{
New-Item -Path $LocalSignaturePath\$SignatureVersion -ItemType Directory

##Download Template File

$output = $LocalSignaturePath + $SigSource
Invoke-WebRequest -Uri $templateurl -OutFile $output -Method Get

}
Elseif (Test-Path -Path $LocalSignaturePath\$SignatureVersion)
{
Write-Output "Latest signature already exists"
break
}

#Check signature path (needs to be created if a signature has never been created for the profile
if (-not(Test-Path -path $LocalSignaturePath)) {
	New-Item $LocalSignaturePath -Type Directory
}
Connect-MgGraph
$currentuser = $env:userdnsdomain + "@" + $env:username


$userPrincipalName = whoami -upn
$userObject = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/me" -Method GET -OutputType PSObject


#Get AzureAD information for current user
$DisplayName = $userObject.displayName
$Surname = $userObject.surname
$FirstName = $userObject.givenName
$EmailAddress = $userObject.mail
$Title = $userObject.jobTitle
$TelePhoneNumber = $userObject.businessPhones[0]
$Mobile = $userObject.mobilePhone
$StreetAddress = $userObject.streetAddress
$City = $userObject.city
$CustomAttribute1 = $userObject.extensionAttribute1
$Fax = $userObject.faxNumber

{

function RemoveLineCarriage($object)
{
	$result = [System.String] $object;
	$result = $result -replace "`t","";
	$result = $result -replace "`n","";
	$result = $result -replace "`r","";
	$result = $result -replace " ;",";";
	$result = $result -replace "; ",";";
	
	$result = $result -replace [Environment]::NewLine, "";
	
	$result;
}


$fullname = $FirstName.TrimEnd("`r?`n")+" "+$Surname.TrimEnd("`r?`n")        
$signame2 = $Fax

$signame2 = $signame2.Substring(0,$signame2.Length-6)
$signame3 = $signame2.Split("{,}")

$signame4 = $signame3[1]
$signame4 = $signame4.Substring(1)
$signame5 = $signame3[0]
$fullname = $signame4+" "+$signame5
}


#Copy signature templates from source to local Signature-folder
$ReplaceAll = 2
$FindContinue = 1
$MatchCase = $False
$MatchWholeWord = $True
$MatchWildcards = $False
$MatchSoundsLike = $False
$MatchAllWordForms = $False
$Forward = $True
$Wrap = $FindContinue
$Format = $False
	
#Insert variables from Active Directory to rtf signature-file
$MSWord = New-Object -ComObject word.application
$fullPath = $LocalSignaturePath+'\'+$SignatureName+'.docx'
$MSWord.Documents.Open($fullPath)
	

	$ReplaceText = $DisplayName

$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)	

#Title		
$FindText = "Title"
$ReplaceText = $Title
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)
	

  	
#Street Address
If ($StreetAddress -ne '') { 
       $FindText = "StreetAddress"
    $ReplaceText = $StreetAddress
   }
   Else {
    $FindText = "StreetAddress"
    $ReplaceText = $DefaultAddress
    }
	$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)

#City
If ($City -ne '') { 
    $FindText = "City"
       $ReplaceText = $City
   }
   Else {
    $FindText = "City"
    $ReplaceText = $DefaultCity 
   }
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)


#Email
$MSWord.Selection.Find.Execute("EmailAddress")
$MSWord.ActiveDocument.Hyperlinks.Add($MSWord.Selection.Range, "mailto:"+$ADEmailAddress, $missing, $missing, "EmailAddress")

If ($EmailAddress -ne '') { 
    $FindText = "EmailAddress"
       $ReplaceText = $EmailAddress
   }
   Else {
    $FindText = "EmailAddress"
    $ReplaceText = ""
   }

$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)

#Fullname
If ($fullname -ne '') { 
    $FindText = "FullName"
       $ReplaceText = $DisplayName
   }
   Else {
    $FindText = "FullName"
    $ReplaceText = "" 
   }
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)

#Telephone
If ($TelephoneNumber -ne "") { 
	$FindText = "TelephoneNumber"
	$ReplaceText = $TelephoneNumber
   }
Else {
	$FindText = "TelephoneNumber"
    $ReplaceText = $DefaultTelephone
	}
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)
	
#Mobile
If ($Mobile -ne "") { 
	$FindText = "MobileNumber"
	$ReplaceText = $Mobile
   }
Else {
	$FindText = "MobileNumber "
    $ReplaceText = ""
	}
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)

#Save new message signature 
Write-Output "Saving signatures"
#Save HTML
$saveFormat = [Enum]::Parse([Microsoft.Office.Interop.Word.WdSaveFormat], "wdFormatHTML");
$path = $LocalSignaturePath+'\'+$SignatureName+" ("+ $userPrincipalName +").htm"
$MSWord.ActiveDocument.saveas([ref]$path, [ref]$saveFormat)
    
#Save RTF 
$saveFormat = [Enum]::Parse([Microsoft.Office.Interop.Word.WdSaveFormat], "wdFormatRTF");
$path = $LocalSignaturePath+'\'+$SignatureName+" ("+ $userPrincipalName +").rtf"
$MSWord.ActiveDocument.SaveAs([ref] $path, [ref]$saveFormat)
	
#Save TXT    
$saveFormat = [Enum]::Parse([Microsoft.Office.Interop.Word.WdSaveFormat], "wdFormatText");
$path = $LocalSignaturePath+'\'+$SignatureName+" ("+ $userPrincipalName +").txt"
$MSWord.ActiveDocument.SaveAs([ref] $path, [ref]$SaveFormat)
$MSWord.ActiveDocument.Close()
$MSWord.Quit()
	

#Office 2010
If (Test-Path HKCU:'\Software\Microsoft\Office\14.0')
{
If ($ForceSignature -eq '1')
    {
    Write-Output "Setting signature for Office 2010 as forced"
    New-ItemProperty HKCU:'\Software\Microsoft\Office\14.0\Common\MailSettings' -Name 'ReplySignature' -Value $SignatureName -PropertyType 'String' -Force
    New-ItemProperty HKCU:'\Software\Microsoft\Office\14.0\Common\MailSettings' -Name 'NewSignature' -Value $SignatureName -PropertyType 'String' -Force
    }
else
{
Write-Output "Setting Office 2010 signature as available"

$MSWord = New-Object -comobject word.application
$EmailOptions = $MSWord.EmailOptions
$EmailSignature = $EmailOptions.EmailSignature
$EmailSignatureEntries = $EmailSignature.EmailSignatureEntries

}
}



#Office 2013 signature

If (Test-Path HKCU:Software\Microsoft\Office\15.0)

{
Write-Output "Setting signature for Office 2013"

If ($ForceSignature -eq '0')

{
Write-Output "Setting Office 2013 as available"

$MSWord = New-Object -ComObject word.application
$EmailOptions = $MSWord.EmailOptions
$EmailSignature = $EmailOptions.EmailSignature
$EmailSignatureEntries = $EmailSignature.EmailSignatureEntries

}

If ($ForceSignature -eq '1')
{
Write-Output "Setting signature for Office 2013 as forced"
    If (Get-ItemProperty -Name 'NewSignature' -Path HKCU:'\Software\Microsoft\Office\15.0\Common\MailSettings') { } 
    Else { 
    New-ItemProperty HKCU:'\Software\Microsoft\Office\15.0\Common\MailSettings' -Name 'NewSignature' -Value $SignatureName -PropertyType 'String' -Force 
    } 
    If (Get-ItemProperty -Name 'ReplySignature' -Path HKCU:'\Software\Microsoft\Office\15.0\Common\MailSettings') { } 
    Else { 
    New-ItemProperty HKCU:'\Software\Microsoft\Office\15.0\Common\MailSettings' -Name 'ReplySignature' -Value $SignatureName -PropertyType 'String' -Force
    } 
        If (Get-ItemProperty -Name 'NewSignature' -Path HKCU:'\Software\Microsoft\Office\15.0\Common\MailSettings') { } 
    Else { 
    New-ItemProperty HKCU:'\Software\Microsoft\Office\16.0\Common\MailSettings' -Name 'NewSignature' -Value $SignatureName -PropertyType 'String' -Force 
    } 
    If (Get-ItemProperty -Name 'ReplySignature' -Path HKCU:'\Software\Microsoft\Office\15.0\Common\MailSettings') { } 
    Else { 
    New-ItemProperty HKCU:'\Software\Microsoft\Office\16.0\Common\MailSettings' -Name 'ReplySignature' -Value $SignatureName -PropertyType 'String' -Force
    } 
}
}

#Office 2016 signature

If (Test-Path HKCU:Software\Microsoft\Office\16.0)

{
Write-Output "Setting signature for Office 2016"

If ($ForceSignature -eq '0')

{
Write-Output "Setting Office 2016 as available"

$MSWord = New-Object -ComObject word.application
$EmailOptions = $MSWord.EmailOptions
$EmailSignature = $EmailOptions.EmailSignature
$EmailSignatureEntries = $EmailSignature.EmailSignatureEntries


Function Get-OutlookProfiles
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory=$true)][string]$Path
    )
    # Get Outlook profiles names.
    $OutlookDefaultProfiles = (Get-ChildItem -Path $Path).PSChildName;
    # More than one profile.
    If($OutlookDefaultProfiles -eq $null -or $OutlookDefaultProfiles.Count -ne 1)
    {
        # Set profile path.
        $OutlookProfilePath = 'HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings';
    }
    # Default profile.
    Else
    {
        # Set default profile path.
        $OutlookProfilePath = ("HKCU:\Software\Microsoft\Office\16.0\Outlook\Profiles\{0}\9375CFF0413111d3B88A00104B2A6676\00000002" -f $OutlookDefaultProfiles);
    }
    # Return path.
    Return $OutlookProfilePath;
}


            
$OutlookRegistryPath = 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Profiles';

# Get Outlook profile registry path.
$OutlookProfilePath = Get-OutlookProfiles -Path $OutlookRegistryPath;
$OutlookNewSignature = $SignatureName+" ("+ $userPrincipalName +")"
$SignatureNewName   = $SignatureName+" ("+ $userPrincipalName +")"
$SignatureReplyName = $SignatureName+" ("+ $userPrincipalName +")"
#$SignatureNewName   = "$OutlookNewSignature ($CurrentUser)"
#$SignatureReplyName = "$OutlookNewSignature ($CurrentUser)"
Get-Item -Path $OutlookProfilePath | New-Itemproperty -Name "New Signature" -value $SignatureNewName -Propertytype string -Force | Out-Null;
Get-Item -Path $OutlookProfilePath | New-Itemproperty -Name "Reply-Forward Signature" -value $SignatureReplyName -Propertytype string -Force | Out-Null;
}

If ($ForceSignature -eq '1')
{
Write-Output "Setting signature for Office 2016 as forced"
    If (Get-ItemProperty -Name 'NewSignature' -Path HKCU:'\Software\Microsoft\Office\16.0\Common\MailSettings') { } 
    Else { 
    New-ItemProperty HKCU:'\Software\Microsoft\Office\16.0\Common\MailSettings' -Name 'NewSignature' -Value $SignatureName -PropertyType 'String' -Force 
    } 
    If (Get-ItemProperty -Name 'ReplySignature' -Path HKCU:'\Software\Microsoft\Office\16.0\Common\MailSettings') { } 
    Else { 
    New-ItemProperty HKCU:'\Software\Microsoft\Office\16.0\Common\MailSettings' -Name 'ReplySignature' -Value $SignatureName -PropertyType 'String' -Force
    } 
        If (Get-ItemProperty -Name 'NewSignature' -Path HKCU:'\Software\Microsoft\Office\16.0\Common\MailSettings') { } 
    Else { 
    New-ItemProperty HKCU:'\Software\Microsoft\Office\16.0\Common\MailSettings' -Name 'NewSignature' -Value $SignatureName -PropertyType 'String' -Force 
    } 
    If (Get-ItemProperty -Name 'ReplySignature' -Path HKCU:'\Software\Microsoft\Office\16.0\Common\MailSettings') { } 
    Else { 
    New-ItemProperty HKCU:'\Software\Microsoft\Office\16.0\Common\MailSettings' -Name 'ReplySignature' -Value $SignatureName -PropertyType 'String' -Force
    } 
}
}

}

Write-Host "" 
Write-Host "Daten:" 
Write-Host "DisplayName:" $DisplayName 
Write-Host "Fax:" $Fax
Write-Host "Personal:" $Personal
Write-Host "Surname:" $Surname
Write-Host "FirstName:" $FirstName
Write-Host "EmailAddres:" $EmailAddress
Write-Host "Title:" $Title
Write-Host "Description:" $Description
Write-Host "TelePhoneNumber:" $TelePhoneNumber
Write-Host "Mobile:" $Mobile
Write-Host "StreetAddress:" $StreetAddress
Write-Host "City:" $City
Write-Host "CustomAttribute1:" $CustomAttribute1