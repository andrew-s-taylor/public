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
$certurl = "https://github.com/andrew-s-taylor/public/raw/main/Powershell%20Scripts/Signature-Script/template.docx"
$templateurl = "https://github.com/andrew-s-taylor/public/raw/main/Powershell%20Scripts/Signature-Script/template.docx"
$SignatureName = 'template' #insert the company name (no spaces) - could be signature name if more than one sig needed
$SignatureVersion = "1" #Change this if you have updated the signature. If you do not change it, the script will quit after checking for the version already on the machine
$ForceSignature = '1' #Set to 1 if you don't want the users to be able to change signature in Outlook
$Address = ""
$Tel = ""
$tenantid = "46cd9aae-0d0e-45e1-83b5-154b8efeb92f"


#################################################### DO NOT EDIT BELOW THIS LINE ####################################################



$appdataf = $env:APPDATA
$outlookf = $appdataf+"\Microsoft"

if((Test-Path -Path $outlookf )){
    #New-Item -ItemType directory -Path $TARGETDIR




 
#Environment variables
$AppData=(Get-Item env:appdata).value
$SigPath = '\Microsoft\Signatures' #Path to signatures. Might need to be changed to correspond language, i.e Swedish '\Microsoft\Signaturer'
$LocalSignaturePath = $AppData+$SigPath
$SigSource = "template.docx" #Path to the *.docx file, i.e "c:\temp\template.docx"
$RemoteSignaturePathFull = $SigSource

#Copy version file
If (-not(Test-Path -Path $LocalSignaturePath\$SignatureVersion))
{
New-Item -Path $LocalSignaturePath\$SignatureVersion -ItemType Directory
$path = "C:\templates"
If(!(test-path $path))
{
      New-Item -ItemType Directory -Force -Path $path
}

#Create Temp folder to store template
$random = Get-Random -Maximum 1000 
$random = $random.ToString()
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-"  + $date
$path = "c:\temp\" + $path2 + "\"

New-Item -ItemType Directory -Path $path


##Download Template File

$output = $path + "template.docx"
Invoke-WebRequest -Uri $templateurl -OutFile $output -Method Get


#Download Certificate
$output = $path + "cert.pfx"
Invoke-WebRequest -Uri $certurl -OutFile $output -Method Get

$sourceDirectory  = $output



$destinationDirectory = "C:\templates\"
Copy-item -Force -Recurse -Verbose $sourceDirectory -Destination $destinationDirectory
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


$currentuser = $env:userdnsdomain + "@" + $env:username
get-azureaduser -Filter "UserPrincipalName eq '$currentuser'"

#Get Active Directory information for current user
$UserName = $env:username
$Filter = "(&(objectCategory=User)(samAccountName=$UserName))"
$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.Filter = $Filter
$ADUserPath = $Searcher.FindOne()
$ADUser = $ADUserPath.GetDirectoryEntry()
$ADDisplayName = $ADUser.DisplayName
$ADFax = $ADUser.facsimileTelephoneNumber
$ADPersonal = $ADUser.PersonalTitle
$ADSurname = $ADUser.sn
$ADFirstName = $ADUser.givenName
$ADEmailAddress = $ADUser.mail
$ADTitle = $ADUser.title
$ADDescription = $ADUser.description
$ADTelePhoneNumber = $ADUser.TelephoneNumber
$ADMobile = $ADUser.mobile
$ADStreetAddress = $ADUser.streetaddress
$ADCity = $ADUser.l
$ADCustomAttribute1 = $ADUser.extensionAttribute1
$ADModify = $ADUser.whenChanged

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


$fullname = $ADFirstName.TrimEnd("`r?`n")+" "+$ADSurname.TrimEnd("`r?`n")        
$signame2 = $ADFax

$signame2 = $signame2.Substring(0,$signame2.Length-6)
$signame3 = $signame2.Split("{,}")

$signame4 = $signame3[1]
$signame4 = $signame4.Substring(1)
$signame5 = $signame3[0]
$fullname = $signame4+" "+$signame5
}


#Copy signature templates from source to local Signature-folder
Write-Output "Copying Signatures"
Copy-Item "$Sigsource" $LocalSignaturePath -Recurse -Force
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
	
#User Name $ Designation 
$FindText = "DisplayName" 
$Designation = $ADCustomAttribute1.ToString() #designations in Exchange custom attribute 1
If ($Designation -ne '') { 
	$Name = $ADFax.ToString()
	$ReplaceText = $Name+', '+$Designation
}
Else {
	$ReplaceText = $ADFax.ToString() 
}
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)	

#Title		
$FindText = "Title"
$ReplaceText = $ADTitle.ToString()
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)
	
#Description
   If ($ADDescription -ne '') { 
   	$FindText = "Description"
   	$ReplaceText = $ADDescription.ToString()
}
Else {
	$FindText = " | Description "
   	$ReplaceText = ""
}
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)
#$LogInfo += $NL+'Description: '+$ReplaceText


#Description

	$FindText = "TelephoneNumber"
   	$ReplaceText = $SeniorTel

$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)
#$LogInfo += $NL+'Description: '+$ReplaceText
   	
#Street Address
If ($ADStreetAddress -ne '') { 
       $FindText = "StreetAddress"
    $ReplaceText = $ADStreetAddress.ToString()
   }
   Else {
    $FindText = "StreetAddress"
    $ReplaceText = $DefaultAddress
    }
	$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)

#City
If ($ADCity -ne '') { 
    $FindText = "City"
       $ReplaceText = $ADCity.ToString()
   }
   Else {
    $FindText = "City"
    $ReplaceText = $DefaultCity 
   }
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)


#Email
If ($ADEmailAddress -ne '') { 
    $FindText = "EmailAddress"
       $ReplaceText = "Email"
   }
   Else {
    $FindText = "Email"
    $ReplaceText = $DefaultEmail 
   }
$MSWord.Selection.Find.Execute("Email")
$MSWord.ActiveDocument.Hyperlinks.Add($MSWord.Selection.Range, “mailto:”+$ADEmailAddress.ToString(), $missing, $missing, "Email")

#Fullname
If ($fullname -ne '') { 
    $FindText = "FullName"
       $ReplaceText = $fullname
   }
   Else {
    $FindText = "FullName"
    $ReplaceText = "" 
   }
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)



#FirstName
If ($AFirstName -ne '') { 
        $FindText = "FirstName"
       $ReplaceText = $forename
   }
   Else {
    $FindText = "FirstName"
    $ReplaceText = "" 
   }
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)



Surname
If ($ADSurname -ne '') { 
    $FindText = "Surname"
       $ReplaceText = $ADSurname.ToString()
   }
   Else {
    $FindText = "Surname"
    $ReplaceText = "" 
   }
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)
	
#Telephone
If ($ADTelephoneNumber -ne "") { 
	$FindText = "TelephoneNumber"
	$ReplaceText = " | Ext:  "+$ADTelephoneNumber.ToString()
   }
Else {
	$FindText = "TelephoneNumber"
    $ReplaceText = $DefaultTelephone
	}
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)
	
#Mobile
If ($ADMobile -ne "") { 
	$FindText = "MobileNumber"
	$ReplaceText = $ADMobile.ToString()
   }
Else {
	$FindText = "| Mob MobileNumber "
    $ReplaceText = "".ToString()
	}
$MSWord.Selection.Find.Execute($FindText, $MatchCase, $MatchWholeWord,	$MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap,	$Format, $ReplaceText, $ReplaceAll	)

#Save new message signature 
Write-Output "Saving signatures"
#Save HTML
$saveFormat = [Enum]::Parse([Microsoft.Office.Interop.Word.WdSaveFormat], "wdFormatHTML");
$path = $LocalSignaturePath+'\'+$SignatureName+".htm"
$MSWord.ActiveDocument.saveas([ref]$path, [ref]$saveFormat)
    
#Save RTF 
$saveFormat = [Enum]::Parse([Microsoft.Office.Interop.Word.WdSaveFormat], "wdFormatRTF");
$path = $LocalSignaturePath+'\'+$SignatureName+".rtf"
$MSWord.ActiveDocument.SaveAs([ref] $path, [ref]$saveFormat)
	
#Save TXT    
$saveFormat = [Enum]::Parse([Microsoft.Office.Interop.Word.WdSaveFormat], "wdFormatText");
$path = $LocalSignaturePath+'\'+$SignatureName+".txt"
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