<#
.SYNOPSIS
  Disable machines not seen in 1 year

.DESCRIPTION
Disables machines not seen in one year.  Optionally emails results

.INPUTS
Params: LiveOU and Disabled OU

.OUTPUTS


.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  13/01/2020
  Purpose/Change: Initial script development
  
.EXAMPLE
disable-computers.ps1 -LiveOU "LiveOU" -DisabledOU "Disabled OU"
#>


param (
    [Parameter(Mandatory=$true)] 
    [String]  $LiveOU = '',

    [Parameter(Mandatory=$true)]
    [String] $DisabledOU = ''
)
########################################################
#######             SMTP Settings                #######
########################################################
$smtpServer = "smtp.you.com"
$smtpFrom = "from@you.com"
$smtpTo = "to@you.com"
$messageSubject = "I have disabled these!"

#########################################################

$1year = (Get-Date).AddDays(-365) # The 365 is the number of days from today since the last logon. 
$1y1m = (Get-Date).AddDays(-395) 
 
# Disable computer objects and move to disabled OU (Older than 1 year): 
$Today = get-date
$desc = "Disabled on"+$Today
Get-ADComputer -Property Name,lastLogonDate -Filter {lastLogonDate -lt $1year} -SearchBase $LiveOU | Set-ADComputer -Enabled $false -Description $desc
Get-ADComputer -Property Name,Enabled -Filter {Enabled -eq $False} -SearchBase $LiveOU | Move-ADObject -TargetPath $DisabledOU
$Today = get-date
$PCs = Get-ADComputer -Property Name,lastLogonDate -Filter {lastLogonDate -lt $1year} -SearchBase $LiveOU
$Disabled = "The following computers have been disabled on "+$Today+$PCs

Send-MailMessage -From "$smtpFrom" -To "$smtpTo" -Subject "$messageSubject" -Body "$($Disabled)" -SMTPServer "$smtpServer"