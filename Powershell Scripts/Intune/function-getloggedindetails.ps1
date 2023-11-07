function getloggedindetails() {
    ##Find logged in username
    $user = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" |
      ForEach-Object { $_.GetOwner() } |
      Select-Object -Unique -Expand User
    
    ##Find logged in user's SID
    ##Loop through registry profilelist until ProfileImagePath matches and return the path
        $path= "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*"
        $sid = (Get-ItemProperty -Path $path | Where-Object { $_.ProfileImagePath -like "*$user" }).PSChildName

    $return = $sid, $user
    
    return $return
    }


$loggedinuser = getloggedindetails
$sid = $loggedinuser[0]
$user = $loggedinuser[1]