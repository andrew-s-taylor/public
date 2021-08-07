Try {
    $updatecheck = winget upgrade
    If ($updatecheck.count -lt 3){
        Write-Output "Compliant"
        Exit 0
    } 
    Write-Warning "Not Compliant"
    Exit 1
} 
Catch {
    Write-Warning "Not Compliant"
    Exit 1
}
