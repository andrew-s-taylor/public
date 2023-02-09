$Path = "c:\windows\system32\cmtrace.exe"

Try {
    $check = Test-Path -Path $path -ErrorAction Stop
    If ($check -eq $true){
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