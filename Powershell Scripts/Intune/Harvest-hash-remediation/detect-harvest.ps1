$regkey = "HKLM:\Software\Harvester"
$regname = "Harvested"
$regvalue = "completed"
Try {
    $Registry = Get-ItemProperty -Path $regkey -Name $regname -ErrorAction Stop | Select-Object -ExpandProperty $regname
    If ($Registry -eq $regvalue){
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