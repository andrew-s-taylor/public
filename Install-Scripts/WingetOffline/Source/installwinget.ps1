$folderpath = $PSScriptRoot
$DependencyFolderPath = $folderpath.Path + "\Dependencies"
$FullPathtoAppxbundle = $folderpath.Path + "\Microsoft.DesktopAppInstaller_2022.610.123.0_neutral___8wekyb3d8bbwe.Msixbundle"

$Dependencies = Get-ChildItem -Path $DependencyFolderPath -Filter "*.appx*" | Select-Object -ExpandProperty FullName

Add-AppxPackage -Path $FullPathtoAppxbundle -DependencyPath $Dependencies