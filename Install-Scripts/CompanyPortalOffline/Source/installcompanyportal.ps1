$folderpath = $PSScriptRoot
$DependencyFolderPath = $folderpath.Path + "\Dependencies"
$FullPathtoAppxbundle = $folderpath.Path + "\Microsoft.CompanyPortal_2022.409.807.0_neutral___8wekyb3d8bbwe.AppxBundle"

$Dependencies = Get-ChildItem -Path $DependencyFolderPath -Filter "*.appx*" | Select-Object -ExpandProperty FullName

Add-AppxPackage -Path $FullPathtoAppxbundle -DependencyPath $Dependencies