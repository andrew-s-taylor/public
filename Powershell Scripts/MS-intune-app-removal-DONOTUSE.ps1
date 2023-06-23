
<#

Copyright (c) 2021 Microsoft
 
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Windows 10 in cloud configuration OneDrive Known Folder Move and built-in app removal script

Version 3.0 May 10 2013

#>

# Removes all Appx apps.  See options below to selectively retain certain Apps

# Get-AppXProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online


Function removeWindowsStore {

$removeList = 'Microsoft.WindowsStore'

    # get all provisioned packages
    $AppList = Get-AppXProvisionedPackage -Online 

    foreach ($app in $AppList) {

        # retain items in the list
   
        if ($removeList -contains $app.DisplayName) {
         write-host "Removing: " $app.DisplayName
         try {
          Remove-AppxProvisionedPackage -Online -PackageName $app.PackageName
          }
          catch [Exception]  {
          write-host "Failed to remove: " $app.DisplayName
          }
        }
        else {
         write-host "Retaining: " $app.DisplayName
         
        }

    }

}


Function removeBuiltinApps {
    # remove all but store

    $retainList = 'Microsoft.WindowsStore'

    # get all provisioned packages
    $AppList = Get-AppXProvisionedPackage -Online 

    foreach ($app in $AppList) {

        # retain items in the list
   
        if ($retainList -contains $app.DisplayName) {
         write-host "Retaining: " $app.DisplayName
        }
        else {
         write-host "Removing: " $app.DisplayName
         try {
          Remove-AppxProvisionedPackage -Online -PackageName $app.PackageName
          }
          catch [Exception]  {
          write-host "Failed to remove: " $app.DisplayName
          }
        }

    }

}


removeWindowsStore

removeBuiltinApps