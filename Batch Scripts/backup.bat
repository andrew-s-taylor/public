::Name - Backup Script
::Description - Backs Up favourites, music, signatures, Outlook settings, templates, UI settings, stickynotes, chrome bookmarks, email signature and mapped drives from local PC to OneDrive
::Inputs - None
::Outputs - Logs to a backup script on OneDrive
::Version - 1.3
::Created By - Andrew Taylor @ andrewstaylor.com
::Updates - Initial Update
::Updated 27-01 - Backing up links files
::Moved Favourites to resolve issue
::Updated added XLStart and WordStartup

Sleep 10

::GET DESKTOP
echo CopyingDesktop > "%Onedrive%\backup\log.txt"
echo CopyingDesktop > "%OneDriveCommercial%\backup\log.txt"
SET BDesk=%USERPROFILE%\Desktop
SET RDesk="%Onedrive%\Desktop"
if not exist "%Onedrive%\Desktop" mkdir "%Onedrive%\Desktop\Desktop"
if not exist "%OneDriveCommercial%\Desktop" mkdir "%OneDriveCommercial%\Desktop\Desktop"
XCopy "%BDesk%\*" "%Onedrive%\Desktop" /E /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
XCopy "%BDesk%\*" "%OneDriveCommercial%\Desktop" /E /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"

::GET MUSIC
echo CopyingMusic >> "%Onedrive%\backup\log.txt"
echo CopyingMusic >> "%OneDriveCommercial%\backup\log.txt"
SET BMus=%USERPROFILE%\Music
SET RMus="%Onedrive%\Music"
if not exist "%Onedrive%\Music" mkdir "%Onedrive%\Music"
XCopy "%BMus%\*" "%Onedrive%\Music" /E /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
if not exist "%OneDriveCommercial%\Music" mkdir "%OneDriveCommercial%\Music"
XCopy "%BMus%\*" "%OneDriveCommercial%\Music" /E /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"


::GET DOCUMENTS
echo CopyingDocuments >> "%Onedrive%\backup\log.txt"
echo CopyingDocuments >> "%OneDriveCommercial%\backup\log.txt"
SET BDocs=%USERPROFILE%\Documents
SET RDocs="%Onedrive%\Documents"
if not exist "%Onedrive%\Documents" mkdir "%Onedrive%\Documents"
XCopy "%BDocs%\*" "%Onedrive%\Documents" /E /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
if not exist "%OneDriveCommercial%\Documents" mkdir "%OneDriveCommercial%\Documents"
XCopy "%BDocs%\*" "%OneDriveCommercial%\Documents" /E /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"

::GET SIGNATURES
echo CopyingSignatures >> "%Onedrive%\backup\log.txt"
echo CopyingSignatures >> "%OneDriveCommercial%\backup\log.txt"
SET BSig=%APPDATA%\Microsoft\Signatures
SET RSig="%Onedrive%\Backup\Signature"
if not exist "%Onedrive%\Backup\Signatures" mkdir "%Onedrive%\Backup\Signature"
XCopy "%BSig%\*" "%Onedrive%\Backup\Signature" /E /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
if not exist "%OneDriveCommercial%\Backup\Signatures" mkdir "%OneDriveCommercial%\Backup\Signature"
XCopy "%BSig%\*" "%OneDriveCommercial%\Backup\Signature" /E /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"

::GET Outlook-Autocorrect
echo CopyingOutlookComplete >> "%Onedrive%\backup\log.txt"
echo CopyingOutlookComplete >> "%OneDriveCommercial%\backup\log.txt"
SET BSig=%LOCALAPPDATA%\Microsoft\Outlook\RoamCache
SET RSig="%Onedrive%\Backup\Roam"
if not exist "%Onedrive%\Backup\Roam" mkdir "%Onedrive%\Backup\Roam"
XCopy "%BSig%\*" "%Onedrive%\Backup\Roam" /E /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
if not exist "%OneDriveCommercial%\Backup\Roam" mkdir "%OneDriveCommercial%\Backup\Roam"
XCopy "%BSig%\*" "%OneDriveCommercial%\Backup\Roam" /E /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"

::GET FAVOURITES
echo CopyingFavourites >> "%Onedrive%\backup\log.txt"
echo CopyingFavourites >> "%OneDriveCommercial%\backup\log.txt"
SET BFav=%USERPROFILE%\Favorites
SET RFav="%Onedrive%\Favorites"
if not exist "%Onedrive%\Favorites" mkdir "%Onedrive%\Favorites"
XCopy "%BFav%\*" "%Onedrive%\Favorites" /E /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
if not exist "%OneDriveCommercial%\Favorites" mkdir "%OneDriveCommercial%\Favorites"
XCopy "%BFav%\*" "%OneDriveCommercial%\Favorites" /E /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"


::GET Links
echo CopyingLinks >> "%Onedrive%\backup\log.txt"
echo CopyingLinks >> "%OneDriveCommercial%\backup\log.txt"
SET BLinks=%USERPROFILE%\Links
SET RLinks="%Onedrive%\Backup\Links\"
if not exist "%Onedrive%\Backup\Links\" mkdir "%Onedrive%\Backup\Links"
XCopy "%BLinks%\*" "%Onedrive%\Backup\Links\" /E /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
if not exist "%OneDriveCommercial%\Links" mkdir "%OneDriveCommercial%\Links"
XCopy "%BLinks%\*" "%OneDriveCommercial%\Backup\Links\" /E /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"

::GET Excel Startup
echo CopyingXLStart >> "%Onedrive%\backup\log.txt"
echo CopyingXLStart >> "%OneDriveCommercial%\backup\log.txt"
SET Bxlstart=%APPDATA%\Microsoft\Excel\XLStart
SET Rxlstart="%Onedrive%\Backup\XLStart"
if not exist "%Onedrive%\Backup\XLStart" mkdir "%Onedrive%\Backup\XLStart"
XCopy "%Bxlstart%\*" "%Onedrive%\Backup\XLStart" /E /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
if not exist "%OneDriveCommercial%\XLStart" mkdir "%OneDriveCommercial%\XLStart"
XCopy "%Bxlstart%\*" "%OneDriveCommercial%\Backup\XLStart\" /E /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"


::GET Word Startup
echo CopyingWordStartup >> "%Onedrive%\backup\log.txt"
echo CopyingWordStartup >> "%OneDriveCommercial%\backup\log.txt"
SET Bwordst=%APPDATA%\Microsoft\Word\STARTUP
SET Rwordst="%Onedrive%\Backup\Wordstartup"
if not exist "%Onedrive%\Backup\Wordstartup" mkdir "%Onedrive%\Backup\Wordstartup"
XCopy "%Bwordst%\*" "%Onedrive%\Backup\Wordstartup" /E /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
if not exist "%OneDriveCommercial%\Wordstartup" mkdir "%OneDriveCommercial%\Wordstartup"
XCopy "%Bwordst%\*" "%OneDriveCommercial%\Backup\Wordstartup\" /E /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"

::GET PST 
echo CopyingPST >> "%Onedrive%\backup\log.txt"
echo CopyingPST >> "%OneDriveCommercial%\backup\log.txt"
SET BPST=%LOCALAPPDATA%\Microsoft\Outlook
SET RPST="%Onedrive%\Outlook"
if not exist "%Onedrive%\Outlook" mkdir "%Onedrive%\Outlook"
XCopy "%BPST%\*.PST" "%Onedrive%\Outlook" /E /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
if not exist "%OneDriveCommercial%\Outlook" mkdir "%OneDriveCommercial%\Outlook"
XCopy "%BPST%\*.PST" "%OneDriveCommercial%\Outlook" /E /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"


::GET NORMALDOT
echo CopyingNormalDot >> "%Onedrive%\backup\log.txt"
echo CopyingNormalDot >> "%OneDriveCommercial%\backup\log.txt"
SET BWord=%APPDATA%\Microsoft\Templates
SET RWord="%Onedrive%\Backup\Templates"
if not exist "%Onedrive%\Backup\Templates" mkdir "%Onedrive%\Backup\Templates"
XCopy "%BWord%\*" "%Onedrive%\Backup\Templates" /E /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
if not exist "%OneDriveCommercial%\Backup\Templates" mkdir "%OneDriveCommercial%\Backup\Templates"
XCopy "%BWord%\*" "%OneDriveCommercial%\Backup\Templates" /E /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"

::GET UI
echo CopyingUI >> "%Onedrive%\backup\log.txt"
echo CopyingUI >> "%OneDriveCommercial%\backup\log.txt"
SET BUI=%LOCALAPPDATA%\Microsoft\Office
SET RUI="%Onedrive%\Backup\UI"
if not exist "%Onedrive%\Backup\UI" mkdir "%Onedrive%\Backup\UI"
XCopy "%BUI%\*.customUI" "%Onedrive%\Backup\UI" /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
XCopy "%BUI%\*.officeUI" "%Onedrive%\Backup\UI" /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
if not exist "%OneDriveCommercial%\Backup\UI" mkdir "%OneDriveCommercial%\Backup\UI"
XCopy "%BUI%\*.customUI" "%OneDriveCommercial%\Backup\UI" /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"
XCopy "%BUI%\*.officeUI" "%OneDriveCommercial%\Backup\UI" /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"


::GET SICKYNOTES
echo CopyingStickyNotes >> "%Onedrive%\backup\log.txt"
echo CopyingStickyNotes >> "%OneDriveCommercial%\backup\log.txt"
SET BSticky=%APPDATA%\Microsoft\Sticky Notes
SET RSticky="%Onedrive%\Backup\Sticky"
if not exist "%Onedrive%\Backup\Sticky" mkdir "%Onedrive%\Backup\Sticky"
XCopy /s "%BSticky%" "%Onedrive%\Backup\Sticky" /E /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
if not exist "%OneDriveCommercial%\Backup\Sticky" mkdir "%OneDriveCommercial%\Backup\Sticky"
XCopy /s "%BSticky%" "%OneDriveCommercial%\Backup\Sticky" /E /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"

::GET CHROME BOOKMARKS
echo CopyingChromeBookmarks >> "%Onedrive%\backup\log.txt"
echo CopyingChromeBookmarks >> "%OneDriveCommercial%\backup\log.txt"
SET BChrome=%LOCALAPPDATA%\Google\Chrome\User Data\Default
SET RChrome="%Onedrive%\Backup\Chrome"
if not exist "%Onedrive%\Backup\Chrome" mkdir "%Onedrive%\Backup\Chrome"
XCopy "%BChrome%\Bookmarks*" "%Onedrive%\Backup\Chrome\Bookmarks*" /E /Y /C /Z /D >> "%Onedrive%\backup\log.txt"
if not exist "%OneDriveCommercial%\Backup\Chrome" mkdir "%OneDriveCommercial%\Backup\Chrome"
XCopy "%BChrome%\Bookmarks*" "%OneDriveCommercial%\Backup\Chrome\Bookmarks*" /E /Y /C /Z /D >> "%OneDriveCommercial%\backup\log.txt"

::GET MAPPED DRIVES
echo MappingDrives >> "%Onedrive%\backup\log.txt"
net use >> "%Onedrive%\backup\log.txt"
