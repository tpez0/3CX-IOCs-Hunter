 #-------------------------------------------------------------------------------------
 # Script: 3CXIOCs.ps1
 # Author: tpez0
 # Notes : No warranty expressed or implied.
 #         Use at your own risk.

 # Function: Simple tool to check Indicators of 3CX DLL-sideloading exploitation
 #           Hashes of compromised files here: https://github.com/sophoslabs/IoCs/blob/master/3CX%20IoCs%202023-03.csv
 #--------------------------------------------------------------------------------------

$filelist = @('ffmpeg.dll', 'd3dcompiler.dll', '3cxdesktopapp-18.12.407.msi', '3cxdesktopapp-18.12.416.msi', 'icon13.ico')

foreach ($filename in $filelist) {
Write-Host 'Get files '  $filename ':' -ForegroundColor Magenta
Get-ChildItem $filename -Path C:\ -Recurse -ErrorAction SilentlyContinue | Select Fullname 
    | ForEach-Object {
        $filefullname = $_.FullName
        Write-Host 'Checking hash for '  $filefullname ':'
        $fileHash = (Get-FileHash $filefullname -Algorithm SHA256).Hash
        if ($fileHash -eq 'c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02' -or $fileHash -eq 'aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868' -or $fileHash -eq '59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983' -or $fileHash -eq 'c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02' -or $fileHash -eq '7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896' -or $fileHash -eq '11be1803e2e307b647a8a7e02d128335c448ff741bf06bf52b332e0bbf423b03' -or $fileHash -eq '4e08e4ffc699e0a1de4a5225a0b4920933fbb9cf123cde33e1674fde6d61444f')
                    {
                        Write-Host 'Compromised' -ForegroundColor Red
                        Write-Host ' '
                    }
                    else {
                        Write-Host 'Clean' -ForegroundColor Green
                        Write-Host ' '
                    }
                }
        }
        
## https://github.com/sophoslabs/IoCs/blob/master/3CX%20IoCs%202023-03.csv  