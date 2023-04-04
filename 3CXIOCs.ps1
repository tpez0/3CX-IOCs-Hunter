 #-------------------------------------------------------------------------------------
 # Script: 3CXIOCs.ps1
 # Author: tpez0
 # Notes : No warranty expressed or implied.
 #         Use at your own risk.
 #
 # Function: Simple tool to check Indicators of 3CX DLL-sideloading exploitation
 #              Hashes of compromised files here: 
 #                  https://github.com/sophoslabs/IoCs/blob/master/3CX%20IoCs%202023-03.csv
 #                  https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/
 #                  https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/3cx-supply-chain-attack 
 #--------------------------------------------------------------------------------------

$filelist = @('3CXDesktopApp.exe',
                'ffmpeg.dll', 
                'd3dcompiler.dll',
                'd3dcompiler_47.dll',
                'trololo.dll',
                '3cxdesktopapp-18.12.407.msi', 
                '3cxdesktopapp-18.12.416.msi',
                '717d29.msi' ,
                '72c2f7.msi',
                'icon0.ico',
                'icon1.ico',
                'icon2.ico',
                'icon3.ico',
                'icon4.ico',
                'icon5.ico',
                'icon6.ico',
                'icon7.ico',
                'icon8.ico',
                'icon9.ico',
                'icon10.ico',
                'icon11.ico',
                'icon12.ico',
                'icon13.ico',
                'icon14.ico',
                'icon15.ico')
$IOClist = @('11be1803e2e307b647a8a7e02d128335c448ff741bf06bf52b332e0bbf423b03', 
                '210c9882eba94198274ebc787fe8c88311af24932832a7fe1f1ca0261f815c3d',
                '2487b4e3c950d56fb15316245b3c51fbd70717838f6f82f32db2efcc4d9da6de',
                '268d4e399dbbb42ee1cd64d0da72c57214ac987efbb509c46cc57ea6b214beca',
                '2c9957ea04d033d68b769f333a48e228c32bcf26bd98e51310efd48e80c1789f',
                '4e08e4ffc699e0a1de4a5225a0b4920933fbb9cf123cde33e1674fde6d61444f',
                '59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983', 
                '7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896', 
                '8c0b7d90f14c55d4f1d0f17e0242efd78fd4ed0c344ac6469611ec72defa6b2d',
                'a541e5fc421c358e0a2b07bf4771e897fb5a617998aa4876e0e1baa5fbb8e25c',
                'aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868', 
                'aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973',
                'c13d49ed325dec9551906bafb6de9ec947e5ff936e7e40877feb2ba4bb176396',
                'c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02', 
                'c62dce8a77d777774e059cf1720d77c47b97d97c3b0cf43ade5d96bf724639bd',
                'd0f1984b4fe896d0024533510ce22d71e05b20bad74d53fae158dc752a65782e',
                'd459aa0a63140ccc647e9026bfd1fccd4c310c262a88896c57bbe3b6456bd090',
                'd51a790d187439ce030cf763237e992e9196e9aa41797a94956681b6279d1b9a',
                'dde03348075512796241389dfea5560c20a3d2a2eac95c894e7bbed5e85a0acc',
                'e059c8c8b01d6f3af32257fc2b6fe188d5f4359c308b3684b1e0db2071c3425c',
                'f1bf4078141d7ccb4f82e3f4f1c3571ee6dd79b5335eb0e0464f877e6e6e3182',
                'f47c883f59a4802514c57680de3f41f690871e26f250c6e890651ba71027e4d3',
                'fad482ded2e25ce9e1dd3d3ecc3227af714bdfbbde04347dbc1b21d6a3670405',
                '20d554a80d759c50d6537dd7097fed84dd258b3e',
                'bf939c9c261d27ee7bb92325cc588624fca75429',
                'cad1120d91b812acafef7175f949dd1b09c6c21a')

foreach ($filename in $filelist) {
Write-Host 'Looking for'  $filename ':' -ForegroundColor Magenta
Get-ChildItem $filename -Path C:\ -Recurse -ErrorAction SilentlyContinue | Select Fullname 
    | ForEach-Object {
        $filefullname = $_.FullName
        Write-Host 'Checking hash for '  $filefullname -NoNewline
        $fileHash256 = (Get-FileHash $filefullname -Algorithm SHA256).Hash
        $fileHash1 = (Get-FileHash $filefullname -Algorithm SHA1).Hash
         if ($IOClist -contains $fileHash256 -or $IOClist -contains $fileHash1)
                {
                        $status = "Compromised"
                        $found = $true
                        $color = 'Red'
                    }
                    else {
                        $status = "Clean"
                        $found = $false
                        $color = 'Green'
                    }

            $res = New-Object PSObject -Property @{
                FileName = $filefullname 
                Hash = @($fileHash256, $fileHash1)
                Status = $status
            }
            Write-Host ': ' -NoNewline
            Write-Host $res.Status -ForegroundColor $color
        }
        }