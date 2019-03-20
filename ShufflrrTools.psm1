function Set-ShufflrrConfig {
<#
.SYNOPSIS
Configures saved Shufflr site and login information on the local machine.

.DESCRIPTION
Saves Shufflrr site, e-mail, and encrypted password to the registry to be used by Shufflrr Tools for Powershell
without specifying the values on each call.

.PARAMETER Site
Specifies the Shufflrr site to call.
Parameter is mandatory.

.PARAMETER Email
Specifies the email/login used for login.
Parameter is mandatory.

.PARAMETER Password
Specifies the password used for login.
Parameter is mandatory.

.INPUTS
System.String. Set-ShufflrrConfig accepts strings for all parameters.

.OUTPUTS
None.

.EXAMPLE
C:\PS> Set-ShufflrrConfig -Site "https://company.shufflrr.com" -Email "user@shufflrr.com" -Password "M1s3Cr379@sSw0R@"
#>
	[CmdletBinding(SupportsShouldProcess=$false)]
    PARAM
    (
        [parameter(Mandatory = $true)][string]$Site,
        [parameter(Mandatory = $true)][string]$Email,
        [parameter(Mandatory = $true)][string]$Password

    )
	$RegPath = "HKCU:\SOFTWARE\Shufflrr"
	If (!(Test-Path "$RegPath\STPS"))
		{
			Try
				{
					New-Item -Path "$RegPath" -Name "STPS" -Force
				}
			Catch
			{
				[System.Exception]
				Write-Output "Unable to write to the registry, you may need to run this from an administrative powershell session."
			}
		}
	If ($Site.Length -eq 0) {
		$Site = Read-Host "Please enter the URL of your Shufflrr site (example: https://mycompany.shufflrr.com):"
	}
	If ($Email.Length -eq 0) {
		$Email = Read-Host "Please enter your Shufflrr username/email:"
	}
	If ($Password.Length -eq 0) {
		$SecurePassword = Read-Host "Please enter your Shufflrr account password:" -AsSecureString | ConvertFrom-SecureString
	}
	Else {
		$SecurePassword = $password | ConvertTo-SecureString -AsPlainText -Force
	}
	$RegPath = "$RegPath\STPS"
    	If (!(Test-Path "$RegPath\config")) {
			Try
				{
						New-Item -Path $RegPath\config -Force
				}
			Catch
			{
				[System.Exception]
				Write-Output "Unable to write to the registry, you may need to run this from an administrative powershell session."
			}
		}
        Else {
            Try
                {    Remove-ItemProperty -Path $RegPath\config -Name * -Force
                }
			Catch
			{
				[System.Exception]
				Write-Output "Unable to write to the registry, you may need to run this from an administrative powershell session."
			}
        }
    $RegPath = "$RegPath\config"
    $SecureHash = $SecurePassword | ConvertFrom-SecureString

    New-ItemProperty -Path $RegPath -PropertyType String -Name Site -Value $Site
	New-ItemProperty -Path $RegPath -PropertyType String -Name Email -Value $Email
	New-ItemProperty -Path $RegPath -PropertyType String -Name Password -Value $SecureHash
}
<#
	Function to login to Shufflrr to be used by other components.
#>
function Get-ShufflrrCredential {
	[CmdletBinding()]
	PARAM
	(
		[string]$Site,
		[string]$Email,
		[string]$Password
	)
	If ([string]::IsNullOrWhiteSpace($Site)) {
		Try {
			$Site = (Get-ItemProperty -Path HKCU:\SOFTWARE\Shufflrr\STPS\config).Site
		}
		Catch [System.Management.Automation.ItemNotFoundException] {
			Write-Output "No Shufflrr Site specified. Either configure Shufflrr Tools for Powershell using Set-ShufflrrConfig or pass a site URI with the -Site key."
		}
		Catch {
			Write-Output "Something went wrong, please check your configuration and connection and try again."
		}
	}
	If ([string]::IsNullOrWhiteSpace($Email)) {
		Try {
			$Email = (Get-ItemProperty -Path HKCU:\SOFTWARE\Shufflrr\STPS\config).Email
		}
		Catch [System.Management.Automation.ItemNotFoundException] {
			Write-Output "No Shufflrr login e-mail specified. Either configure Shufflrr Tools for Powershell using Set-ShufflrrConfig or pass a site URI with the -Email key."
		}
		Catch {
			Write-Output "Something went wrong, please check your configuration and connection and try again."
		}
	}
		If ([string]::IsNullOrWhiteSpace($Password)) {
		Try {
            $SecurePassword = (Get-ItemProperty -Path HKCU:\SOFTWARE\Shufflrr\STPS\config).Password | ConvertTo-SecureString
            $Credentials = New-Object System.Management.Automation.PSCredential($Email, $SecurePassword)
            $Password = $Credentials.GetNetworkCredential().Password
		}
		Catch [System.Management.Automation.ItemNotFoundException] {
			Write-Output "No Shufflrr login password specified. Either configure Shufflrr Tools for Powershell using Set-ShufflrrConfig or pass a site URI with the -Password key."
		}
		Catch {
			Write-Output "Something went wrong, please check your configuration and connection and try again."
		}
    }
    $ShufflrrCredential = "" | Select-Object -Property Site,Email,Password
    $ShufflrrCredential.Site = $Site
    $ShufflrrCredential.Email = $Email
    $ShufflrrCredential.Password = $Password
    Return $ShufflrrCredential
}

<#
	Function to validate valid Shufflrr session exists or create one to be used by other components.
#>
function Get-ShufflrrSession {
	[CmdletBinding()]
	PARAM
	(
		[string]$Site,
		[string]$Email,
		[string]$Password
	)
    $ShufflrrCredential = Get-ShufflrrCredential $Site $Email $Password
	$Site = $ShufflrrCredential.Site
    $Email = $ShufflrrCredential.Email
    $Password = $ShufflrrCredential.Password

    If (!(Test-Path Variable:Global:$ShufflrrSession) -or ($Global:ShufflrrSession.Cookies.GetCookies("$Site/api/account/login").Expired -eq $true)) {
        $LoginRequestURL = "$Site/api/account/login"
	    $LoginRawPayload = @{
	    emailAddress="$Email"
	    password="$Password"
		keepLoggedIn='true'
	}
	$LoginPayload = $LoginRawPayload | ConvertTo-Json
	Invoke-WebRequest -Method POST -ContentType 'application/json' -Body $LoginPayload -Uri $LoginRequestURL -SessionVariable 'ShufflrrSession' -UseBasicParsing
	$Global:ShufflrrCookies = $ShufflrrSession.Cookies.GetCookies($LoginRequestURL)
	$Global:ShufflrrSession = $ShufflrrSession
    }
}

function Get-ShufflrrDir {
<#
.SYNOPSIS
Gets the contents of a Shufflrr folder.

.DESCRIPTION
Displays the objects in a Shufflrr folder with name, id, type, and current users' permissions.

.PARAMETER Site
Specifies the Shufflrr site to call if it has not been set globally.
Parameter is optional.

.PARAMETER Email
Specifies the email/login used for login if it has not been set globally.
Parameter is optional.

.PARAMETER Password
Specifies the password used for login if it has not been set globally.
Parameter is optional.

.PARAMETER Folder
Specifies the name or path of a folder to list the contents of. Can be used instead of FolderID.
This parameter is optional.

.PARAMETER FolderID
Specifies a Folder ID to list the contents of. Can be used instead of Folder.

.INPUTS
System.String. Get-ShufflrrDir accepts strings for all parameters.

.OUTPUTS
PSObject. Get-ShufflrrDir outpouts a table formatted PSObject.

.EXAMPLE
C:\PS> Get-ShufflrrDir -Site "https://company.shufflrr.com" -Email "user@shufflrr.com" -Password "M1s3Cr379@sSw0R@" -Folder "\My Folder\My Subfolder"
name                     id fileType       userPermissions
----                     -- --------       ---------------
My Presentations     999999 Folder         Read, Write, Share, FullControl
Another Folder       111111 Folder         Read, Write, Share, FullControl
Test.pptx            555555 Presentation   Read, Write, Share, FullControl

.EXAMPLE

C:\PS> Get-ShufflrrDir -FolderId "123456"
name               id     fileType userPermissions
----               --     -------- ---------------
A Folder           123456 Folder   Read, Write, Share, FullControl
My Presentations   654321 Folder   Read, Write, Share, FullControl
Test Folder        135790 Folder   Read, Write, Share, FullControl
#>
	[CmdletBinding()]
	PARAM
	(
		[string]$Site,
		[string]$Email,
		[string]$Password,
		[string]$Folder,
		[string]$FolderID
	)
    $ShufflrrCredential = Get-ShufflrrCredential $Site $Email $Password

    $ShufflrrSession = Get-ShufflrrSession $Site $Email $Password
    $Site = $ShufflrrCredential.Site
    $Email = $ShufflrrCredential.Email
    $Password = $ShufflrrCredential.Password

	$RootFolders = Invoke-RestMethod -Uri "$Site/api/folders/" -WebSession $Global:ShufflrrSession
	$RootFolderList = [Collections.Generic.List[Object]]($RootFolders)

    If (([string]::IsNullOrWhiteSpace($Folder)) -And ([string]::IsNullOrWhiteSpace($FolderID))) {
        Return $RootFolders | Sort-Object -Property name | Select-Object -Property name, id, fileType, userPermissions | Format-Table -AutoSize
    }
    Else {
        If ([string]::IsNullOrWhiteSpace($Folder)) {
            $FolderContents = Invoke-RestMethod -Uri "$Site/api/folders/$FolderID/contents" -WebSession $Global:ShufflrrSession
            Return $FolderContents | Sort-Object -Property name | Select-Object -Property name, id, fileType, userPermissions | Format-Table -AutoSize
        }
        Else {
            $Folder = $Folder.Trim("\")
            $FolderDepth = ([regex]::Matches($Folder, "\\")).count + 1
            $FolderTree = $Folder -split '\\'

            If ($FolderDepth -eq 1) {
                $RootFolderIndex = $RootFolderList.FindIndex( {$args[0].name -eq "$Folder"} )
                If ($RootFolderIndex -eq -1) {
                    Write-Error "A folder `"$Folder`" does not exist. Please check your spelling and try again." -ErrorAction Stop
                }
                $FolderId = $RootFolderList.id[$RootFolderIndex]
                $FolderContents = Invoke-RestMethod -Uri "$Site/api/folders/$FolderID/contents" -WebSession $Global:ShufflrrSession
                Return $FolderContents | Sort-Object -Property name | Select-Object -Property name, id, fileType, userPermissions | Format-Table -AutoSize
            }
            Else {
                for ($i=0; $i -lt $FolderDepth; $i++) {
                    If ($i -eq 0) {
                        $FolderIndex = $RootFolderList.FindIndex( {$args[0].name -eq $FolderTree[$i] } )
                        If ($FolderIndex -eq -1) {
                            Write-Error "A folder `"$Folder`" does not exist. Please check your spelling and try again." -ErrorAction Stop
                        }
                        $FolderId = $RootFolderList.id[$FolderIndex]
                        $FolderContents = Invoke-RestMethod -Uri "$Site/api/folders/$FolderID/contents" -WebSession $Global:ShufflrrSession
                        $FolderList = [Collections.Generic.List[Object]]($FolderContents)
                    }
                    Else {
                        $FolderIndex = $FolderList.FindIndex( {$args[0].name -eq $FolderTree[$i]} )
                        If ($FolderIndex -eq -1) {
                            Write-Error "A folder `"$Folder`" does not exist. Please check your spelling and try again." -ErrorAction Stop
                        }
                        $FolderId = $FolderList.id[$FolderIndex]
                        $FolderContents = Invoke-RestMethod -Uri "$Site/api/folders/$FolderID/contents" -WebSession $Global:ShufflrrSession
                        $FolderList = [Collections.Generic.List[Object]]($FolderContents)
                    }
                }
                Return $FolderContents | Sort-Object -Property name | Select-Object -Property name, id, fileType, userPermissions | Format-Table -AutoSize
            }
        }
    }
}

function Get-ShufflrrFile {
<#
.SYNOPSIS
Gets a file from a Shufflrr site.

.DESCRIPTION
Downloads files from Shufflrr sites to the local computer.

.PARAMETER Site
Specifies the Shufflrr site to call if it has not been set globally.
Parameter is optional.

.PARAMETER Email
Specifies the email/login used for login if it has not been set globally.
Parameter is optional.

.PARAMETER Password
Specifies the password used for login if it has not been set globally.
Parameter is optional.

.PARAMETER ShufflrrPath
Specifies the path and name of a file to download.
This parameter is optional.

.PARAMETER FilePath
Specifies the local path to download the file to.

.INPUTS
System.String. Get-ShufflrrFile accepts strings for all parameters.

.OUTPUTS
System.String. Get-ShufflrrFile outputs a confirmation string.

.EXAMPLE
C:\PS> Get-ShufflrrFile -Site "https://company.shufflrr.com" -Email "user@shufflrr.com" -ShufflrrPath "My Folder\My File.pptx" -FilePath "C:\Shufflrr\Downloads"
Your file has been downloaded.
#>
	[CmdletBinding()]
	PARAM
	(
		[string]$Site,
		[string]$Email,
		[string]$Password,
		[string]$ShufflrrPath,
		[string]$FilePath
	)
    $ShufflrrCredential = Get-ShufflrrCredential $Site $Email $Password

    $ShufflrrSession = Get-ShufflrrSession $Site $Email $Password
    $Site = $ShufflrrCredential.Site
    $Email = $ShufflrrCredential.Email
    $Password = $ShufflrrCredential.Password

    $ShufflrrPath = $ShufflrrPath.Trim("\")
    $FolderDepth = ([regex]::Matches($ShufflrrPath, "\\")).count
    $FolderTree = $ShufflrrPath -split '\\'

    Try {
        If(!(Test-Path -Path $FilePath)) {
            New-Item -ItemType Directory -Force -Path $FilePath -ErrorAction Stop
        }
    }
    Catch {
        Write-Error "A folder `"$FilePath`" does not exist and could not be created. Please check permissions." -ErrorAction Stop
    }

    $RootFolders = Invoke-RestMethod -Uri "$Site/api/folders/" -WebSession $Global:ShufflrrSession
    $RootFolderList = [Collections.Generic.List[Object]]($RootFolders)

    If ($FolderDepth -eq 1) {
        $RootFolderIndex = $RootFolderList.FindIndex( {$args[0].name -eq "$($FolderTree[0])" } )
        If ($RootFolderIndex -eq -1) {
                Write-Error "A folder named `"$($FolderTree[0])`" does not exist at the root of this site. Please check your spelling and try again." -ErrorAction Stop
            }
            $FolderId = $RootFolderList.id[$RootFolderIndex]
            $FolderContents = Invoke-RestMethod -Uri "$Site/api/folders/$FolderID/contents" -WebSession $Global:ShufflrrSession
            $FolderList = [Collections.Generic.List[Object]]($FolderContents)
            $FolderIndex = $FolderList.FindIndex( {$args[0].name -eq "$($FolderTree[1])" } )

            Try {
                $Download = Invoke-RestMethod -Uri "$($FolderList.downloadUrl[$FolderIndex])" -WebSession $Global:ShufflrrSession -OutFile "$($FilePath)\$($FolderList.name[$FolderIndex])" -ErrorAction Stop
                $Download
            }
            Catch {
                Write-Error "Sorry, the file could not be downloaded at this time. Please check your connection and credentials and try again." -ErrorAction Stop
            }
        }
        Else {
            for ($i=0; $i -lt $FolderDepth; $i++) {
                If ($i -eq 0) {
                    $FolderIndex = $RootFolderList.FindIndex( {$args[0].name -eq $FolderTree[$i] } )
                    If ($FolderIndex -eq -1) {
                        Write-Error "A folder `"$($FolderTree[0])`" does not exist. Please check your spelling and try again." -ErrorAction Stop
                    }
                    $FolderId = $RootFolderList.id[$FolderIndex]
                    $FolderContents = Invoke-RestMethod -Uri "$Site/api/folders/$FolderID/contents" -WebSession $Global:ShufflrrSession
                    $FolderList = [Collections.Generic.List[Object]]($FolderContents)
                }
                Else {
                    $FolderIndex = $FolderList.FindIndex( {$args[0].name -eq $FolderTree[$i]} )
                    If ($FolderIndex -eq -1) {
                        Write-Error "A folder `"$($FolderTree[$i])`" does not exist. Please check your spelling and try again." -ErrorAction Stop
                    }
                    $FolderId = $FolderList.id[$FolderIndex]
                    $FolderContents = Invoke-RestMethod -Uri "$Site/api/folders/$FolderID/contents" -WebSession $Global:ShufflrrSession
                    $FolderList = [Collections.Generic.List[Object]]($FolderContents)
                    If ($i -eq ($FolderDepth - 1)) {
                        $f = $i + 1
                        $FolderIndex = $FolderList.FindIndex( {$args[0].name -eq $FolderTree[$f] } )
                        Try {
                            $Download = Invoke-RestMethod -Uri "$($FolderList.downloadUrl)" -WebSession $Global:ShufflrrSession -OutFile "$($FilePath)\$($FolderList.name)" -ErrorAction Stop
                            $Download
                            Write-Output "Your file has been downloaded."
                        }
                        Catch {
                            Write-Error "Sorry, the file could not be downloaded at this time. Please check your connection and credentials and try again." -ErrorAction Stop
                        }
                    }

                }
        }
    }
}

function Add-ShufflrrFile {
<#
.SYNOPSIS
Adds a file from a Shufflrr site.

.DESCRIPTION
Uploads a file from the local computer to a Shufflrr site.

.PARAMETER Site
Specifies the Shufflrr site to call if it has not been set globally.
Parameter is optional.

.PARAMETER Email
Specifies the email/login used for login if it has not been set globally.
Parameter is optional.

.PARAMETER Password
Specifies the password used for login if it has not been set globally.
Parameter is optional.

.PARAMETER FilePath
Specifies the path and name of a file on the local computer to upload.
This parameter is mandatory.

.PARAMETER DestFolder
Specifies the path to a Shufflrr folder to upload to.
This parameter is mandatory.

.PARAMETER ContentType
Specifies the Content-Type of the file being uploaded, if not used Shufflrr Tools will attempt to determine it.
This parameter is optional.

.PARAMETER UpdateSlides
Switch to enable UpdateSlides option on the upload. Default is false.
This parameter is optional.

.INPUTS
System.String. Get-ShufflrrFile accepts strings for all parameters.

.OUTPUTS
System.String. Get-ShufflrrFile outputs a confirmation string.

.EXAMPLE
C:\PS> Add-ShufflrrFile -Site "https://company.shufflrr.com" -Email "user@shufflrr.com" -FilePath "C:\My Folder\My File.pptx" -DestFolder "My Folder\My Uploads"
Your file has been uploaded.

.EXAMPLE
C:\PS> Add-ShufflrrFile -FilePath "C:\My Folder\My File.txt" -DestFolder "My Folder\My Uploads" -ContentType 'text/plain' -UpdateSlides
#>
    [CmdletBinding()]
    PARAM
    (
        [string]$Site,
		[string]$Email,
		[string]$Password,
        [string][parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]$FilePath,
        [string][parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]$DestFolder,
        [string]$ContentType,
        [switch]$UpdateSlides

    )
    BEGIN
    {
    $ShufflrrCredential = Get-ShufflrrCredential $Site $Email $Password

    $ShufflrrSession = Get-ShufflrrSession $Site $Email $Password
    $Site = $ShufflrrCredential.Site
    $Email = $ShufflrrCredential.Email
    $Password = $ShufflrrCredential.Password

    If ($UpdateSlides) {
        [string]$UpdateSlides = "`"true`""
    }
    Else {
        [string]$UpdateSlides = "`"false`""
    }
   	$RootFolders = Invoke-RestMethod -Uri "$Site/api/folders/" -WebSession $Global:ShufflrrSession
	$RootFolderList = [Collections.Generic.List[Object]]($RootFolders)

    $DestFolder = $DestFolder.Trim("\")
    $FolderDepth = ([regex]::Matches($DestFolder, "\\")).count + 1
    $FolderTree = $DestFolder -split '\\'

    If ($FolderDepth -eq 1) {
        $RootFolderIndex = $RootFolderList.FindIndex( {$args[0].name -eq "$DestFolder"} )
        If ($RootFolderIndex -eq -1) {
            Write-Error "A folder `"$DestFolder`" does not exist. Please check your spelling and try again." -ErrorAction Stop
        }
        $FolderId = $RootFolderList.id[$RootFolderIndex]
    }
    Else {
        for ($i=0; $i -lt $FolderDepth; $i++) {
            If ($i -eq 0) {
                $FolderIndex = $RootFolderList.FindIndex( {$args[0].name -eq $FolderTree[$i] } )
                If ($FolderIndex -eq -1) {
                    Write-Error "A folder `"$DestFolder`" does not exist. Please check your spelling and try again." -ErrorAction Stop
                }
                $FolderId = $RootFolderList.id[$FolderIndex]
                $FolderContents = Invoke-RestMethod -Uri "$Site/api/folders/$FolderID/contents" -WebSession $Global:ShufflrrSession
                $FolderList = [Collections.Generic.List[Object]]($FolderContents)
            }
            Else {
                $FolderIndex = $FolderList.FindIndex( {$args[0].name -eq $FolderTree[$i]} )
                If ($FolderIndex -eq -1) {
                    Write-Error "A folder `"$DestFolder`" does not exist. Please check your spelling and try again." -ErrorAction Stop
                }
                $FolderId = $FolderList.id[$FolderIndex]
                $FolderContents = Invoke-RestMethod -Uri "$Site/api/folders/$FolderID/contents" -WebSession $Global:ShufflrrSession
                $FolderList = [Collections.Generic.List[Object]]($FolderContents)
            }
        }
    }
        if (-not (Test-Path $FilePath))
        {
            $errorMessage = ("File {0} missing or unable to read." -f $FilePath)
            $exception =  New-Object System.Exception $errorMessage
			$errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, 'MultipartFormDataUpload', ([System.Management.Automation.ErrorCategory]::InvalidArgument), $FilePath
			$PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        if (-not $ContentType)
        {
            Add-Type -AssemblyName System.Web

            $mimeType = [System.Web.MimeMapping]::GetMimeMapping($FilePath)

            if ($mimeType)
            {
                $ContentType = $mimeType
            }
            else
            {
                $ContentType = "application/octet-stream"
            }
        }
    }
    PROCESS
    {
		$fileName = Split-Path $FilePath -leaf
        $boundary = [guid]::NewGuid().ToString("N")
        $formboundary = "----STPSFormBoundary$boundary"
		$cookies = $Global:ShufflrrSession.Cookies.GetCookies("$Site/api/account/login")
        $cookiearray = "$($cookies[0].name)", "$($cookies[0].value)"
        $headercookie = [string]::Join("=",$cookiearray)
    	$fileBin = [System.IO.File]::ReadAllBytes($FilePath)
        $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
        $Uri = "$Site/api/folders/$($FolderId)/upload"
        $Headers = @{"Cookie"="$headercookie"; "Origin"="$Site"; "Accept-Encoding"="gzip, deflate, br"; "Accept-Language"="en-US,en;q=0.9"; "User-Agent"="Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.120 Safari/537.36 Vivaldi/2.3.1440.57"; "Accept"="application/json, text/javascript, */*; q=0.01"; "Referer"="$($Site)/Shufflrr"; "X-Requested-With"="XMLHttpRequest"}
        $Body = "--$($formboundary)$([char]13)$([char]10)Content-Disposition: form-data; name=`"metadataset`"$([char]13)$([char]10)$([char]13)$([char]10){`"metadata`":[],`"updateSlides`":$($UpdateSlides)}$([char]13)$([char]10)--$($formboundary)$([char]13)$([char]10)Content-Disposition: form-data; name=`"uploadId`"$([char]13)$([char]10)$([char]13)$([char]10)9431$([char]13)$([char]10)--$($formboundary)$([char]13)$([char]10)Content-Disposition: form-data; name=`"files[]`"; filename=`"$fileName`"$([char]13)$([char]10)Content-Type: $ContentType$([char]13)$([char]10)$([char]13)$([char]10)$($enc.GetString($fileBin))$([char]13)$([char]10)--$($formboundary)--$([char]13)$([char]10)"

        try
		{
			$FileUpload =  Invoke-WebRequest -Uri $Uri `
                                     -Method "POST" `
                                     -Headers $Headers `
									 -ContentType "multipart/form-data; boundary=$($formboundary)" `
									 -Body $body `
                                     -WebSession $Global:ShufflrrSession

            If ($FileUpload.StatusCode -eq 200 -and $FileUpload.Content -eq "[{`"filename`":`"$fileName`",`"error`":null,`"complete`":true}]") {
                "File has been successfully uploaded to $($DestFolder)\$($fileName)."
            }
            Else {
                Write-Error "Something went wrong trying to upload the file, please check the error details and try again." -ErrorAction Stop
            }
		}
		catch [Exception]
		{
			$PSCmdlet.ThrowTerminatingError($_)
		}
    }
    END { }
}

function Remove-ShufflrrFile {
<#
.SYNOPSIS
Deletes a file from a Shufflrr site.

.DESCRIPTION
Deletes files from Shufflrr sites.

.PARAMETER Site
Specifies the Shufflrr site to call if it has not been set globally.
Parameter is optional.

.PARAMETER Email
Specifies the email/login used for login if it has not been set globally.
Parameter is optional.

.PARAMETER Password
Specifies the password used for login if it has not been set globally.
Parameter is optional.

.PARAMETER ShufflrrFile
Specifies the path and name of a file to delete.
This parameter is mandatory.

.INPUTS
System.String. Get-ShufflrrFile accepts strings for all parameters.

.OUTPUTS
System.String. Get-ShufflrrFile outputs a confirmation string.

.EXAMPLE
C:\PS> Remove-ShufflrrFile -Site "https://company.shufflrr.com" -Email "user@shufflrr.com" -ShufflrrFile "My Folder\My File.pptx"
Your file has been deleted.
#>
	[CmdletBinding(SupportsShouldProcess=$false)]
	PARAM
	(
		[string]$Site,
		[string]$Email,
		[string]$Password,
		[parameter(Mandatory = $true)][string]$ShufflrrFile
	)
    $ShufflrrCredential = Get-ShufflrrCredential $Site $Email $Password

    $ShufflrrSession = Get-ShufflrrSession $Site $Email $Password
    $Site = $ShufflrrCredential.Site
    $Email = $ShufflrrCredential.Email
    $Password = $ShufflrrCredential.Password

    $ShufflrrFile = $ShufflrrFile.Trim("\")
    $FolderDepth = ([regex]::Matches($ShufflrrFile, "\\")).count
    $FolderTree = $ShufflrrFile -split '\\'

    $RootFolders = Invoke-RestMethod -Uri "$Site/api/folders/" -WebSession $Global:ShufflrrSession
    $RootFolderList = [Collections.Generic.List[Object]]($RootFolders)
    $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $Headers.Add("Accept", 'application/json, text/javascript, */*; q=0.01')
    $Headers.Add("Origin", "$Site")
    $Headers.Add("X-Requested-With", "XMLHttpRequest")
    $Headers.Add("Content-Type", 'application/json')
    $Headers.Add("Referer", "$($Site)/Shufflrr")
    $Headers.Add("Accept-Encoding", "gzip, deflate, br")
    $Headers.Add("Accept-Language", "en-US,en;q=0.9")

    If ($FolderDepth -eq 1) {
        $RootFolderIndex = $RootFolderList.FindIndex( {$args[0].name -eq "$($FolderTree[0])" } )
        If ($RootFolderIndex -eq -1) {
                Write-Error "A folder named `"$($FolderTree[0])`" does not exist at the root of this site. Please check your spelling and try again." -ErrorAction Stop
            }
            $FolderId = $RootFolderList.id[$RootFolderIndex]
            $FolderContents = Invoke-RestMethod -Uri "$Site/api/folders/$FolderID/contents" -WebSession $Global:ShufflrrSession
            $FolderList = [Collections.Generic.List[Object]]($FolderContents)
            $FolderIndex = $FolderList.FindIndex( {$args[0].name -eq "$($FolderTree[1])" } )

            Try {
                $DeleteFile = Invoke-RestMethod -Uri "$($Site)/api/files/$($FolderList.id)" -WebSession $Global:ShufflrrSession -Method Delete -Headers $Headers -Body "{ }"
                $DeleteFile
            }
            Catch {
                Return $DeleteFile
                Write-Error "Sorry, the file could not be deleted at this time. Please check your connection and credentials and try again." -ErrorAction Stop
            }
        }
        Else {
            for ($i=0; $i -lt $FolderDepth; $i++) {
                If ($i -eq 0) {
                    $FolderIndex = $RootFolderList.FindIndex( {$args[0].name -eq $FolderTree[$i] } )
                    If ($FolderIndex -eq -1) {
                        Write-Error "A folder `"$($FolderTree[0])`" does not exist. Please check your spelling and try again." -ErrorAction Stop
                    }
                    $FolderId = $RootFolderList.id[$FolderIndex]
                    $FolderContents = Invoke-RestMethod -Uri "$Site/api/folders/$FolderID/contents" -WebSession $Global:ShufflrrSession
                    $FolderList = [Collections.Generic.List[Object]]($FolderContents)
                }
                Else {
                    $FolderIndex = $FolderList.FindIndex( {$args[0].name -eq $FolderTree[$i]} )
                    If ($FolderIndex -eq -1) {
                        Write-Error "A folder `"$($FolderTree[$i])`" does not exist. Please check your spelling and try again." -ErrorAction Stop
                    }
                    $FolderId = $FolderList.id[$FolderIndex]
                    $FolderContents = Invoke-RestMethod -Uri "$Site/api/folders/$FolderID/contents" -WebSession $Global:ShufflrrSession
                    $FolderList = [Collections.Generic.List[Object]]($FolderContents)
                    If ($i -eq ($FolderDepth - 1)) {
                        $f = $i + 1
                        $FolderIndex = $FolderList.FindIndex( {$args[0].name -eq $FolderTree[$f] } )
                        If ($FolderIndex -eq -1) {
                            Write-Error "Sorry, the file `"$ShufflrrFile`" does not exist." -ErrorAction Stop
                        }
                        Try {
                            $DeleteFile = Invoke-RestMethod -Uri "$($Site)/api/files/$($FolderList.id)" -WebSession $Global:ShufflrrSession -Method Delete -Headers $Headers -Body "{ }"
                            $DeleteFile
                            Write-Output "Your file has been deleted."
                        }
                        Catch {
                            Write-Error "Sorry, the file could not be deleted at this time. Please check your connection and credentials and try again." -ErrorAction Stop
                        }
                    }

                }
        }
    }
}