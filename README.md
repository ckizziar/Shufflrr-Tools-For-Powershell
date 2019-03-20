# Shufflrr Tools for Powershell

Shufflrr Tools for PowersShell allows you to interact with Shufflrr Sites directly from within Powershell sessions, or using automation tasks. The module currently supports listing directories, uploading files, downloading files, and deleting files. Credentials can either be saved in a profile, or specified with each call.

## Getting Started

You can either download a zip release or clone the repository to get the module files.

### Prerequisites

You will need:

```
Powershell 3.0+
```

### Installing

Make sure the place the module somewhere into the Powershell Path, you can find these locations like this:

```
PS> $env:PSModulePath -split ';'
C:\Users\yourname\Documents\WindowsPowerShell\Modules
C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
```

Once you have the module where you want it, simply import it using the Import-Module command.

```
PS> Import-Module ShufflrrTools
```

You should be ready to start shuffling. To avoid providing credentials every time you want to ineract with Shufflrr, you can use the Set-ShufflrrConfig Cmdlet to create your profile.

```
PS> Set-ShufflrrConfig -Site https://myown.shufflrr.com -Email youremail@somewhere.com -Password 'M1s3Cr379@sSw0R@'

Your Shufflrr settings have been saved.

PS>
```

# Command Reference and Usage

# Add-ShufflrrFile

## SYNOPSIS
Adds a file from a Shufflrr site.

## SYNTAX

### Set 1
```
Add-ShufflrrFile [[-Site] <String>] [[-Email] <String>] [[-Password] <String>] [-FilePath] <String> [-DestFolder] <String> [[-ContentType] <String>] [-UpdateSlides] [<CommonParameters>]
```

## DESCRIPTION
Uploads a file from the local computer to a Shufflrr site.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
C:\\PS\>
```powershell
Add-ShufflrrFile -Site "https://company.shufflrr.com" -Email "user@shufflrr.com" -FilePath "C:\My Folder\My File.pptx" -DestFolder "My Folder\My Uploads"
```

Your file has been uploaded.

### -------------------------- EXAMPLE 2 --------------------------
C:\\PS\>
```powershell
Add-ShufflrrFile -FilePath "C:\My Folder\My File.txt" -DestFolder "My Folder\My Uploads" -ContentType 'text/plain' -UpdateSlides
```

## PARAMETERS

### Site
Specifies the Shufflrr site to call if it has not been set globally.
Parameter is optional.

```yaml
Type: String
Parameter Sets: Set 1
Aliases: 

Required: false
Position: 0
Default Value: 
Pipeline Input: false
```

### Email
Specifies the email/login used for login if it has not been set globally.
Parameter is optional.

```yaml
Type: String
Parameter Sets: Set 1
Aliases: 

Required: false
Position: 1
Default Value: 
Pipeline Input: false
```

### Password
Specifies the password used for login if it has not been set globally.
Parameter is optional.

```yaml
Type: String
Parameter Sets: Set 1
Aliases: 

Required: false
Position: 2
Default Value: 
Pipeline Input: false
```

### FilePath
Specifies the path and name of a file on the local computer to upload.
This parameter is mandatory.

```yaml
Type: String
Parameter Sets: Set 1
Aliases: 

Required: true
Position: 3
Default Value: 
Pipeline Input: false
```

### DestFolder
Specifies the path to a Shufflrr folder to upload to.
This parameter is mandatory.

```yaml
Type: String
Parameter Sets: Set 1
Aliases: 

Required: true
Position: 4
Default Value: 
Pipeline Input: false
```

### ContentType
Specifies the Content-Type of the file being uploaded, if not used Shufflrr Tools will attempt to determine it.
This parameter is optional.

```yaml
Type: String
Parameter Sets: Set 1
Aliases: 

Required: false
Position: 5
Default Value: 
Pipeline Input: false
```

### UpdateSlides
Switch to enable UpdateSlides option on the upload. Default is false.
This parameter is optional.

```yaml
Type: SwitchParameter
Parameter Sets: Set 1
Aliases: 

Required: false
Position: named
Default Value: False
Pipeline Input: false
```

### \<CommonParameters\>
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String. Get-ShufflrrFile accepts strings for all parameters.


## OUTPUTS

### System.String. Get-ShufflrrFile outputs a confirmation string.


## NOTES

## RELATED LINKS






# Get-ShufflrrDir

## SYNOPSIS
Gets the contents of a Shufflrr folder.

## SYNTAX

### Set 1
```
Get-ShufflrrDir [[-Site] <String>] [[-Email] <String>] [[-Password] <String>] [[-Folder] <String>] [[-FolderID] <String>] [<CommonParameters>]
```

## DESCRIPTION
Displays the objects in a Shufflrr folder with name, id, type, and current users' permissions.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
C:\\PS\>
```powershell
Get-ShufflrrDir -Site "https://company.shufflrr.com" -Email "user@shufflrr.com" -Password 'M1s3Cr379@sSw0R@' -Folder "\My Folder\My Subfolder"
```

name                     id fileType       userPermissions
----                     -- --------       ---------------
My Presentations     999999 Folder         Read, Write, Share, FullControl
Another Folder       111111 Folder         Read, Write, Share, FullControl
Test.pptx            555555 Presentation   Read, Write, Share, FullControl

### -------------------------- EXAMPLE 2 --------------------------
C:\\PS\>
```powershell
Get-ShufflrrDir -FolderId "123456"
```

name               id     fileType userPermissions
----               --     -------- ---------------
A Folder           123456 Folder   Read, Write, Share, FullControl
My Presentations   654321 Folder   Read, Write, Share, FullControl
Test Folder        135790 Folder   Read, Write, Share, FullControl

## PARAMETERS

### Site
Specifies the Shufflrr site to call if it has not been set globally.
Parameter is optional.

```yaml
Type: String
Parameter Sets: Set 1
Aliases: 

Required: false
Position: 0
Default Value: 
Pipeline Input: false
```

### Email
Specifies the email/login used for login if it has not been set globally.
Parameter is optional.

```yaml
Type: String
Parameter Sets: Set 1
Aliases: 

Required: false
Position: 1
Default Value: 
Pipeline Input: false
```

### Password
Specifies the password used for login if it has not been set globally.
Parameter is optional.

```yaml
Type: String
Parameter Sets: Set 1
Aliases: 

Required: false
Position: 2
Default Value: 
Pipeline Input: false
```

### Folder
Specifies the name or path of a folder to list the contents of. Can be used instead of FolderID.
This parameter is optional.

```yaml
Type: String
Parameter Sets: Set 1
Aliases: 

Required: false
Position: 3
Default Value: 
Pipeline Input: false
```

### FolderID
Specifies a Folder ID to list the contents of. Can be used instead of Folder.

```yaml
Type: String
Parameter Sets: Set 1
Aliases: 

Required: false
Position: 4
Default Value: 
Pipeline Input: false
```

### \<CommonParameters\>
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String. Get-ShufflrrDir accepts strings for all parameters.


## OUTPUTS

### PSObject. Get-ShufflrrDir outpouts a table formatted PSObject.


## NOTES

## RELATED LINKS




