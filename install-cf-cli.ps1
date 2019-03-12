
<#PSScriptInfo

.VERSION 1.4

.GUID aa17cffe-c071-4ced-8c48-5e33793c4a84

.AUTHOR kbott@pivotal.io

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#>

<# 

.DESCRIPTION 
 Download and Install Cloudfoundry CF CLI Releases from GitHub using Dynamic Parameters

#> 
# This helper script downloads an available om Version
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript( {
            write-verbose $_
            if (-Not ( split-path -LiteralPath $_ | Test-Path ) ) {
                throw "Folder does not exist or is not a container"
            }
            return $true
        })]
    $DownloadDir
)
DynamicParam {
    function get-releases {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $request = Invoke-WebRequest -UseBasicParsing -Uri https://github.com/cloudfoundry/cli/releases
        $windowsRelease = $request.links | where href -Match .zip
        $releases = $windowsRelease | ForEach-Object {($_.href -split "/")[-1] -replace ".zip" -replace "v"}
        write-verbose "getting releases"
        Write-Output $releases
    }
    function New-DynamicParam {
        param(

            [string]
            $Name,

            [string[]]
            $ValidateSet,

            [switch]
            $Mandatory,

            [string]
            $ParameterSetName = "__AllParameterSets",

            [int]
            $Position,

            [switch]
            $ValueFromPipelineByPropertyName,

            [string]
            $HelpMessage,

            [validatescript( {
                    if (-not ( $_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary] -or -not $_) ) {
                        Throw "DPDictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object, or not exist"
                    }
                    $True
                })]
            $DPDictionary = $false

        )
        #Create attribute object, add attributes, add to collection
        $ParamAttr = New-Object System.Management.Automation.ParameterAttribute
        $ParamAttr.ParameterSetName = $ParameterSetName
        if ($mandatory) {
            $ParamAttr.Mandatory = $True
        }
        if ($Position -ne $null) {
            $ParamAttr.Position = $Position
        }
        if ($ValueFromPipelineByPropertyName) {
            $ParamAttr.ValueFromPipelineByPropertyName = $True
        }
        if ($HelpMessage) {
            $ParamAttr.HelpMessage = $HelpMessage
        }

        $AttributeCollection = New-Object 'Collections.ObjectModel.Collection[System.Attribute]'
        $AttributeCollection.Add($ParamAttr)

        #param validation set if specified
        if ($ValidateSet) {
            $ParamOptions = New-Object System.Management.Automation.ValidateSetAttribute -ArgumentList $ValidateSet
            $AttributeCollection.Add($ParamOptions)
        }


        #Create the dynamic parameter
        $Parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, [string], $AttributeCollection)

        #Add the dynamic parameter to an existing dynamic parameter dictionary, or create the dictionary and add it
        if ($DPDictionary) {
            $DPDictionary.Add($Name, $Parameter)
        }
        else {
            $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $Dictionary.Add($Name, $Parameter)
            $Dictionary
        }
    }
    $releases = get-releases
    $releaselist = @()
    foreach ($release in $releases ) {
        Write-Verbose $release
        $releaselist += $release


    }
    New-DynamicParam -Name CLIRelease -ValidateSet $releaselist  -Mandatory
}
Begin {
    foreach ($param in $PSBoundParameters.Keys) {
        if (-not ( Get-Variable -name $param -scope 0 -ErrorAction SilentlyContinue ) -and "Verbose", "Debug" -notcontains $param ) {
            New-Variable -Name $Param -Value $PSBoundParameters.$param -Description DynParam
            Write-Verbose "Adding variable for dynamic parameter '$param' with value '$($PSBoundParameters.$param)'"
        }
    }

}

Process {
<# this is the runas admin, blocks us from automation ;-)
    $myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

    $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
 
    # Check to see if we are currently running "as Administrator"
    if ($OldShell.IsPresent -or !$myWindowsPrincipal.IsInRole($adminRole)) {
        Write-Host "Installer will Start in a new Admin Window to Install"
        $arguments = "-DownloadDir $DownloadDir -CLIRelease $CLIRelease"
        $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell"
        $newProcess.Arguments = "$PSScriptRoot/$($myinvocation.MyCommand) $arguments" 
        Write-Verbose $newProcess.Arguments
        $newProcess.Verb = "runas"
        [System.Diagnostics.Process]::Start($newProcess) 
        exit
    }
    [switch]$OldShell = $true #>
    write-host "Downloading CF CLI Release $CLIRelease from packages.cloudfoundry.org"
    New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
    $Outfile = "$DownloadDir/$($CLIRelease).zip"
    Invoke-WebRequest -UseBasicParsing -Uri "https://packages.cloudfoundry.org/stable?release=windows64&version=$($CLIRelease)&source=github-rel"  -OutFile $Outfile
    Unblock-File $Outfile
    Write-Host "Expanding $Outfile" -NoNewline
    Expand-Archive $Outfile -DestinationPath $DownloadDir -Force
    Start-Process -FilePath "$HOME/Downloads/cf_installer.exe" -ArgumentList "/SILENT /SP-" -PassThru
    
}
end {
    $object = New-Object psobject
    $object  | Add-Member -MemberType NoteProperty -Name Path -Value cf.exe
    $object  | Add-Member -MemberType NoteProperty -Name Version -Value (cf.exe version)
    Write-Output $object
}







