<#
.SYNOPSIS
    Gets security data of specified email address from Microsoft Office 365.
.DESCRIPTION
    This script queries Office 365 servers to fetch security data.
.EXAMPLE
    PS C:\> .\office-365-email.ps1 -InFile <ifile>
    Read file and print output to console.
.EXAMPLE
    PS C:\> .\office-365-email.ps1 -InFile <ifile> -OutFile <ofile>
    Read file and print output to a file based on the provided name template.
.EXAMPLE
    PS C:\> Write-Host "<email-addr1>`n<email-addr2>" | .\office-365-email.ps1
    Pipe data and print output to console.
.EXAMPLE
    PS C:\> Get-Content <ifile> | .\office-365-email.ps1
    Pipe data data read from a file and print output to console.
.EXAMPLE
    PS C:\> Get-Content <ifile> | .\office-365-email.ps1 -OutFile <ofile>
    Pipe data read from a file and print output to a file based on the provided
    name template.
.NOTES
    Author:    Diogo Fernandes
    Requires:  PowerShell v5.0 and .NET Framework 4.5
#>


Param (
    [Parameter(
        HelpMessage         = "Input 'Identity' file.",
        Mandatory           = $true,
        Position            = 1,
        ValueFromPipeline   = $true
    )]
    # [ValidateScript({ Test-Path $_ })]
    [Alias('InFile')]
    [string]$ifile,

    [Parameter(
        HelpMessage         = "Output text file name template.",
        Position            = 2
    )]
    [Alias('OutFile')]
    [string]$ofile
)


# check if the command line window is running with administrator rights

if ($Input) { $data = [string]$Input }
else {
    if (Test-Path $ifile) { $data = [string](Get-Content $ifile) }
    else { throw [System.IO.FileNotFoundException] "$ifile not found" }
}

if ($data -ne $null) {
    $PSDefaultParameterValues["Out-File:Encoding"] = "utf8"
    $PSDefaultParameterValues["*:Encoding"] = "utf8"

    $uri = "https://outlook.office365.com/powershell-liveid/"

    $data = $data -split "[\n\s\t,;:]" | ? { $_ } | sort -uniq | % { $_.Trim() }
    if ($ofile -and $ofile.LastIndexOf('.') -ne -1) {
        $ofile = $ofile.Substring(0, $ofile.LastIndexOf('.'))
    }

    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
    # $cred = Get-Credential 1>$null 2>&1
    try {
        $cred = Get-Credential # -Credential <user>
    } catch [System.Management.Automation.ParameterBindingException] {
        # break # Script
        return
    }
    try {
        $sess = New-PSSession `
            -ConfigurationName Microsoft.Exchange `
            -ConnectionUri $uri `
            -Credential $cred `
            -Authentication Basic `
            -AllowRedirection
        Import-PSSession $sess -AllowClobber
    } catch { Write-Host -Foreground Red $_; return; }

    if ($ofile) {
        foreach ($i in $data) {
            $outfile = "$ofile-$i"
            Remove-Item "$outfile.txt", "$outfile.csv" *>$null
        }
    }

    foreach ($i in $data) {
        $txt = [string]$null
        $csv = [string]$null

        # try {
            # https://www.michev.info/Blog/Post/1415/error-handling-in-exchange-remote-powershell-sessions
            # Invoke-Command -Session $sess -ScriptBlock {
            # The syntax is not supported by this runspace. This can occur if the runspace is in no-language mode.
                $txt  = Get-Mailbox $i -ErrorAction SilentlyContinue | `
                    Format-List * -force
                if (!$txt) {
                    Write-Host -Foreground Red "$i not found online"
                    continue
                }

                $txt += Get-InboxRule -Mailbox $i
                $txt += Get-InboxRule -Mailbox $i | `
                    Format-List * -force
                $txt += Get-MobileDeviceStatistics -Mailbox $i | `
                    Format-List * -force

                # any subject, last 30 days
                # can be parameterized
                $csv = Get-Messagetrace -SenderAddress $i `
                    -StartDate $((Get-Date).AddDays(-30).ToString("yyy\/MM\/dd")) `
                    -EndDate $(Get-Date -UFormat "%Y/%m/%d") `
                    -PageSize 5000 | `
                    Where {$_.Subject -like "*"}
            # } -ErrorAction Stop
        # } catch { Write-Host -Foreground Red $_; continue; }

        if ($ofile) {
            $outfile = "$ofile-$i"
            $txt | Out-File "$outfile.txt"
            $csv | Export-Csv -Encoding "utf8" "$outfile.csv"
        } else {
            $txt | Out-String
            $csv | Out-String
        }
    }

    Remove-PSSession $sess
}
