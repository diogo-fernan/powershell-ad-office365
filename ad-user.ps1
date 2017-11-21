<#
.SYNOPSIS
    Gets security information of specified users from Active Directory (AD).
.DESCRIPTION
    This script queries the infrastructure masters of available domains under
    the default AD forest to fetch information of the specified 'SamAccountName'
    or 'EmailAddress' properties. In addition, the 'ProxyAddresses' property is
    also searched for email address aliases.
.EXAMPLE
    PS C:\> .\ad-user.ps1 -InFile <ifile>
    Read file and print output to console.
.EXAMPLE
    PS C:\> .\ad-user.ps1 -InFile <ifile> -OutFile <ofile>
    Read file and print output to file.
.EXAMPLE
    PS C:\> Write-Host "<user1>`n<email-addr2>" | .\ad-user.ps1
    Pipe data and print output to console.
.EXAMPLE
    PS C:\> Get-Content <ifile> | .\ad-user.ps1
    Pipe data data read from a file and print output to console.
.EXAMPLE
    PS C:\> Get-Content <ifile> | .\ad-user.ps1 -OutFile <ofile>
    Pipe data read from a file and print output to file.
.NOTES
    Author:    Diogo Fernandes
    URL:       https://github.com/diogo-fernan/
    Requires:  PowerShell v2.0
#>


Param (
    [Parameter(
        HelpMessage         = "Input 'SamAccountName' and/or 'EmailAddress' file.",
        Mandatory           = $true,
        Position            = 1,
        ValueFromPipeline   = $true
    )]
    # [ValidateScript({ Test-Path $_ })]
    [Alias('InFile')]
    [string]$ifile,

    [Parameter(
        HelpMessage         = "Output Comma Separated Value (CSV) file.",
        Position            = 2
    )]
    [Alias('OutFile')]
    [string]$ofile
)

import-module activedirectory

if ($Input) { $data = [string]$Input }
else {
    if (Test-Path $ifile) { $data = [string](Get-Content $ifile) }
    else { throw [System.IO.FileNotFoundException] "$ifile not found." }
}

if ($data -ne $null) {
    import-module activedirectory

    $data = $data -split "[\n\s\t,;:]"
    $dom = (Get-ADForest).Domains

    if ($dom -ne $null) {
        $dc = $dom | foreach {(Get-ADDomain $_).InfrastructureMaster}

        $data = $data | ? { $_ } | sort -uniq | % { $_.Trim() }
        $prop = @(
            "SamAccountName",
            "UserPrincipalName",
            "CanonicalName",
            "Created",
            "Title",
            "Office",
            "Country",
            "Department",
            "Enabled",
            "LastBadPasswordAttempt",
            "LockedOut",
            "LogonCount",
            "MemberOf",
            "PasswordExpired",
            "PasswordLastSet",
            "PasswordNeverExpires",
            "PasswordNotRequired",
            "ProxyAddresses",
            "SID"
        )
        $propEx = @(
            "MemberOf",
            "ProxyAddresses"
        )
        if ($ofile) {
            Remove-Item $ofile 2>$null
        }

        function ArrayToHash ($a) {
            begin { $h = [ordered]@{} }
            process { $a | foreach { $h[$_] = $null } }
            end { return $h }
        }

        function Run-ADQuery {
            Param (
                [Parameter(Mandatory=$true)]
                [string]$iserver,
                [Parameter(Mandatory=$true)]
                [string]$istr
            )
            Begin { $o = $null }
            Process {
                try {
                    $o = Get-ADUser `
                        -Server $iserver `
                        -Filter "SamAccountName -eq '$istr' -or UserPrincipalName -eq '$istr' -or ProxyAddresses -like '*$istr*'" `
                        -Properties $prop `
                        | Select $prop
                } catch [ADException],[ADIdentityNotFoundException],[TimeoutException] { }
                foreach ($i in $o) {
                    foreach ($j in ($i.PSObject.Properties | Where-Object {$propEx -contains $_.Name})) {
                        $tmp = $i | Select -expand $j.Name
                        $i.PSObject.Properties.Remove($j.Name)
                        $i | Add-Member NoteProperty $j.Name ($tmp -join ",")
                    }
                }
            }
            End { $o }
        }

        function Query-ADUser {
            Param (
                [Parameter(Mandatory=$true)]
                [string]$istr
            )
            Begin { $o = $null }
            Process {
                foreach ($i in $dc) {
                    $o = Run-ADQuery $i $istr
                    if ($o -ne $null) {
                        break
                    }
                }
                if ($o -eq $null) {
                    $v = ArrayToHash $prop
                    $v['SamAccountName'] = $istr
                    $o = New-Object PSObject -Prop $v
                }
            }
            End { return $o }
        }

        function Main {
            Param (
                [Parameter(Mandatory=$true)]
                [string[]]$id,
                [string]$of
            )
            $data = @()
            foreach ($i in $id) {
                $data += Query-ADUser $i
            }
            if ($of) {
                $data | Export-CSV -Path $of -NoTypeInformation
            } else {
                $data | Format-List | Out-String
            }
            # Out-File -FilePath ofile -Encoding unicode -Append
            # Format-Table -Wrap, Format-List
        }

        Main $data $ofile
    } else {
        Write-Host "no domains found under the default forest."
    }
}
