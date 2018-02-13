<#
.SYNOPSIS
    Gets security information of specified computers from Active Directory (AD).
.DESCRIPTION
    This script queries the infrastructure masters of available domains under
    the default AD forest to fetch information of the specified 'DNSHostName' or
    'IPv4Address' properties.
.EXAMPLE
    PS C:\> .\ad-computer.ps1 -InFile <ifile>
    Read file and print output to console.
.EXAMPLE
    PS C:\> .\ad-computer.ps1 -InFile <ifile> -OutFile <ofile>
    Read file and print output to file.
.EXAMPLE
    PS C:\> Write-Host "<hostname1>`n<ip-addr2>" | .\ad-computer.ps1
    Pipe data and print output to console.
.EXAMPLE
    PS C:\> Get-Content <ifile> | .\ad-computer.ps1
    Pipe data data read from a file and print output to console.
.EXAMPLE
    PS C:\> Get-Content <ifile> | .\ad-computer.ps1 -OutFile <ofile>
    Pipe data read from a file and print output to file.
.NOTES
    Author:    Diogo Fernandes
    URL:       https://github.com/diogo-fernan/
    Requires:  PowerShell v2.0
#>


Param (
    [Parameter(
        HelpMessage         = "Input 'DNSHostName' and/or 'IPv4Address' file.",
        Mandatory           = $true,
        Position            = 1,
        ValueFromPipeline   = $true
    )]
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
            "Name",
            "IPv4Address",
            "CanonicalName",
            "OperatingSystem",
            "PasswordExpired",
            "PasswordLastSet",
            "LastBadPasswordAttempt",
            "LastLogonDate",
            "SID",
            "MemberOf"
        )
        $propEx = @(
            "MemberOf"
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
                $ft = "Name -eq '$istr' -or DNSHostName -like '$istr*'"
                if ($istr -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
                    $ft += " -or IPv4Address -eq '$istr'"
                }
                try {
                    $o = Get-ADComputer `
                        -Server $iserver `
                        -Filter $ft `
                        -Properties $prop `
                        | Select $prop
                } catch [Microsoft.ActiveDirectory.Management.ADException]
                        [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
                        [TimeoutException] { }
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

        function Query-ADComputer {
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
                    $v['Name'] = $istr
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
                $data += Query-ADComputer $i
            }
            if ($of) {
                $data | Export-CSV -Path $of -NoTypeInformation
            } else {
                $data | Format-List | Out-String
            }
        }

        Main $data $ofile
    } else {
        Write-Host "no domains found under the default forest."
    }
}
