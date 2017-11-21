<#
.SYNOPSIS
    Recursively obtains email addresses from the specified distribution lists
    from Active Directory (AD). Works with AD or Office 365 aliases.
.DESCRIPTION
    This script queries the infrastructure masters of available domains under
    the default AD forest to fetch information of the specified 'ProxyAddresses'
    property.
.EXAMPLE
    PS C:\> .\ad-dl.ps1 -InFile <ifile>
    Read file and print output to console.
.EXAMPLE
    PS C:\> .\ad-dl.ps1 -InFile <ifile> -OutFile <ofile>
    Read file and print output to file.
.EXAMPLE
    PS C:\> Write-Host "<dl-addr1>`n<dl-addr2>" | .\ad-dl.ps1
    Pipe data and print output to console.
.EXAMPLE
    PS C:\> Get-Content <ifile> | .\ad-dl.ps1
    Pipe data data read from a file and print output to console.
.EXAMPLE
    PS C:\> Get-Content <ifile> | .\ad-dl.ps1 -OutFile <ofile>
    Pipe data read from a file and print output to file.
.NOTES
    Author:    Diogo Fernandes
    URL:       https://github.com/diogo-fernan/
    Requires:  PowerShell v2.0
#>


Param (
    [Parameter(
        HelpMessage         = "Input 'ProxyAddresses' file (one per line).",
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
            Begin {
                $o = $null
                $str = "$($istr.split("@")[0])@"
            }
            Process {
                try {
                    $g = Get-ADGroup `
                        -Server $iserver `
                        -Filter "ProxyAddresses -like '*SMTP:$str*'" `
                        -Properties DisplayName,ProxyAddresses `
                        | Select DisplayName,ProxyAddresses
                } catch [TimeoutException] { }
                if ($g) {
                    $ga = ""
                    foreach ($i in $g.ProxyAddresses) {
                        if ($i -like "*SMTP:$str*") {
                            $ga = "$($ga)$($i.split(":")[1]),"
                        }
                    }
                    $o = New-Object PSObject -Property @{
                        DisplayName = $g.DisplayName
                        GroupAddresses = "$istr,$($ga.Substring(0,$ga.Length-1))"
                    }
                    $o.GroupAddresses = ($o.GroupAddresses -Split "," | Select -uniq) -join ","
                }
            }
            End { $o }
        }

        function Query-ADGroupMember {
            Param (
                [Parameter(Mandatory=$true)]
                [string]$iserver,
                [Parameter(Mandatory=$true)]
                [string]$istr
            )
            Begin { $o = @(); $oo = $null }
            Process {
                try {
                    $oo = Get-ADGroupMember -Server $iserver -Recursive $istr `
                          | Select -Unique
                    foreach ($i in $oo) {
                        try {
                            $o += Get-ADUser -Server $iserver $i -Properties EmailAddress `
                                  | Select-Object -Expand EmailAddress
                        } catch [Microsoft.ActiveDirectory.Management.ADReferralException] {
                            $flag = $True
                            foreach ($j in $($dc | Where-Object {$_ -ne $iserver})) {
                                try {
                                    $o += Get-ADUser -Server $j $i -Properties EmailAddress `
                                          | Select-Object -Expand EmailAddress
                                    $flag = $False
                                    break
                                } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { }
                            }
                            if ($flag) {
                                $o += $i.SamAccountName
                            }
                        }
                    }
                } catch [Microsoft.ActiveDirectory.Management.ADException],
                        [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException],
                        [System.TimeoutException] { }
            }
            End { $o | Sort -uniq }
        }

        function Query-ADGroup {
            Param (
                [Parameter(Mandatory=$true)]
                [string]$istr
            )
            Begin { $o = @() }
            Process {
                foreach ($i in $dc) {
                    $g = Run-ADQuery $i $istr
                    if ($g -ne $null) {
                        break
                    }
                }
                if ($g -eq $null) {
                    $g = New-Object PSObject -Property @{
                        EmailAddress = ""
                        GroupName = ""
                        GroupAddresses = $istr
                    }
                }

                if ($g.DisplayName -ne $null -and $g.DisplayName -ne "") {
                    $g.DisplayName = $g.DisplayName -Replace "^\*",""

                    foreach ($i in $dc) {
                        $p = Query-ADGroupMember $i $g.DisplayName
                        if ($p -ne $null) {
                            break
                        }
                    }
                    if ($p -eq $null) {
                        $o += New-Object PSObject -Property @{
                            EmailAddress = ""
                            GroupName = ""
                            GroupAddresses = $g.GroupAddresses
                        }
                    } else {
                        foreach ($i in $p) {
                            $o += New-Object PSObject -Property @{
                                EmailAddress = $i
                                GroupName = $g.DisplayName
                                GroupAddresses = $g.GroupAddresses
                            }
                        }
                    }
                } else {
                    $o += New-Object PSObject -Property @{
                        EmailAddress = ""
                        GroupName = ""
                        GroupAddresses = $g.GroupAddresses
                    }
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
                $data += Query-ADGroup $i
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
