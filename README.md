# PowerShell AD
This repository is for a collection of PowerShell programs that **automate the collection of security data from Active Directory (AD) and Office 365 resources**  that is useful for enterprise incident response. In AD, the data collection pertains to selected properties of **user**, **computer** and **group** objects, each of them realized into individual programs. The data is retrieved from queries directed at the infrastructure masters (Global Catalog (GC) servers) of all available domains under the default AD forest of the system, which are obtained with `(Get-ADForest).Domains`. In Office 365, the data is retrieved from [https://outlook.office365.com/powershell-liveid/](https://outlook.office365.com/powershell-liveid/).

The main usefulness of these programs lies in the automated gathering of interesting properties readily available in AD and in Office 365 for an arbitrary number of input values. This can help in simple associations between unique identifiers and respective accounts or even in relevant security properties such as timestamps that can help in the analysis of incidents or investigations.

These PowerShell programs were developed for enterprise incident response purposes and are therefore suitable for security practitioners alike.

# `ad-computer.ps1`
The `ad-computer.ps1` program searches AD computer objects with the specified hostnames under the `DNSHostName` property or with the specified IPv4 addresses under the `IPv4Address` property. The retrieved properties include system information, logon and password data.

# `ad-dl.ps1`
The `ad-dl.ps1` program searches AD group objects with the specified email address under the `ProxyAddresses` property. It then recursively obtains all user email addresses under a certain group name from the respective forest domain (group members can be in different domains). This program is particularly useful to retrieve all user accounts that are under specified distribution lists (*e.g.*, used in phishing campaigns).

# `ad-user.ps1`
The `ad-user.ps1` program searches AD user objects with the specified email addresses under the `EmailAddress` or `ProxyAddresses` properties or with the specified unique identifiers under the `SamAccountName` property. Email address aliases are supported due to the inclusion of `ProxyAddresses` in the search. A number of security properties are retrieved for each object found, namely logon- and password-related.

# `office-365-email.ps1`
The `office-365-email.ps1` program searches Office 365 objects with the specified email addresses under the `Identity` property, provided that PowerShell-based access to Office 365 is configured correctly. A number of commands are run for each input, namely `Get-Mailbox`, `Get-InboxRule`, `Get-MobileDeviceStatistics` and `Get-Messagetrace`, which are pulled down upon successful session establishment. The latter command creates a separate comma-separated file with the messages log for the last 30 days.

# Dependencies and Usage
All programs targeting AD require only the `import-module activedirectory` dependecy for importing AD commands.

These PowerShell programs were developed with the same approach, accepting input data from files or from the pipeline separated by any of the characters `[\n\s\t,;:]` and either printing data to the standard output or to comma-separated value files. This can be summarized with the following usage syntax:
```
PS C:\> [(Get-Content ifile | echo "data") |] ad-*.ps1 [-InFile ifile] [-OutFile ofile]
```
