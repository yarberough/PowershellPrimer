# A PowerShell Primer: From Basics to Automation

PowerShell has revolutionized Windows administration since its introduction. Unlike traditional command-line interfaces, PowerShell's object-oriented approach offers unprecedented control over Windows systems and Active Directory environments. In this guide, we'll explore PowerShell from the ground up, focusing on practical applications that will make your daily tasks more efficient.

## Getting Started with PowerShell

When you first open PowerShell, you'll see a familiar blue window with a command prompt. But don't let its simple appearance fool you – PowerShell is far more powerful than the traditional Command Prompt. 

To begin exploring, let's start with some basic commands, called cmdlets (pronounced "command-lets"). PowerShell follows a verb-noun pattern that makes learning new commands intuitive. Let's explore the most common verbs (Get, Set, New, Remove, Start, Stop) with practical examples:

### Get Commands - Retrieving Information
```powershell
Get-Location     # Shows current directory
Get-ChildItem    # Lists files and folders (like 'dir' or 'ls')
Get-Process      # Shows running processes
Get-Service      # Lists all services
Get-EventLog -LogName System -Newest 10    # Shows recent system events
Get-Command      # Lists all available commands
Get-Help Get-Process    # Shows help for a specific command
```

### Set Commands - Modifying Settings
```powershell
Set-Location C:\Users    # Changes directory
Set-Service -Name "Spooler" -Status Running    # Changes service status
Set-ExecutionPolicy RemoteSigned    # Modifies script execution policy
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
    -Name "HideFileExt" -Value 0    # Shows file extensions
```

### New Commands - Creating Items
```powershell
New-Item -Path "C:\Temp" -ItemType Directory    # Creates new folder
New-Item -Path "C:\Temp\test.txt" -ItemType File    # Creates new file
New-LocalUser -Name "JohnDoe" -Description "Regular User"    # Creates local user
New-PSDrive -Name "X" -PSProvider FileSystem -Root "\\server\share"    # Maps network drive
```

### Remove Commands - Deleting Items
```powershell
Remove-Item C:\Temp\test.txt    # Deletes a file
Remove-Item C:\Temp -Recurse    # Deletes folder and contents
Remove-LocalUser -Name "JohnDoe"    # Deletes local user
Remove-PSDrive -Name "X"    # Removes mapped drive
```

### Start and Stop Commands - Managing Processes
```powershell
Start-Process notepad    # Launches notepad
Start-Service "Spooler"    # Starts a service
Stop-Process -Name "notepad"    # Ends notepad process
Stop-Service "Spooler"    # Stops a service
```

### Test and Debug Commands
```powershell
Test-Connection google.com    # Pings a host
Test-Path C:\Windows    # Checks if path exists
Debug-Process -Name "notepad"    # Attaches debugger
```

These commands form the foundation of PowerShell scripting. The consistent verb-noun pattern makes it easier to guess command names – if you can Get something, you can usually Set it too. Many cmdlets also support common parameters like -WhatIf (to preview changes) and -Verbose (for detailed output):

```powershell
Remove-Item C:\Temp\test.txt -WhatIf    # Shows what would happen without actually deleting
New-Item C:\Temp\test.txt -Verbose    # Shows detailed information about what's happening
```

## Understanding Variables and Data Types

PowerShell uses variables to store information temporarily. Every variable starts with a $ symbol, and PowerShell's type system is both flexible and powerful. Let's explore the various data types and their practical applications:

### Basic Variable Declaration and Type Casting

```powershell
# Automatic type inference
$name = "John"           # String
$age = 30               # Integer
$salary = 75000.50      # Double
$isAdmin = $true        # Boolean

# Explicit type declaration
[string]$department = "IT"
[int]$employeeId = "1001"    # Automatically converts string to integer
[datetime]$startDate = "2024-01-15"    # Converts string to date

# Type conversion
$numberAsString = "42"
$actualNumber = [int]$numberAsString
$dateString = $startDate.ToString("yyyy-MM-dd")
```

### Working with Arrays and Collections

```powershell
# Simple arrays
$fruits = @("apple", "banana", "orange")
$numbers = 1..5    # Creates array of numbers 1 through 5

# Adding and removing elements
$fruits += "mango"    # Adds to array
$fruits = $fruits -ne "banana"    # Removes banana

# ArrayList for better performance with large collections
$tasks = [System.Collections.ArrayList]@()
$tasks.Add("Complete report")
$tasks.Add("Review code")
$tasks.Remove("Complete report")

# Filtering and transforming arrays
$longFruits = $fruits | Where-Object { $_.Length -gt 5 }
$upperFruits = $fruits | ForEach-Object { $_.ToUpper() }
```

### Hash Tables and Custom Objects

```powershell
# Hash table creation and manipulation
$settings = @{
    "Server" = "srv01"
    "Port" = 443
    "Enabled" = $true
}

# Adding and updating entries
$settings["Timeout"] = 30
$settings.Port = 8080

# Converting hash table to custom object
$serverConfig = [PSCustomObject]@{
    Hostname = "srv01"
    IP = "192.168.1.100"
    Services = @("Web", "Database")
}

# Accessing properties
$serverConfig.Hostname
$serverConfig.Services[0]
```

### Working with Objects and Properties

```powershell
# Creating and manipulating process objects
$process = Get-Process chrome
$process | Get-Member    # Lists all properties and methods

# Accessing multiple properties
$processInfo = $process | Select-Object Name, CPU, WorkingSet, StartTime

# Creating calculated properties
$diskInfo = Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID,
    @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB, 2)}},
    @{Name="FreeGB";Expression={[math]::Round($_.FreeSpace/1GB, 2)}}
```

### Variable Scoping and Inheritance

```powershell
# Global scope
$Global:sharedVariable = "Accessible everywhere"

# Script scope
$Script:configPath = "C:\Config"

# Function scope demonstration
function Test-Scope {
    $localVar = "Only visible in function"
    Write-Host $Global:sharedVariable    # Accessible
    Write-Host $Script:configPath        # Accessible
    Write-Host $localVar                 # Only accessible within function
}

# Module scope
$Private:secretKey = "Hidden from other modules"
```

### Advanced Variable Techniques

```powershell
# Using environment variables
$env:USERNAME
$env:COMPUTERNAME
$env:PATH += ";C:\CustomPath"

# Variable substitution in strings
$serverName = "PRD01"
$message = "Connected to $serverName"
$complex = "Server ${serverName} is $(Get-Date)"

# Splatting for cleaner command calls
$params = @{
    Path = "C:\Logs"
    Filter = "*.log"
    Recurse = $true
    File = $true
}
Get-ChildItem @params

# Working with secure strings
$securePassword = ConvertTo-SecureString "MyPassword" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential("username", $securePassword)
```

### Type Comparison and Validation

```powershell
# Type checking
$name -is [string]    # Returns true
$age -is [int]        # Returns true

# Null checking and default values
$nullable = $null
$result = $nullable ?? "Default Value"

# Variable validation
[ValidateRange(0, 100)][int]$percentage = 50
[ValidateSet("Dev", "Test", "Prod")][string]$environment = "Dev"
[ValidatePattern("[A-Z]{2}\d{4}")][string]$productCode = "AB1234"
```

These variable and data type features make PowerShell a robust scripting language for system administration and automation. Understanding how to work with different types of variables and their properties is crucial for writing efficient and maintainable scripts.

## Functions: Building Your Own Tools

Functions transform PowerShell from a simple scripting language into a powerful platform for creating custom administration tools. Understanding how to build these tools starts with identifying repetitive tasks and common patterns in your work.

### Identifying Opportunities for Tool Creation

Before building tools, consider these common scenarios that benefit from custom functions:

1. Tasks you perform repeatedly across different systems
2. Complex operations that combine multiple PowerShell commands
3. Standardized processes that other team members need to perform
4. Operations that require consistent error handling and logging
5. Tasks that need to be automated and scheduled

### Basic Function Structure

Let's start with a simple function that demonstrates proper parameter handling and documentation:

```powershell
function Get-DiskSpace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ComputerName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory=$false)]
        [int]$ThresholdGB = 10
    )
    
    begin {
        Write-Verbose "Checking disk space on $ComputerName"
    }
    
    process {
        try {
            Get-WmiObject Win32_LogicalDisk -ComputerName $ComputerName |
                Where-Object { $_.DriveType -eq 3 } |
                Select-Object DeviceID, 
                    @{Name="Size(GB)";Expression={[math]::Round($_.Size/1GB, 2)}},
                    @{Name="FreeSpace(GB)";Expression={[math]::Round($_.FreeSpace/1GB, 2)}}
        }
        catch {
            Write-Error "Failed to retrieve disk space from $ComputerName: $_"
        }
    }
    
    end {
        Write-Verbose "Completed disk space check"
    }
}
```

### Advanced Tool Examples

#### System Health Check Tool

```powershell
function Test-SystemHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$ComputerName,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "C:\Reports\HealthCheck.csv"
    )
    
    begin {
        $results = @()
        $date = Get-Date
    }
    
    process {
        foreach ($computer in $ComputerName) {
            $health = [PSCustomObject]@{
                ComputerName = $computer
                DateTime = $date
                CPUUsage = $null
                MemoryAvailable = $null
                DiskSpace = $null
                LastBootTime = $null
                Status = "Unknown"
            }
            
            try {
                $cpu = Get-WmiObject Win32_Processor -ComputerName $computer |
                    Measure-Object LoadPercentage -Average
                $health.CPUUsage = $cpu.Average
                
                $memory = Get-WmiObject Win32_OperatingSystem -ComputerName $computer
                $health.MemoryAvailable = [math]::Round(($memory.FreePhysicalMemory / 1MB), 2)
                
                $disk = Get-WmiObject Win32_LogicalDisk -ComputerName $computer -Filter "DeviceID='C:'"
                $health.DiskSpace = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
                
                $os = Get-WmiObject Win32_OperatingSystem -ComputerName $computer
                $health.LastBootTime = $os.ConvertToDateTime($os.LastBootUpTime)
                
                $health.Status = "Healthy"
            }
            catch {
                $health.Status = "Error: $_"
            }
            
            $results += $health
        }
    }
    
    end {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-Output $results
    }
}
```

#### User Account Management Tool

```powershell
function New-StandardUser {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [string]$FullName,
        
        [Parameter(Mandatory=$true)]
        [string]$Department,
        
        [Parameter(Mandatory=$true)]
        [string]$Manager,
        
        [Parameter(Mandatory=$false)]
        [string]$Office = "Main Office"
    )
    
    begin {
        Import-Module ActiveDirectory
        $defaultGroups = @("Domain Users", "VPN Users", "Print Users")
        $ou = "OU=StandardUsers,DC=company,DC=local"
    }
    
    process {
        try {
            # Generate email address
            $email = "$Username@company.com"
            
            # Create initial password
            $securePassword = ConvertTo-SecureString "Welcome1!" -AsPlainText -Force
            
            if ($PSCmdlet.ShouldProcess($Username, "Create new user account")) {
                # Create user account
                $newUser = New-ADUser -Name $FullName `
                    -SamAccountName $Username `
                    -UserPrincipalName $email `
                    -GivenName $FullName.Split()[0] `
                    -Surname $FullName.Split()[-1] `
                    -EmailAddress $email `
                    -Department $Department `
                    -Manager $Manager `
                    -Office $Office `
                    -AccountPassword $securePassword `
                    -Enabled $true `
                    -ChangePasswordAtLogon $true `
                    -Path $ou `
                    -PassThru
                
                # Add to standard groups
                foreach ($group in $defaultGroups) {
                    Add-ADGroupMember -Identity $group -Members $newUser
                }
                
                Write-Output "Created user account for $FullName ($Username)"
            }
        }
        catch {
            Write-Error "Failed to create user account: $_"
        }
    }
}
```

#### Log Analysis Tool

```powershell
function Search-ApplicationLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$LogPath = "C:\Logs\Application.log",
        
        [Parameter(Mandatory=$false)]
        [datetime]$StartTime = (Get-Date).AddHours(-24),
        
        [Parameter(Mandatory=$false)]
        [string[]]$ErrorTypes = @("Error", "Critical", "Warning"),
        
        [Parameter(Mandatory=$false)]
        [switch]$ExportResults
    )
    
    begin {
        $patterns = @{
            TimeStamp = '^\[(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})]'
            Level = '\[(ERROR|WARNING|INFO|CRITICAL)\]'
            Message = '(?<=]:\s).+'
        }
        
        $results = @()
    }
    
    process {
        Get-Content $LogPath | ForEach-Object {
            if ($_ -match $patterns.TimeStamp) {
                $timestamp = [datetime]::ParseExact($matches[1], 
                    "yyyy-MM-dd HH:mm:ss", 
                    [System.Globalization.CultureInfo]::InvariantCulture)
                
                if ($timestamp -ge $StartTime) {
                    $level = if ($_ -match $patterns.Level) { $matches[1] } else { "UNKNOWN" }
                    
                    if ($ErrorTypes -contains $level) {
                        $message = if ($_ -match $patterns.Message) { $matches[0] } else { $_ }
                        
                        $results += [PSCustomObject]@{
                            TimeStamp = $timestamp
                            Level = $level
                            Message = $message
                        }
                    }
                }
            }
        }
    }
    
    end {
        if ($ExportResults) {
            $exportPath = "C:\Reports\LogAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $results | Export-Csv -Path $exportPath -NoTypeInformation
            Write-Output "Results exported to $exportPath"
        }
        
        return $results
    }
}
```

### Guidelines for Building Effective Tools

1. Always include proper error handling with try/catch blocks
2. Use Write-Verbose for debugging information
3. Implement parameter validation where appropriate
4. Include help documentation for your functions
5. Follow PowerShell naming conventions (Verb-Noun)
6. Make functions reusable by parameterizing values
7. Use PowerShell's built-in support for things like -WhatIf and -Verbose

### Making Your Tools Production-Ready

```powershell
# Example of a production-ready function header
function Verb-Noun {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true,
            HelpMessage="Enter required parameter"
        )]
        [ValidateNotNullOrEmpty()]
        [string]$RequiredParam,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Option1", "Option2", "Option3")]
        [string]$Choice = "Option1"
    )
    
    begin {
        # Initialize resources
        $StartTime = Get-Date
        Write-Verbose "Starting execution at $StartTime"
    }
    
    process {
        # Main logic here
    }
    
    end {
        # Cleanup
        $EndTime = Get-Date
        $Duration = $EndTime - $StartTime
        Write-Verbose "Execution completed. Duration: $Duration"
    }
}
```

These examples demonstrate how to build robust, reusable tools that follow PowerShell best practices. When creating your own tools, start by identifying common tasks in your environment that could benefit from automation, then build functions that make those tasks easier and more consistent.

## Active Directory Management

PowerShell excels at Active Directory management tasks, offering powerful tools for user administration, security auditing, and system maintenance. Here's a comprehensive look at common AD management scenarios and their implementations.

### Basic User Management

```powershell
# Import the AD module
Import-Module ActiveDirectory

# Find inactive user accounts
function Get-InactiveADUsers {
    param(
        [int]$DaysInactive = 90,
        [string]$SearchBase = "OU=Users,DC=company,DC=com"
    )
    
    $inactiveDate = (Get-Date).AddDays(-$DaysInactive)
    Get-ADUser -Filter {LastLogonDate -lt $inactiveDate} `
        -SearchBase $SearchBase `
        -Properties LastLogonDate, Manager, Department |
        Select-Object Name, SamAccountName, LastLogonDate, Manager, Department
}

# Create new user with standard configurations
function New-StandardADUser {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FirstName,
        
        [Parameter(Mandatory=$true)]
        [string]$LastName,
        
        [Parameter(Mandatory=$true)]
        [string]$Department,
        
        [Parameter(Mandatory=$true)]
        [string]$Manager
    )
    
    $username = ($FirstName.Substring(0,1) + $LastName).ToLower()
    $upn = "$username@company.com"
    
    New-ADUser `
        -Name "$FirstName $LastName" `
        -GivenName $FirstName `
        -Surname $LastName `
        -SamAccountName $username `
        -UserPrincipalName $upn `
        -Department $Department `
        -Manager $Manager `
        -Path "OU=NewUsers,DC=company,DC=com" `
        -AccountPassword (ConvertTo-SecureString "Welcome1!" -AsPlainText -Force) `
        -Enabled $true `
        -ChangePasswordAtLogon $true
        
    # Add to standard groups
    Add-ADGroupMember -Identity "Domain Users" -Members $username
    Add-ADGroupMember -Identity "VPN Users" -Members $username
}
```

### Group Management and Access Control

```powershell
# Audit group memberships
function Get-GroupMembershipReport {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )
    
    $members = Get-ADGroupMember -Identity $GroupName -Recursive |
        Where-Object {$_.objectClass -eq "user"} |
        ForEach-Object {
            $user = Get-ADUser $_ -Properties Manager, Department, LastLogonDate
            [PSCustomObject]@{
                Username = $_.SamAccountName
                Name = $user.Name
                Department = $user.Department
                Manager = (Get-ADUser $user.Manager).Name
                LastLogon = $user.LastLogonDate
            }
        }
    
    return $members
}

# Clean up empty groups
function Remove-EmptyADGroups {
    param(
        [string]$SearchBase = "OU=Groups,DC=company,DC=com"
    )
    
    Get-ADGroup -Filter * -SearchBase $SearchBase |
        ForEach-Object {
            $group = $_
            $members = Get-ADGroupMember -Identity $group
            if ($members.Count -eq 0) {
                Write-Output "Removing empty group: $($group.Name)"
                Remove-ADGroup -Identity $group -Confirm:$false
            }
        }
}
```

### Security Auditing and Compliance

```powershell
# Audit privileged group memberships
function Get-PrivilegedGroupAudit {
    $privilegedGroups = @(
        "Enterprise Admins",
        "Domain Admins",
        "Schema Admins",
        "Account Operators",
        "Backup Operators"
    )
    
    $results = foreach ($groupName in $privilegedGroups) {
        Get-ADGroupMember -Identity $groupName |
            ForEach-Object {
                $user = Get-ADUser $_ -Properties LastLogonDate, PasswordLastSet, Enabled
                [PSCustomObject]@{
                    GroupName = $groupName
                    Username = $_.SamAccountName
                    Enabled = $user.Enabled
                    LastLogon = $user.LastLogonDate
                    PasswordLastSet = $user.PasswordLastSet
                }
            }
    }
    
    return $results
}

# Find users with non-expiring passwords
function Get-NonExpiringPasswords {
    Get-ADUser -Filter {PasswordNeverExpires -eq $true} `
        -Properties PasswordNeverExpires, PasswordLastSet, LastLogonDate |
        Select-Object Name, SamAccountName, PasswordLastSet, LastLogonDate
}

# Check for weak password policies
function Test-PasswordPolicy {
    $domain = Get-ADDomain
    $policy = Get-ADDefaultDomainPasswordPolicy
    
    [PSCustomObject]@{
        Domain = $domain.DNSRoot
        MinPasswordLength = $policy.MinPasswordLength
        PasswordHistoryCount = $policy.PasswordHistoryCount
        MaxPasswordAge = $policy.MaxPasswordAge
        MinPasswordAge = $policy.MinPasswordAge
        ComplexityEnabled = $policy.ComplexityEnabled
        LockoutThreshold = $policy.LockoutThreshold
        LockoutDuration = $policy.LockoutDuration
        ReversibleEncryption = $policy.ReversibleEncryptionEnabled
    }
}
```

### Compliance and Security Functions

```powershell
# Audit file system permissions for sensitive shares
function Get-SharePermissionAudit {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Shares
    )
    
    foreach ($share in $Shares) {
        $acl = Get-Acl $share
        foreach ($access in $acl.Access) {
            [PSCustomObject]@{
                Share = $share
                IdentityReference = $access.IdentityReference
                AccessControlType = $access.AccessControlType
                FileSystemRights = $access.FileSystemRights
                IsInherited = $access.IsInherited
            }
        }
    }
}

# Find and disable dormant admin accounts
function Disable-DormantAdminAccounts {
    param(
        [int]$DaysInactive = 60
    )
    
    $inactiveDate = (Get-Date).AddDays(-$DaysInactive)
    $adminGroups = "Domain Admins", "Enterprise Admins"
    
    foreach ($group in $adminGroups) {
        Get-ADGroupMember -Identity $group |
            Get-ADUser -Properties LastLogonDate |
            Where-Object {$_.LastLogonDate -lt $inactiveDate -and $_.Enabled} |
            ForEach-Object {
                Set-ADUser $_ -Enabled $false
                Write-Output "Disabled dormant admin account: $($_.SamAccountName)"
            }
    }
}

# Monitor for sensitive group changes
function Watch-SensitiveGroupChanges {
    param(
        [int]$Hours = 24
    )
    
    $startDate = (Get-Date).AddHours(-$Hours)
    $sensitiveGroups = "Domain Admins", "Enterprise Admins", "Schema Admins"
    
    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        StartTime = $startDate
        ID = 4728, 4729, 4732, 4733  # Group membership changes
    } | Where-Object {
        $_.Properties[2].Value -in $sensitiveGroups
    } | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Event = switch ($_.ID) {
                4728 { "Member Added" }
                4729 { "Member Removed" }
                4732 { "Member Added" }
                4733 { "Member Removed" }
            }
            Group = $_.Properties[2].Value
            Account = $_.Properties[1].Value
            ModifiedBy = $_.Properties[6].Value
        }
    }
}
```

### Bulk Operations and Maintenance

```powershell
# Bulk update user properties from CSV
function Update-UserPropertiesFromCSV {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CsvPath
    )
    
    Import-Csv $CsvPath | ForEach-Object {
        try {
            Set-ADUser -Identity $_.SamAccountName `
                -Office $_.Office `
                -Department $_.Department `
                -Title $_.Title `
                -Company $_.Company
            Write-Output "Updated user: $($_.SamAccountName)"
        }
        catch {
            Write-Error "Failed to update $($_.SamAccountName): $_"
        }
    }
}

# Generate AD health report
function Get-ADHealthReport {
    [PSCustomObject]@{
        ForestMode = (Get-ADForest).ForestMode
        DomainMode = (Get-ADDomain).DomainMode
        DCCount = (Get-ADDomainController -Filter *).Count
        DisabledAccounts = (Get-ADUser -Filter {Enabled -eq $false}).Count
        ExpiredAccounts = (Get-ADUser -Filter {AccountExpirationDate -lt (Get-Date)} `
            -Properties AccountExpirationDate).Count
        LockedAccounts = (Search-ADAccount -LockedOut).Count
        ExpiredPasswords = (Search-ADAccount -PasswordExpired).Count
        RODCs = (Get-ADDomainController -Filter {IsReadOnly -eq $true}).Count
    }
}
```

These functions provide a robust foundation for managing Active Directory environments securely and efficiently. Remember to always test these functions in a non-production environment first and ensure you have proper backup procedures in place before making significant changes to your Active Directory infrastructure.

## Automation Tips and Tricks

Here are some powerful techniques to enhance your PowerShell automation:

### 1. Error Handling
```powershell
try {
    Stop-Service "ImportantService"
} catch {
    Write-Error "Failed to stop service: $_"
    Send-MailMessage -To "admin@company.com" -Subject "Service Error"
}
```

### 2. Remote Management
```powershell
# Create a remote session
$session = New-PSSession -ComputerName "Server01"

# Run commands remotely
Invoke-Command -Session $session -ScriptBlock {
    Get-Service | Where-Object {$_.Status -eq "Stopped"}
}
```

### 3. Background Jobs
```powershell
# Start a background job
Start-Job -ScriptBlock {
    Get-ADUser -Filter * -Properties LastLogonDate |
    Export-Csv "C:\Reports\UserReport.csv"
}

# Check job status
Get-Job

# Get results
Receive-Job -Id 1
```

## Real-World Automation Example

Here's a practical script that monitors disk space and emails alerts:

```powershell
function Monitor-DiskSpace {
    param(
        [int]$threshold = 10,    # Alert when free space below 10%
        [string]$emailTo = "admin@company.com"
    )
    
    $disks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType = 3"
    $alerts = @()
    
    foreach ($disk in $disks) {
        $freeSpacePercent = ($disk.FreeSpace / $disk.Size) * 100
        
        if ($freeSpacePercent -lt $threshold) {
            $alerts += "Drive $($disk.DeviceID) has $([math]::Round($freeSpacePercent,2))% free space"
        }
    }
    
    if ($alerts) {
        $body = $alerts | Out-String
        Send-MailMessage -To $emailTo -Subject "Disk Space Alert" -Body $body
    }
}

# Schedule this to run daily:
# Create-Schedule -Action (New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-File "C:\Scripts\Monitor-DiskSpace.ps1"')
```

## Best Practices

1. Always use meaningful variable names that reflect their purpose
2. Comment your code, especially complex operations
3. Use proper error handling with try/catch blocks
4. Test scripts in a safe environment before running in production
5. Use the -WhatIf parameter when available to preview changes
6. Store sensitive information securely using SecureString or encrypted files

## Conclusion

PowerShell's versatility makes it an indispensable tool for Windows administration. Start with these basics, practice regularly, and you'll soon discover countless ways to automate your daily tasks. Remember, the best way to learn is by doing – start with simple scripts and gradually tackle more complex challenges.

For further learning, explore PowerShell's built-in help system using Get-Help, and don't forget about the extensive online community ready to assist with your PowerShell journey.
