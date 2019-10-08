# Get-UserSession
## SYNOPSIS
PowerShell wrapper for "query user" command which also offers resolving the Display Name of users and gathering of user session process information
## DESCRIPTION
PowerShell wrapper for "query user" command which also offers resolving the Display Name of users and gathering of user session process information
# PARAMETERS

## **-ComputerName**

> ![Foo](https://img.shields.io/badge/Type-String[]-Blue?) ![Foo](https://img.shields.io/badge/Mandatory-FALSE-Green?) \
The computer name(s) for which you want to gather user session information

  ## **-ResolveDisplayName**

> ![Foo](https://img.shields.io/badge/Type-SwitchParameter-Blue?) ![Foo](https://img.shields.io/badge/Mandatory-FALSE-Green?) ![Foo](https://img.shields.io/badge/DefaultValue-False-Blue?color=5547a8)\
Used to determine whether or not to attempt resolving the Display Name for each user

  ## **-IncludeProcessInfo**

> ![Foo](https://img.shields.io/badge/Type-SwitchParameter-Blue?) ![Foo](https://img.shields.io/badge/Mandatory-FALSE-Green?) ![Foo](https://img.shields.io/badge/DefaultValue-False-Blue?color=5547a8)\
Used to determine whether or not to gather process information for each user session

  ## **-Credential**

> ![Foo](https://img.shields.io/badge/Type-PSCredential-Blue?) ![Foo](https://img.shields.io/badge/Mandatory-FALSE-Green?) \
Used to pass into the Invoke-Command function for gathering process information. This is exposed so that you have flexibility for connectivity.

  ## **-Port**

> ![Foo](https://img.shields.io/badge/Type-Int32-Blue?) ![Foo](https://img.shields.io/badge/Mandatory-FALSE-Green?) ![Foo](https://img.shields.io/badge/DefaultValue--1-Blue?color=5547a8)\
Used to pass into the Invoke-Command function for gathering process information. This is exposed so that you have flexibility for connectivity.

  ## **-UseSSL**

> ![Foo](https://img.shields.io/badge/Type-SwitchParameter-Blue?) ![Foo](https://img.shields.io/badge/Mandatory-FALSE-Green?) ![Foo](https://img.shields.io/badge/DefaultValue-False-Blue?color=5547a8)\
Used to pass into the Invoke-Command function for gathering process information. This is exposed so that you have flexibility for connectivity.

  ## **-Authentication**

> ![Foo](https://img.shields.io/badge/Type-AuthenticationMechanism-Blue?) ![Foo](https://img.shields.io/badge/Mandatory-FALSE-Green?) \
Used to pass into the Invoke-Command function for gathering process information. This is exposed so that you have flexibility for connectivity.

  ## **-SessionOption**

> ![Foo](https://img.shields.io/badge/Type-PSSessionOption-Blue?) ![Foo](https://img.shields.io/badge/Mandatory-FALSE-Green?) \
Used to pass into the Invoke-Command function for gathering process information. This is exposed so that you have flexibility for connectivity.

  ## **-BatchSize**

> ![Foo](https://img.shields.io/badge/Type-Int32-Blue?) ![Foo](https://img.shields.io/badge/Mandatory-FALSE-Green?) ![Foo](https://img.shields.io/badge/DefaultValue-[int]$env:NUMBER_OF_PROCESSORS + 1-Blue?color=5547a8)\
Used for the runspace pooling that is utilized for more efficient parallel processing. This is exposed so that you have flexibility for runspace behavior.  Default value is calculated from: [int]$env:NUMBER_OF_PROCESSORS + 1

  ## **-ApartmentState**

> ![Foo](https://img.shields.io/badge/Type-String-Blue?) ![Foo](https://img.shields.io/badge/Mandatory-FALSE-Green?) ![Foo](https://img.shields.io/badge/DefaultValue-STA-Blue?color=5547a8)\
Used for the runspace pooling that is utilized for more efficient parallel processing. This is exposed so that you have flexibility for runspace behavior.  Default value is 'STA'

  ## **-ShowProgress**

> ![Foo](https://img.shields.io/badge/Type-SwitchParameter-Blue?) ![Foo](https://img.shields.io/badge/Mandatory-FALSE-Green?) ![Foo](https://img.shields.io/badge/DefaultValue-False-Blue?color=5547a8)\
Used to determine whether or not to display a progress bar as the runspace pool is processed

 
#### EXAMPLE 1
```powershell
PS C:\>Get-UserSession

Gets the current user sessions from the local machine
```
 #### EXAMPLE 2
```powershell
PS C:\>Get-UserSession -ComputerName (Get-ADComputer -Filter *).DnsHostname -ShowProgress -Verbose | Format-Table -Autosize

Gets the user sessions from all Active Directory computers while showing a progress bar and displaying verbose information
```
 #### EXAMPLE 3
```powershell
PS C:\>'ComputerA', 'ComputerB' | Get-UserSession -ResolveDisplayName | Format-Table -Autosize

Gets the user sessions from ComputerA and ComputerB and resolves the Display Name of the users for the output
```
