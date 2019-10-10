Function Get-UserSession
{
    <#

        .SYNOPSIS
            PowerShell wrapper for "query user" command which also offers resolving the Display Name of users and gathering of user session process information
        .DESCRIPTION
            PowerShell wrapper for "query user" command which also offers resolving the Display Name of users and gathering of user session process information

        .PARAMETER ComputerName
            The computer name(s) for which you want to gather user session information
        
        .PARAMETER ResolveDisplayName
            Used to determine whether or not to attempt resolving the Display Name for each user
        
        .PARAMETER IncludeProcessInfo
            Used to determine whether or not to gather process information for each user session
        .PARAMETER Credential
            Used to pass into the Invoke-Command function for gathering process information. This is exposed so that you have flexibility for connectivity.
        .PARAMETER Port
            Used to pass into the Invoke-Command function for gathering process information. This is exposed so that you have flexibility for connectivity.
        .PARAMETER UseSSL
            Used to pass into the Invoke-Command function for gathering process information. This is exposed so that you have flexibility for connectivity.
        .PARAMETER Authentication
            Used to pass into the Invoke-Command function for gathering process information. This is exposed so that you have flexibility for connectivity.
        .PARAMETER SessionOption
            Used to pass into the Invoke-Command function for gathering process information. This is exposed so that you have flexibility for connectivity.
        
        .PARAMETER BatchSize
            Used for the runspace pooling that is utilized for more efficient parallel processing. This is exposed so that you have flexibility for runspace behavior.

            Default value is calculated from:
            [int]$env:NUMBER_OF_PROCESSORS + 1
        .PARAMETER ApartmentState
            Used for the runspace pooling that is utilized for more efficient parallel processing. This is exposed so that you have flexibility for runspace behavior.

            Default value is 'STA'

        .PARAMETER ShowProgress
            Used to determine whether or not to display a progress bar as the runspace pool is processed

        .EXAMPLE
            Get-UserSession

            Gets the current user sessions from the local machine
        .EXAMPLE
            Get-UserSession -ComputerName (Get-ADComputer -Filter *).DnsHostname -ShowProgress -Verbose | Format-Table -Autosize

            Gets the user sessions from all Active Directory computers while showing a progress bar and displaying verbose information
        .EXAMPLE
            'ComputerA', 'ComputerB' | Get-UserSession -ResolveDisplayName | Format-Table -Autosize

            Gets the user sessions from ComputerA and ComputerB and resolves the Display Name of the users for the output

    #>
    
    [cmdletbinding()]
    Param(
        [Parameter(
            ValueFromPipeline = $true
            , ValueFromPipelineByPropertyName = $true
        )]
        [string[]]$ComputerName
        ,
        [switch]$ResolveDisplayName
        ,
        [Parameter(ParameterSetName = 'ProcessInfo')]
        [switch]$IncludeProcessInfo
        ,
        [Parameter(ParameterSetName = 'ProcessInfo')]
        [pscredential]$Credential
        ,
        [Parameter(ParameterSetName = 'ProcessInfo')]
        [int]$Port = -1
        ,
        [Parameter(ParameterSetName = 'ProcessInfo')]
        [switch]$UseSSL
        ,
        [Parameter(ParameterSetName = 'ProcessInfo')]
        [System.Management.Automation.Runspaces.AuthenticationMechanism]$Authentication
        ,
        [Parameter(ParameterSetName = 'ProcessInfo')]
        [System.Management.Automation.Remoting.PSSessionOption]$SessionOption
        ,
        [ValidateScript({
            If ($_ -lt 1) { Throw 'Please specify a value of 1 or greater.' }
            Else { $true }
        })]
        [int]$BatchSize = [int]$env:NUMBER_OF_PROCESSORS + 1
        ,
        [ValidateSet(
            'STA'
            ,'MTA'
        )]
        [string]$ApartmentState = 'STA'
        ,
        [switch]$ShowProgress
    )

    Begin
    {
        $Verbose = ($PSBoundParameters.Verbose -eq $true)
        Write-Verbose -Message "----------" -Verbose:$Verbose
        Write-Verbose -Message "Function '$($MyInvocation.MyCommand)' was called" -Verbose:$Verbose

        # Initialize the runspace pool
        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $BatchSize)
        $Pool.ApartmentState = $ApartmentState
        $Pool.Open()

        $GetProcessInfo = $IncludeProcessInfo.IsPresent

        # Determine if the current console is elevated, which is needed to get process information tied to users
        If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
        {
            If ($GetProcessInfo)
            {
                Write-Warning -Message "The 'IncludeProcessInfo' parameter requires requires elevated user rights. Try running the command again in a session that has been opened with elevated user rights (that is, Run as Administrator)."
                $GetProcessInfo = $false
            }
        }

        If ($GetProcessInfo)
        {
            $ProcessInfoScriptBlock = {
                            
                $CpuCores = (Get-WmiObject -Class Win32_Processor).NumberOfLogicalProcessors
                $ProcessPerformanceCounters = Get-WmiObject -Class Win32_PerfFormattedData_PerfProc_Process

                # Logic used to calculate CPU usage value
                $CpuProperty = @{
                    Name       = 'Cpu'
                    Expression = {
                        $Ids = $_.Group.Id
                        [System.Math]::Round(
                            ($ProcessPerformanceCounters |
                                Where-Object -FilterScript { $Ids -contains $_.IDProcess } |
                                Select-Object -Property @{
                                    Name = 'PercentProcessorTime'
                                    Expression = {$_.PercentProcessorTime / $CpuCores}
                                } |
                                Measure-Object -Property PercentProcessorTime -Sum).Sum
                            , 1
                        )
                    }
                }

                # Logic used to calculate memory usage value
                $MemoryProperty = @{
                    Name       = 'Memory'
                    Expression = {
                        $Ids = $_.Group.Id
                        [System.Math]::Round(
                            ($ProcessPerformanceCounters |
                                Where-Object -FilterScript { $Ids -contains $_.IDProcess } |
                                Measure-Object -Property workingSetPrivate -Sum).Sum / 1MB
                            , 1
                        )
                    }
                }

                # Get process information and group by UserName to return the UserName, CPU usage, memory usage, and the actual processes
                Get-Process -IncludeUserName |
                    Group-Object -Property UserName |
                    Select-Object -Property @(
                        @{
                            Name = 'Username'
                            Expression = { $_.Name.Split('\')[-1] }
                        }
                        , $CpuProperty
                        , $MemoryProperty
                        , @{
                            Name = 'Processes'
                            Expression = { $_.Group }
                        }
                )

            } # $ProcessInfoScriptBlock

        } # If ($GetProcessInfo)


        $UserSessionScriptBlock = {
            Param(
                [string]$ComputerName
                ,
                [bool]$ResolveDisplayName
                ,
                [object[]]$UserProcesses
                ,
                [bool]$Verbose
            )
            
            If ([string]::IsNullOrEmpty($ComputerName))
            {
                $ComputerName = 'localhost'
            }
            
            # Check for connectivity over TCP port 135 (WMI) with a 1 second timeout
            $TestPort = 135
            $TimeoutMilliseconds = 1000
            $TCPClient = [System.Net.Sockets.TcpClient]::new()
            $Proceed = $TCPClient.BeginConnect($ComputerName, $TestPort, $null, $null).AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)
            $TCPClient.Close()

            If ($Proceed)
            {
                
                Write-Verbose -Message "Running query.exe against $($ComputerName)." -Verbose:$Verbose
                $Users = query user /server:$ComputerName 2>&1

                If ($Users -match "No User exists")
                {
                    Write-Warning -Message "There were no users found on $($ComputerName)." -Verbose:$Verbose
                }

                ElseIf ($Users -match "Error")
                {
                    Write-Error -Message "There was an error running query against $($ComputerName) : $Users"
                }

                ElseIf ($Users -eq $null -and $ErrorActionPreference -eq 'SilentlyContinue')
                {
                    # Handdle null output called by -ErrorAction.
                    Write-Verbose -Message "Error action has supressed output from query.exe. Results were null." -Verbose:$Verbose
                }

                Else
                {
                    Write-Verbose -Message "Users found on $($ComputerName). Converting output from text." -Verbose:$Verbose

                    # Conversion logic. Handles the fact that the sessionname column may be populated or not.
                    $Users = $Users | ForEach-Object {
                        (($_.trim() -replace ">" -replace "(?m)^([A-Za-z0-9-._]{3,20})\s+(\d+\s+\w+)", '$1  none  $2' -replace "\s{2,}", "," -replace "none", $null))
                    } | ConvertFrom-Csv


                    $CountString = "$($Users.Count) user$('s' * [int]($Users.Count -ne 1))"
                    Write-Verbose -Message "Generating output for $($CountString) connected to $($ComputerName)." -Verbose:$Verbose

                    
                    # Output objects.
                    foreach ($User in $Users)
                    {
                        
                        # Convert the LOGON TIME value to a formatted date/time string
                        If (-not [string]::IsNullOrEmpty($User.'LOGON TIME'))
                        {
                            $SlashSplit = $User.'LOGON TIME'.Split('/')
                            $SpaceSplit = $SlashSplit[-1].Split(' ')
                            $ColonSplit = $SpaceSplit[1].Split(':')

                            $ParsedLogonTime = @{
                                Month  = ([int]$SlashSplit[0]).ToString('00')
                                Day    = ([int]$SlashSplit[1]).ToString('00')
                                Year   = $SpaceSplit[0]
                                Hour   = ([int]$ColonSplit[0]).ToString('00')
                                Minute = $ColonSplit[-1]
                                AmPm   = $SpaceSplit[-1]
                            }

                            $LogonTimeString = '{0}/{1}/{2} {3}:{4} {5}' -f $ParsedLogonTime.Month, $ParsedLogonTime.Day, $ParsedLogonTime.Year, $ParsedLogonTime.Hour, $ParsedLogonTime.Minute, $ParsedLogonTime.AmPm
                        }

                        # Build the return object from all of the session information
                        $HashObject = [Ordered]@{
                            ComputerName = $ComputerName
                            Username     = $User.USERNAME
                            DisplayName  = ""
                            SessionId    = $User.ID
                            SessionState = $User.STATE.Replace("Disc", "Disconnected")
                            SessionType  = $($User.SESSIONNAME -Replace '#', '' -Replace "[0-9]+", "")
                            IdleTime     = If ($User.'IDLE TIME' -ne '.' -and $User.'IDLE TIME' -notmatch '^24692+')
                            {
                                $IdleTimeValues = $User.'IDLE TIME' -replace '(\d+[+])*(\d+[:])*([0-9]+)', '$1;$2;$3' -replace '[+]' -replace '[:]' -split ';'
                                [TimeSpan]::new($IdleTimeValues[0], $IdleTimeValues[1], $IdleTimeValues[2], 0)
                            };
                            LogonTime    = If ($User.'LOGON TIME') { [DateTime]::ParseExact($LogonTimeString, 'MM/dd/yyyy hh:mm tt', [Globalization.CultureInfo]::InvariantCulture) };
                        }

                        # Attempt to resolve the Display Name if the switch parameter was specified, otherwise remove the attribute from the return object
                        If ($ResolveDisplayName)
                        {
                            $HashObject['DisplayName'] = (Get-WmiObject -Class Win32_UserAccount -Namespace "root\cimv2" -Filter "Name = '$($HashObject['Username'])'").FullName
                        }
                        Else
                        {
                            $HashObject.Remove('DisplayName')
                        }

                        
                        # Add the CPU, memory, and process information to the return object
                        If ($UserProcesses.Count -gt 0)
                        {
                            If ($ComputerName -eq 'localhost')
                            {
                                $ComputerUserProcesses = $UserProcesses.Where( {[string]::IsNullOrEmpty($_.PSComputerName) -and ($_.UserName -eq $HashObject.Username)})[0]
                            }
                            Else
                            {
                                $ComputerUserProcesses = $UserProcesses.Where( {($_.PSComputerName -eq $ComputerName) -and ($_.UserName -eq $HashObject.Username)})[0]
                            }
                            
                            $HashObject['Cpu'] = $ComputerUserProcesses.Cpu
                            $HashObject['Memory'] = $ComputerUserProcesses.Memory
                            $HashObject['Processes'] = $ComputerUserProcesses.Processes
                        }

                        # Return the object after casting as a PSCustomObject
                        [PSCustomObject]$HashObject

                    } # foreach ($User in $Users)

                } # Else

            } # If ($Proceed)

            Else
            {
                Write-Warning -Message "Computer '$($ComputerName)' is unreachable on port $($TestPort)"
            }
        
        } # $UserSessionScriptBlock

    }

    Process
    {
        If ($GetProcessInfo)
        {

            $InvokeCommandSplat = @{
                ScriptBlock = $ProcessInfoScriptBlock
                ErrorAction = 'Continue'
            }

            If ($ComputerName.Count -gt 0)
            {
                $InvokeCommandSplat['ComputerName'] = $ComputerName
            }

            If ($null -ne $Credential)
            {
                $InvokeCommandSplat['Credential'] = $Credential
            }

            If (-1 -ne $Port)
            {
                $InvokeCommandSplat['Port'] = $Port
            }

            If ($UseSSL.IsPresent)
            {
                $InvokeCommandSplat['UseSSL'] = $UseSSL.IsPresent
            }

            If ($null -ne $Authentication)
            {
                $InvokeCommandSplat['Authentication'] = $Authentication
            }

            If ($null -ne $SessionOption)
            {
                $InvokeCommandSplat['SessionOption'] = $SessionOption
            }

            # Run Invoke-Command to get the process information after building a splat with all necessary parameters
            Write-Verbose -Message "Running Invoke-Command with specified parameters to gather process information" -Verbose:$verbose
            $UserProcesses = Invoke-Command @InvokeCommandSplat

        }
        Else
        {
            $UserProcesses = @()
        }
        
        If ($ComputerName.Count -eq 0)
        {
            $ComputerName = @('')
        }

        If ($ShowProgress.IsPresent)
        {
            $ProgressActivity = 'Receiving Results'
            $TotalCompleted = 0
        }

        # Build a runspace for each computer and execute it
        $RunSpaces = foreach ($computerEntry in $ComputerName)
        {
            $Pipeline = [PowerShell]::Create()
            $null = $Pipeline.AddScript($UserSessionScriptBlock)

            $ScriptBlockParams = @(
                $computerEntry
                ,$ResolveDisplayName.IsPresent
                ,$UserProcesses
                ,$Verbose
            )

            foreach ($parameter in $ScriptBlockParams)
            {
                $null = $Pipeline.AddArgument($parameter)
            }

            $Pipeline.RunspacePool = $Pool

            [PSCustomObject]@{
                Pipeline = $Pipeline
                Status = $Pipeline.BeginInvoke()
            }

        } # foreach ($computerEntry in $ComputerName)

        # Process the various runspace streams and output, while displaying progress if desired
        While ($RunSpaces.Status -ne $null)
        {
            $Completed = $RunSpaces | Where-Object -FilterScript { $_.Status.IsCompleted -eq $true }

            If ($ShowProgress.IsPresent)
            {
			    $TotalCompleted += $Completed.Count
                [int]$PercentComplete = ($TotalCompleted / $RunSpaces.Count) * 100
                Write-Progress -Id 1 -Activity $ProgressActivity -PercentComplete $PercentComplete -Status "Percent Complete: $($PercentComplete)%"
		    }

            foreach ($RunSpace in $Completed)
            {
                # EndInvoke method retrieves the results of the asynchronous call
                $RunSpace.Pipeline.Streams.Warning | ForEach-Object -Process { Write-Warning -Message $_ }
                $RunSpace.Pipeline.Streams.Verbose | ForEach-Object -Process { Write-Verbose -Message $_ -Verbose:$Verbose }
                
                $RunSpace.Pipeline.EndInvoke($RunSpace.Status)

                $RunSpace.Status = $null
                $RunSpace.Pipeline.Dispose()
            }
        }

        If ($ShowProgress.IsPresent)
        {
            Write-Progress -Id 1 -Activity $ProgressActivity -Completed
        }

    } # Process

} # Function Get-UserSession
