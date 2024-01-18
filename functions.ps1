function Get-DnsInfo {
    # Try to get DNS servers and domain suffix from network configuration
    $networkConfig = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }

    $dnsServers = $networkConfig.DNSServerSearchOrder | Where-Object { $_ -ne $null } | Select-Object -Unique
    $domainSuffix = $networkConfig.DNSDomainSuffixSearchOrder | Where-Object { $_ -ne $null } | Select-Object -Unique

    if ($dnsServers.Count -eq 0) {
        # If DNS servers are not configured, fall back to default gateway
        $defaultGateway = (
            Get-NetRoute -AddressFamily IPv4 | Where-Object { 
                $_.DestinationPrefix -eq '0.0.0.0/0' 
        }).NextHop
        $dnsServers = (Resolve-DnsName -Name $defaultGateway).QueryResults.QueryData.IPAddress | Where-Object { $_ -ne $null } | Select-Object -Unique
    }

    return @{
        DnsServers = $dnsServers
        DomainSuffix = $domainSuffix
    }
}

function Render-Template {
    # Read a config file template, match any strings surrounded by $pre and $post, to keys of the same name in $Variables
    # and replace them with the value of the key in $Variables
    # If the key is not found or is null, comment out the line with preserved indentation
    # 
    [CmdletBinding()]
    param (
        [string]$TemplateFilePath,
        [hashtable]$Variables,
        [string]$pre = '!!@',
        [string]$post = '@!!',
        [string]$comment = '# '
    )

    If (-not (Test-Path $TemplateFilePath -PathType Leaf)) {
        Throw "Template file not found: $TemplateFilePath"
    }
    
    $regex = "$pre(\w+)$post"
    $templateContent = Get-Content $TemplateFilePath

    for ($i = 0; $i -lt $templateContent.Count; $i++) {
        $line = $templateContent[$i]
        $match = [regex]::Matches($line, $regex)

        foreach ($m in $match) {
            $var = $m.Groups[1].Value
            If ($Variables.ContainsKey($var) -and $Variables[$var] -notin $null,'') {
                $line = $line -replace "$pre$var$post", $Variables[$var]
            } Else {
                # If variable not found or is null, comment out the line with preserved indentation
                $leadingWhitespace = $line -replace '^(\s*).*$','$1'
                $line = $leadingWhitespace + $comment + ($line.trim() -replace $regex, '')
                break  # No need to check further If one variable in the line is null or not found
            }
        } 

        $templateContent[$i] = $line
    }
    #return $templateContent -join "`n"
    return ($templateContent -join "`n" -replace $regex, '')
}

Function Fetch-Checksums {
    [CmdletBinding()]
    param (
        [parameter(position=0)][string]$url,
        [parameter(position=1)][string]$pattern = '^(?<Checksum>[a-fA-F0-9]+)\s+(?<FileName>.+)$'
    )
    If ( -not $url) {
        Throw "No URL specified"
    }
    $count = 0
    Do {
        Try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing
            $success = $?
        }
        Catch {
            Write-Warning "Failed to download checksums: $_"
            Write-Warning "Retrying in 5 seconds..."
            Start-Sleep -Seconds 5
        }
        $count++
    } While ( -not $success -and $count -lt 5 )
    If (-not $success) {
        Throw $_
    }
    $matches = $response.RawContent -split '\r?\n' | ForEach-Object {
        If ($_ -match $pattern) {
            [PSCustomObject] @{
                FileName = $Matches['FileName'].Trim('*')
                Checksum = $Matches['Checksum']
            }
        }
    }
    Return $matches
}

Function cleanupFile ([string]$file) {
    If (test-path $file) {
      Remove-Item $file -force
    }
}

Function Cleanup-VM {
<#
.SYNOPSIS
    Stop VM and remove all resources
.EXAMPLE
    PS C:\> .\Cleanup-VM "VM1","VM2" [-Force]
#>

[CmdletBinding()]
    param(
        [string[]] $VMNames = @(),
        [switch] $Force = $false
    )

    If ($Force -or $PSCmdlet.ShouldContinue("Are you sure you want to delete VM?", "Data purge warning")) {
        If ($VMNames.Count -gt 0) {
            Write-Host "Stop and delete VMs and its data files..." -NoNewline

            $VMNames | ForEach-Object {

                $v = $_
                If ($v.GetType() -eq [Microsoft.HyperV.PowerShell.VirtualMachine]) {
                    $v = $v.Name
                }

                Write-Verbose "Trying to stop $v ..."
                stop-vm $v -TurnOff -Confirm:$false -ErrorAction 'SilentlyContinue' | Out-Null

                # remove snapshots
                Remove-VMSnapshot -VMName $v -IncludeAllChildSnapshots -ErrorAction SilentlyContinue
                # remove disks
                Get-VM $v -ErrorAction SilentlyContinue | ForEach-Object {
                    $_.id | get-vhd -ErrorAction SilentlyContinue | ForEach-Object {
                        remove-item -path $_.path -force -ErrorAction SilentlyContinue
                    }
                }
                #remove cloud-init metadata iso
                $VHDPath = (Get-VMHost).VirtualHardDiskPath
                Remove-Item -Path "$VHDPath$v-metadata.iso" -ErrorAction SilentlyContinue
                # remove vm
                Remove-VM -VMName $v -Force -ErrorAction SilentlyContinue | Out-Null
            }

            Write-Host -ForegroundColor Green " Done."

        }
    }
}
Function Make-Random {
    Param  ( 
        [parameter(position=0)][int]$count = 10,
        [switch]$uppercase,
        [switch]$hex
    )
    if ($hex) {
        $charset = (0x30..0x39) + ( 0x41..0x47)
    } else {
        $charset = (0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A)
    }
    $result = (-join ($charset | Get-Random -Count $count | Foreach-Object {[char]$_}))
    if ($uppercase) {
        $result = $result.ToUpper()
    }
    Return $result
}

Function Set-VMAdvancedSettings {
        <#
        .SYNOPSIS
            Changes the settings for Hyper-V guests that are not available through GUI tools.
            If you do not specify any parameters to be changed, the script will re-apply the settings that the virtual machine already has.
        .DESCRIPTION
            Changes the settings for Hyper-V guests that are not available through GUI tools.
            If you do not specify any parameters to be changed, the script will re-apply the settings that the virtual machine already has.
            If the virtual machine is running, this script will attempt to shut it down prior to the operation. Once the replacement is complete, the virtual machine will be turned back on.
        src: https://www.altaro.com/hyper-v/powershell-script-change-advanced-settings-hyper-v-virtual-machines/
        .PARAMETER VM
            The name or virtual machine object of the virtual machine whose BIOSGUID is to be changed. Will accept a string, output from Get-VM, or a WMI instance of class Msvm_ComputerSystem.
        .PARAMETER ComputerName
            The name of the Hyper-V host that owns the target VM. Only used If VM is a string.
        .PARAMETER NewBIOSGUID
            The new GUID to assign to the virtual machine. Cannot be used with AutoGenBIOSGUID.
        .PARAMETER AutoGenBIOSGUID
            Automatically generate a new BIOS GUID for the VM. Cannot be used with NewBIOSGUID.
        .PARAMETER BaseboardSerialNumber
            New value for the VM's baseboard serial number.
        .PARAMETER BIOSSerialNumber
            New value for the VM's BIOS serial number.
        .PARAMETER ChassisAssetTag
            New value for the VM's chassis asset tag.
        .PARAMETER ChassisSerialNumber
            New value for the VM's chassis serial number.
        .PARAMETER ComputerName
            The Hyper-V host that owns the virtual machine to be modified.
        .PARAMETER Timeout
            Number of seconds to wait when shutting down the guest before assuming the shutdown failed and ending the script.
            Default is 300 (5 minutes).
            If the virtual machine is off, this parameter has no effect.
        .PARAMETER Force
            Suppresses prompts. If this parameter is not used, you will be prompted to shut down the virtual machine If it is running and you will be prompted to replace the BIOSGUID.
            Force can shut down a running virtual machine. It cannot affect a virtual machine that is saved or paused.
        .PARAMETER WhatIf
            Performs normal WhatIf operations by displaying the change that would be made. However, the new BIOSGUID is automatically generated on each run. The one that WhatIf displays will not be used.
        .NOTES
            Version 1.2
            July 25th, 2018
            Author: Eric Siron

            Version 1.2:
            * Multiple non-impacting infrastructure improvements
            * Fixed operating against remote systems
            * Fixed "Force" behavior

            Version 1.1: Fixed incorrect verbose outputs. No functionality changes.
        .EXAMPLE
            Set-VMAdvancedSettings -VM svtest -AutoGenBIOSGUID
            
            Replaces the BIOS GUID on the virtual machine named svtest with an automatically-generated ID.

        .EXAMPLE
            Set-VMAdvancedSettings svtest -AutoGenBIOSGUID

            Exactly the same as example 1; uses positional parameter for the virtual machine.

        .EXAMPLE
            Get-VM svtest | Set-VMAdvancedSettings -AutoGenBIOSGUID

            Exactly the same as example 1 and 2; uses the pipeline.

        .EXAMPLE
            Set-VMAdvancedSettings -AutoGenBIOSGUID -Force

            Exactly the same as examples 1, 2, and 3; prompts suppressed.

        .EXAMPLE
            Set-VMAdvancedSettings -VM svtest -NewBIOSGUID $Guid

            Replaces the BIOS GUID of svtest with the supplied ID. These IDs can be generated with [System.Guid]::NewGuid(). You can also supply any value that can be parsed to a GUID (ex: C0AB8999-A69A-44B7-B6D6-81457E6EC66A }.

        .EXAMPLE
            Set-VMAdvancedSettings -VM svtest -NewBIOSGUID $Guid -BaseBoardSerialNumber '42' -BIOSSerialNumber '42' -ChassisAssetTag '42' -ChassisSerialNumber '42'

            Modifies all settings that this function can affect.
        
        .EXAMPLE
            Set-VMAdvancedSettings -VM svtest -AutoGenBIOSGUID -WhatIf

            Shows HOW the BIOS GUID will be changed, but the displayed GUID will NOT be recycled If you run it again without WhatIf. TIP: Use this to view the current BIOS GUID without changing it.
        
        .EXAMPLE
            Set-VMAdvancedSettings -VM svtest -NewBIOSGUID $Guid -BaseBoardSerialNumber '42' -BIOSSerialNumber '42' -ChassisAssetTag '42' -ChassisSerialNumber '42' -WhatIf

            Shows what would be changed without making any changes. TIP: Use this to view the current settings without changing them.
        #>
        #requires -Version 4

        [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High', DefaultParameterSetName='ManualBIOSGUID')]
        param (
            [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=1)][PSObject]$VM,
            [Parameter()][String]$ComputerName = $env:COMPUTERNAME,
            [Parameter(ParameterSetName='ManualBIOSGUID')][Object]$NewBIOSGUID,
            [Parameter(ParameterSetName='AutoBIOSGUID')][Switch]$AutoGenBIOSGUID,
            [Parameter()][String]$BaseBoardSerialNumber,
            [Parameter()][String]$BIOSSerialNumber,
            [Parameter()][String]$ChassisAssetTag,
            [Parameter()][String]$ChassisSerialNumber,
            [Parameter()][UInt32]$Timeout = 300,
            [Parameter()][Switch]$Force
        )

        Begin {
            function Change-VMSetting {
                    param (
                        [Parameter(Mandatory=$true)][System.Management.ManagementObject]$VMSettings,
                        [Parameter(Mandatory=$true)][String]$PropertyName,
                        [Parameter(Mandatory=$true)][String]$NewPropertyValue,
                        [Parameter(Mandatory=$true)][String]$PropertyDisplayName,
                        [Parameter(Mandatory=$true)][System.Text.StringBuilder]$ConfirmText
                    )
                    $Message = 'Set "{0}" from {1} to {2}' -f $PropertyName, $VMSettings[($PropertyName)], $NewPropertyValue
                    Write-Verbose -Message $Message
                    $OutNull = $ConfirmText.AppendLine($Message)
                    $CurrentSettingsData[($PropertyName)] = $NewPropertyValue
                    $OriginalValue = $CurrentSettingsData[($PropertyName)]
            }

            <# adapted from http://blogs.msdn.com/b/taylorb/archive/2008/06/18/hyper-v-wmi-rich-error-messages-for-non-zero-returnvalue-no-more-32773-32768-32700.aspx #>
            function Process-WMIJob {
                param (
                    [Parameter(ValueFromPipeline=$true)][System.Management.ManagementBaseObject]$WmiResponse,
                    [Parameter()][String]$WmiClassPath = $null,
                    [Parameter()][String]$MethodName = $null,
                    [Parameter()][String]$VMName,
                    [Parameter()][String]$ComputerName
                )
        
                Process {
                    $ErrorCode = 0
                    If ($WmiResponse.ReturnValue -eq 4096) {
                        $Job = [WMI]$WmiResponse.Job
                        While ($Job.JobState -eq 4) {
                            Write-Progress -Activity ('Modifying virtual machine {0} on host {1}' -f $VMName, $ComputerName) -Status ('{0}% Complete' -f $Job.PercentComplete) -PercentComplete $Job.PercentComplete
                            Start-Sleep -Milliseconds 100
                            $Job.PSBase.Get()
                        }
    
                        If ($Job.JobState -ne 7) {
                            If ($Job.ErrorDescription -ne "") {
                                Write-Error -Message $Job.ErrorDescription
                                Exit 1
                            }
                            Else {
                                $ErrorCode = $Job.ErrorCode
                            }
                            Write-Progress $Job.Caption "Completed" -Completed $true
                        }
                    }
                    Elseif  ($WmiResponse.ReturnValue -ne 0) {
                        $ErrorCode = $WmiResponse.ReturnValue
                    }
    
                    If ($ErrorCode -ne 0) {
                        If ($WmiClassPath -and $MethodName) {
                            $PSWmiClass = [WmiClass]$WmiClassPath
                            $PSWmiClass.PSBase.Options.UseAmendedQualifiers = $true
                            $MethodQualifiers = $PSWmiClass.PSBase.Methods[$MethodName].Qualifiers
                            $IndexOfError = [System.Array]::IndexOf($MethodQualifiers["ValueMap"].Value, [String]$ErrorCode)
                            If ($IndexOfError -ne "-1") {
                                Write-Error -Message ('Error Code: {0}, Method: {1}, Error: {2}' -f $ErrorCode, $MethodName, $MethodQualifiers["Values"].Value[$IndexOfError])
                                Exit 1
                            }
                            Else {
                                Write-Error -Message ('Error Code: {0}, Method: {1}, Error: Message Not Found' -f $ErrorCode, $MethodName)
                                Exit 1
                            }
                        }
                    }
                }
            }
        }
        Process {
            $ConfirmText = New-Object System.Text.StringBuilder
            $VMObject = $null
            Write-Verbose -Message 'Validating input...'
            $VMName = ''
            $InputType = $VM.GetType()
            If ($InputType.FullName -eq 'System.String') {
                $VMName = $VM
            } Elseif  ($InputType.FullName -eq 'Microsoft.HyperV.PowerShell.VirtualMachine') {
                $VMName = $VM.Name
                $ComputerName = $VM.ComputerName
            } Elseif  ($InputType.FullName -eq 'System.Management.ManagementObject') {
                $VMObject = $VM
            } Else {
                Write-Error -Message 'You must supply a virtual machine name, a virtual machine object from the Hyper-V module, or an Msvm_ComputerSystem WMI object.'
                Exit 1
            }

            If ($NewBIOSGUID -ne $null) {
                try {
                    $NewBIOSGUID = [System.Guid]::Parse($NewBIOSGUID)
                }
                catch {
                    Write-Error -Message 'Provided GUID cannot be parsed. Supply a valid GUID or use the AutoGenBIOSGUID parameter to allow an ID to be automatically generated.'
                    Exit 1
                }
            }

            Write-Verbose -Message ('Establishing WMI connection to Virtual Machine Management Service on {0}...' -f $ComputerName)
            $VMMS = Get-WmiObject -ComputerName $ComputerName -Namespace 'root\virtualization\v2' -Class 'Msvm_VirtualSystemManagementService' -ErrorAction Stop
            Write-Verbose -Message 'Acquiring an empty parameter object for the ModifySystemSettings function...'
            $ModifySystemSettingsParams = $VMMS.GetMethodParameters('ModifySystemSettings')
            Write-Verbose -Message ('Establishing WMI connection to virtual machine {0}' -f $VMName)
            If ($VMObject -eq $null) {
                $VMObject = Get-WmiObject -ComputerName $ComputerName -Namespace 'root\virtualization\v2' -Class 'Msvm_ComputerSystem' -Filter ('ElementName = "{0}"' -f $VMName) -ErrorAction Stop
            }
            If ($VMObject -eq $null) {
                Write-Error -Message ('Virtual machine {0} not found on computer {1}' -f $VMName, $ComputerName)
                Exit 1
            }
            Write-Verbose -Message ('Verifying that {0} is off...' -f $VMName)
            $OriginalState = $VMObject.EnabledState
            If ($OriginalState -ne 3) {
                If ($OriginalState -eq 2 -and ($Force.ToBool() -or $PSCmdlet.ShouldProcess($VMName, 'Shut down'))) {
                    $ShutdownComponent = $VMObject.GetRelated('Msvm_ShutdownComponent')
                    Write-Verbose -Message 'Initiating shutdown...'
                    Process-WMIJob -WmiResponse $ShutdownComponent.InitiateShutdown($true, 'Change BIOSGUID') -WmiClassPath $ShutdownComponent.ClassPath -MethodName 'InitiateShutdown' -VMName $VMName -ComputerName $ComputerName -ErrorAction Stop
                    # the InitiateShutdown function completes as soon as the guest's integration services respond; it does not wait for the power state change to complete
                    Write-Verbose -Message ('Waiting for virtual machine {0} to shut down...' -f $VMName)
                    $TimeoutCounterStarted = [datetime]::Now
                    $TimeoutExpiration = [datetime]::Now + [timespan]::FromSeconds($Timeout)
                    While ($VMObject.EnabledState -ne 3) {
                        $ElapsedPercent = [UInt32]((([datetime]::Now - $TimeoutCounterStarted).TotalSeconds / $Timeout) * 100)
                        if ($ElapsedPercent -ge 100) {
                            Write-Error -Message ('Timeout waiting for virtual machine {0} to shut down' -f $VMName)
                            Exit 1
                        } Else {
                            Write-Progress -Activity ('Waiting for virtual machine {0} on {1} to stop' -f $VMName, $ComputerName) -Status ('{0}% timeout expiration' -f ($ElapsedPercent)) -PercentComplete $ElapsedPercent
                            Start-Sleep -Milliseconds 250
                            $VMObject.Get()
                        }
                    }
                }
                Elseif  ($OriginalState -ne 2) {
                    Write-Error -Message ('Virtual machine must be turned off to change advanced settings. It is not in a state this script can work with.' -f $VMName)
                    Exit 1
                }
            }
            Write-Verbose -Message ('Retrieving all current settings for virtual machine {0}' -f $VMName)
            $CurrentSettingsDataCollection = $VMObject.GetRelated('Msvm_VirtualSystemSettingData')
            Write-Verbose -Message 'Extracting the settings data object from the settings data collection object...'
            $CurrentSettingsData = $null
            foreach ($SettingsObject in $CurrentSettingsDataCollection) {
                if ($VMObject.Name -eq $SettingsObject.ConfigurationID) {
                    $CurrentSettingsData = [System.Management.ManagementObject]($SettingsObject)
                }
            }

            If ($AutoGenBIOSGUID -or $NewBIOSGUID) {
                If ($AutoGenBIOSGUID) {
                    $NewBIOSGUID = [System.Guid]::NewGuid().ToString()
                }
                Change-VMSetting -VMSettings $CurrentSettingsData -PropertyName 'BIOSGUID' -NewPropertyValue (('{{{0}}}' -f $NewBIOSGUID).ToUpper()) -PropertyDisplayName 'BIOSGUID' -ConfirmText $ConfirmText
            }
            If ($BaseBoardSerialNumber) {
                Change-VMSetting -VMSettings $CurrentSettingsData -PropertyName 'BaseboardSerialNumber' -NewPropertyValue $BaseBoardSerialNumber -PropertyDisplayName 'baseboard serial number' -ConfirmText $ConfirmText
            }
            If ($BIOSSerialNumber) {
                Change-VMSetting -VMSettings $CurrentSettingsData -PropertyName 'BIOSSerialNumber' -NewPropertyValue $BIOSSerialNumber -PropertyDisplayName 'BIOS serial number' -ConfirmText $ConfirmText
            }
            If ($ChassisAssetTag) {
                Change-VMSetting -VMSettings $CurrentSettingsData -PropertyName 'ChassisAssetTag' -NewPropertyValue $ChassisAssetTag -PropertyDisplayName 'chassis asset tag' -ConfirmText $ConfirmText
            }
            If ($ChassisSerialNumber) {
                Change-VMSetting -VMSettings $CurrentSettingsData -PropertyName 'ChassisSerialNumber' -NewPropertyValue $ChassisSerialNumber -PropertyDisplayName 'chassis serial number' -ConfirmText $ConfirmText
            }

            Write-Verbose -Message 'Assigning modified data object as parameter for ModifySystemSettings function...'
            $ModifySystemSettingsParams['SystemSettings'] = $CurrentSettingsData.GetText([System.Management.TextFormat]::CimDtd20)
            If ($Force.ToBool() -or $PSCmdlet.ShouldProcess($VMName, $ConfirmText.ToString())) {
                Write-Verbose -Message ('Instructing Virtual Machine Management Service to modify settings for virtual machine {0}' -f $VMName)
                Process-WMIJob -WmiResponse ($VMMS.InvokeMethod('ModifySystemSettings', $ModifySystemSettingsParams, $null)) -WmiClassPath $VMMS.ClassPath -MethodName 'ModifySystemSettings' -VMName $VMName -ComputerName $ComputerName
            }
            $VMObject.Get()
            If ($OriginalState -ne $VMObject.EnabledState) {
                Write-Verbose -Message ('Returning {0} to its prior running state.' -f $VMName)
                Process-WMIJob -WmiResponse $VMObject.RequestStateChange($OriginalState) -WmiClassPath $VMObject.ClassPath -MethodName 'RequestStateChange' -VMName $VMName -ComputerName $ComputerName -ErrorAction Stop
            }
        }
    #}  # uncomment this line and the first two lines to use as a profile or dot-sourced function
}

# $freeRAMbytes = ((Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize * 1KB) - (Get-Process | Measure-Object WorkingSet -Sum).Sum


Function YAML-fileWrite{
    [cmdletBinding()]
    param (
        $content,    
        [int]$indent = 2,
        [string]$path
    )
    If ($content.GetType().name -eq 'Object[]') {
        # content is an array. pass it thru
        $r_content = $content
    } else {
        If (Test-Path $content) {
            # Content is a file. load it
            $r_content = Get-Content $content
        } Else {
            Throw "Unable to load content from $content"
        }
    }
    
    $indent_str = ' ' * $indent
    $result_yaml = @()
    $result_yaml += ($indent_str + '- content: |')
    # Loop through each line, skip blank lines

    Foreach ($l in $r_content) {
        # Skip blank lines and comments
        # try trimming $l so we can detect a leading #
        Try {$ll = $l.trim()}
        Catch {$ll = $l}
        if (($l -match '^\s*$') -or ($ll -match '^#')) {
            continue
        }
        $line = $indent_str + '    ' + $l
        $result_yaml += $line
    }
    $result_yaml += ($indent_str + '  path: ' + $path)
    Return $result_yaml
}

Function Create-htpasswd {
    [cmdletBinding()]
    param (
        [parameter(Position=0)][string]$username,
        [parameter(Position=1)][string]$password
    )
    # Take a plaintext username + password and generate the contents of an .htpasswd file for use with nginx
    # uses bcrypt
    # https://poshsecurity.com/blog/2013/4/12/password-hashing-with-bcrypt-and-powershell-part-2.html
    # https://httpd.apache.org/docs/2.4/misc/password_encryptions.html
    # https://github.com/BcryptNet/bcrypt.net/releases

    if ( (-not $username) -or (-not $password) ) {
        Throw "username and password must be specified"
    }
    Add-Type -Path ($PWD.path + '\tools\BCrypt.Net-Next.dll')
    $salt = [bcrypt.net.bcrypt]::generatesalt()
    $hashedpass = [bcrypt.net.bcrypt]::hashpassword($password, $Salt)

    $contents = $username + ':' + $hashedpass
    Return $contents
}