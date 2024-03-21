<#
.SYNOPSIS
  Provision Cloud images on Hyper-V
  Monolithic version for RMM use 
  All defaults are set. Running the script without any parameters will create an Ubuntu 22.04 VM
  Create a userdata file and put it in this script as $userdata_template

.NOTES

  My fork (less monolithic than this script): https://github.com/Luke-Williams9/hyperv-vm-provisioning
  
  Thanks to schtritoff for the doing most of the dirty work:
  This projected Forked from: https://github.com/schtritoff/hyperv-vm-provisioning

  Thanks to Benjamin Armstrong for the original script:
  https://blogs.msdn.microsoft.com/virtual_pc_guy/2015/06/23/building-a-daily-ubuntu-image-for-hyper-v/
  Ben Armstrongs blog:
  https://american-boffin.bawkie.com/
  
  References:
  - https://git.launchpad.net/cloud-init/tree/cloudinit/sources/DataSourceAzure.py
  - https://github.com/Azure/azure-linux-extensions/blob/master/script/ovf-env.xml
  - https://cloudinit.readthedocs.io/en/latest/topics/datasources/azure.html
  - https://github.com/fdcastel/Hyper-V-Automation
  - https://bugs.launchpad.net/ubuntu/+source/walinuxagent/+bug/1700769
  - https://gist.github.com/Informatic/0b6b24374b54d09c77b9d25595cdbd47
  - https://www.neowin.net/news/canonical--microsoft-make-azure-tailored-linux-kernel/
  - https://www.altaro.com/hyper-v/powershell-script-change-advanced-settings-hyper-v-virtual-machines/

  It should download cloud image and create VM, please be patient for first boot - it could take 10 minutes
  and requires network connection on VM
  
#>

<# -------------------------------------------------------- Parameters --------------------------------------------------------------------------------------------- #>

#requires -Modules Hyper-V
#requires -RunAsAdministrator
[cmdletBinding()]
param (
  [switch] $Force = $false,
  [string] $GuestAdminUsername = "admin",
  [string] $GuestAdminPassword,
  [string] $GuestAdminSshPubKey,
  [string] $ImageVersion,
  [string] $KeyboardLayout = "us", # 2-letter country code, for more info https://wiki.archlinux.org/title/Xorg/Keyboard_configuration
  [string] $KeyboardModel, # default: "pc105"
  [string] $KeyboardOptions, # example: "compose:rwin"
  [string] $Locale = ((Get-Culture).Name.replace('-','_')) + '.UTF-8', # "en_US.UTF-8",
  [string] $NetMacAddress,
  [string] $NetInterface  = "eth0",
  [string] $NetAddress,
  [string] $NetNetmask,
  [string] $NetNetwork,
  [string] $NetGateway,
  [array]  $NameServers,
  [switch] $NoStart, # Set to True to prevent starting the VM at the end of the script
  [string] $tempRoot = "${env:systemdrive}\linuxVMtemp",
  [string] $TimeZone, # UTC or continental zones of IANA DB like: Europe/Berlin. https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
  [string] $VMName,
  [int]    $VMGeneration = 1, # create gen1 hyper-v machine because of portability to Azure (https://docs.microsoft.com/en-us/azure/virtual-machines/windows/prepare-for-upload-vhd-image)
  [int]    $VMProcessorCount = 4,
  [bool]   $VMDynamicMemoryEnabled = $false,
  [uint64] $VMMemoryStartupBytes = 4GB,
  [uint64] $VMMinimumBytes = $VMMemoryStartupBytes,
  [uint64] $VMMaximumBytes = $VMMemoryStartupBytes,
  [uint64] $VHDSizeBytes = 200GB,
  [switch] $VMdataVol = $false,
  [uint64] $VMdataVolSizeBytes = 64GB,
  [string] $VMdataVolMountPoint = '/mnt/data',
  [string] $VirtualSwitchName,
  [string] $VMVlanID,
  [string] $VMNativeVlanID,
  [string] $VMAllowedVlanIDList,
  [switch] $VMVMQ,
  [switch] $VMDhcpGuard,
  [switch] $VMRouterGuard,
  [switch] $VMPassthru = $false,
  [switch] $VMMacAddressSpoofing = $false,
  [switch] $VMExposeVirtualizationExtensions = $false,
  [string] $VMVersion = (Get-VMHostSupportedVersion | Where-Object IsDefault).Version,
  [string] $VMHostname,
  [string] $VMpath, # if not defined here default Virtal Machine path is used
  [string] $VHDpath, # if not defined here Hyper-V settings path / fallback path is set below
  [string] $blumiraSensorInstall # required
)

$ErrorActionPreference = 'Stop'

# Make sure this script runs in a 64 bit environment
if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
  write-warning "Executing your script in 64-bit mode"
  if ($myInvocation.Line) {
    &"$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile $myInvocation.Line
  } else {
    &"$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile -file "$($myInvocation.InvocationName)" $args
  }
  exit $lastexitcode
}

if ( -not $blumiraSensorInstall) {
  Throw "-blumiraSensorInstall is required. Copy the install string from the Blumira portal."
  exit 1
}
if ($env:adminUser) {
  $guestAdminUsername = $env:adminUser
}
if ($env:adminpassword) {
  $guestAdminPassword = $env:adminpassword
}
if ($env:vmHostname) {
  $VMName = $env:vmHostname
}
if ($env:ipAddress) {
  $NetAddress = $env:ipAddress
}

<# -------------------------------------------------------- Functions ---------------------------------------------------------------------------------------------- #>

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
    function Render-Template {
      # Read a config file template, match any strings surrounded by $pre and $post, to keys of the same name in $Variables
      # and replace them with the value of the key in $Variables
      # If the key is not found or is null, comment out the line with preserved indentation
      # 
      [CmdletBinding()]
      param (
          [string]$Template,
          [hashtable]$Variables,
          [string]$pre = '!!@',
          [string]$post = '@!!',
          [string]$comment = '# '
      )
      
      $regex = "$pre(\w+)$post"
      $templateContent = $Template -split "`n"

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

<# -------------------------------------------------------- USERDATA ----------------------------------------------------------------------------------------------- #>

# Userdata.ubuntu-docker.template
$userdata_template = @'
#cloud-config
# vim: syntax=yaml
# created: !!@createdDateStamp@!!
# values surrounded by !!@ @!! need to be replaced by powershell variables of the same name

hostname: !!@VMHostname@!!
fqdn: !!@FQDN@!!
# prefer_fqdn_over_hostname: true

# cloud-init Bug 21.4.1: locale update prepends "LANG=" like in
# /etc/defaults/locale set and results into error
#locale: $Locale
timezone: !!@TimeZone@!!

growpart:
  mode: auto
  devices: [/]
  ignore_growroot_disabled: false

preserve_sources_list: true
package_update: true
package_upgrade: true
package_reboot_if_required: true

packages:
  - eject
  - console-setup
  - keyboard-configuration
  - docker.io
  - docker-compose
  - linux-tools-virtual
  - linux-cloud-tools-virtual
  - linux-azure
  - snmp
  - snmpd

# https://learn.microsoft.com/en-us/azure/virtual-machines/linux/cloudinit-add-user#add-a-user-to-a-vm-with-cloud-init

users:
  - default
  - name: !!@GuestAdminUsername@!!
    no_user_group: true
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    plain_text_passwd: !!@GuestAdminPassword@!!
    lock_passwd: false
    ssh_authorized_keys:
    !!@ssh_keys@!!

ntp:
  enabled: true
  servers:
    - 0.pool.ntp.org
    - 1.pool.ntp.org
    - 2.pool.ntp.org
    - 3.pool.ntp.org

  disable_root: true    # true: notify default user account / false: allow root ssh login
ssh_pwauth: true      # true: allow login with password; else only with setup pubkey(s)

runcmd:
  # remove metadata iso
  - 'sh -c "if test -b /dev/cdrom; then eject; fi"'
  - 'sh -c "if test -b /dev/sr0; then eject /dev/sr0; fi"'
  # disable cloud init on next boot (https://cloudinit.readthedocs.io/en/latest/topics/boot.html, https://askubuntu.com/a/1047618)
  - 'sh -c touch /etc/cloud/cloud-init.disabled'
  - 'echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf sudo sysctl -p'
  # set locale
  # cloud-init Bug 21.4.1: locale update prepends "LANG=" like in
  # /etc/defaults/locale set and results into error
  - 'locale-gen "!!@Locale@!!"'
  - 'update-locale "!!@Locale@!!"'
  - 'systemctl enable docker-bootstrap.service'
  - 'systemctl start docker-bootstrap.service'
  - "!!#blumiraSensorInstall#!!"
  - 'reboot'
  
write_files:
  - content: |
      #!/bin/bash
      # This example script parses /etc/resolv.conf to retrive DNS information.
      # In the interest of keeping the KVP daemon code free of distro specific
      # information; the kvp daemon code invokes this external script to gather
      # DNS information.
      # This script is expected to print the nameserver values to stdout.
      # Each Distro is expected to implement this script in a distro specific
      # fashion. For instance on Distros that ship with Network Manager enabled,
      # this script can be based on the Network Manager APIs for retrieving DNS
      # entries.
      cat /etc/resolv.conf 2>/dev/null | awk '/^nameserver/ { print $2 }'
    path: /usr/libexec/hypervkvpd/hv_get_dns_info
  - content: |
      #!/bin/bash
      # SPDX-License-Identifier: GPL-2.0
      # This example script retrieves the DHCP state of a given interface.
      # In the interest of keeping the KVP daemon code free of distro specific
      # information; the kvp daemon code invokes this external script to gather
      # DHCP setting for the specific interface.
      #
      # Input: Name of the interface
      #
      # Output: The script prints the string "Enabled" to stdout to indicate
      #	that DHCP is enabled on the interface. If DHCP is not enabled,
      #	the script prints the string "Disabled" to stdout.
      #
      # Each Distro is expected to implement this script in a distro specific
      # fashion. For instance, on Distros that ship with Network Manager enabled,
      # this script can be based on the Network Manager APIs for retrieving DHCP
      # information.
      # RedHat based systems
      #if_file="/etc/sysconfig/network-scripts/ifcfg-"$1
      # Debian based systems
      if_file=`"/etc/network/interrfaces.d/*`"
      dhcp=`$(grep `"dhcp`" `$if_file 2>/dev/null)
      if [ "$dhcp" != "" ];
      then
      echo "Enabled"
      else
      echo "Disabled"
      fi
    path: /usr/libexec/hypervkvpd/hv_get_dhcp_info
  - content: |
      {"attributes":{"buildNum":6867,"defaultIndex":"elastiflow-flow-ecs-*","defaultRoute":"/app/dashboards#/view/4a608bc0-3d3e-11eb-bc2c-c5758316d788?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-15m,to:now))&_a=(description:'',filters:!(),fullScreenMode:!f,options:(hidePanelTitles:!f,useMargins:!f),query:(language:kuery,query:''),timeRestore:!f,title:'ElastiFlow%20(flow):%20Overview',viewMode:view)","doc_table:highlight":false,"filters:pinnedByDefault":true,"format:number:defaultPattern":"0,0.[00]","format:percent:defaultPattern":"0,0.[00]%","state:storeInSessionStorage":true,"theme:darkMode":true,"timepicker:quickRanges":"[\r\n  {\r\n    \"from\": \"now-15m/m\",\r\n    \"to\": \"now/m\",\r\n    \"display\": \"Last 15 minutes\"\r\n  },\r\n  {\r\n    \"from\": \"now-30m/m\",\r\n    \"to\": \"now/m\",\r\n    \"display\": \"Last 30 minutes\"\r\n  },\r\n  {\r\n    \"from\": \"now-1h/m\",\r\n    \"to\": \"now/m\",\r\n    \"display\": \"Last 1 hour\"\r\n  },\r\n  {\r\n    \"from\": \"now-2h/m\",\r\n    \"to\": \"now/m\",\r\n    \"display\": \"Last 2 hours\"\r\n  },\r\n  {\r\n    \"from\": \"now-4h/m\",\r\n    \"to\": \"now/m\",\r\n    \"display\": \"Last 4 hours\"\r\n  },\r\n  {\r\n    \"from\": \"now-12h/m\",\r\n    \"to\": \"now/m\",\r\n    \"display\": \"Last 12 hours\"\r\n  },\r\n  {\r\n    \"from\": \"now-24h/m\",\r\n    \"to\": \"now/m\",\r\n    \"display\": \"Last 24 hours\"\r\n  },\r\n  {\r\n    \"from\": \"now-48h/m\",\r\n    \"to\": \"now/m\",\r\n    \"display\": \"Last 48 hours\"\r\n  },\r\n  {\r\n    \"from\": \"now-7d/m\",\r\n    \"to\": \"now/m\",\r\n    \"display\": \"Last 7 days\"\r\n  },\r\n  {\r\n    \"from\": \"now-30d/m\",\r\n    \"to\": \"now/m\",\r\n    \"display\": \"Last 30 days\"\r\n  },\r\n  {\r\n    \"from\": \"now-60d/m\",\r\n    \"to\": \"now/m\",\r\n    \"display\": \"Last 60 days\"\r\n  },\r\n  {\r\n    \"from\": \"now-90d/m\",\r\n    \"to\": \"now/m\",\r\n    \"display\": \"Last 90 days\"\r\n  }\r\n]","timepicker:timeDefaults":"{\r\n  \"from\": \"now-1h/m\",\r\n  \"to\": \"now\"\r\n}"},"id":"2.11.1","migrationVersion":{"config":"7.9.0"},"references":[],"type":"config","updated_at":"2024-01-13T00:32:11.594Z","version":"WzQxMyw3XQ=="}
      {"exportedCount":1,"missingRefCount":0,"missingReferences":[]}
    path: /opt/elastiflow/elastiflow/advancedSettings.ndjson
  - content: |
      \v
      \s \r \m

      \d \t

      \n :: \4{eth0}
      _
    path: /etc/issue
  - content: |
      [Unit]
      Description=Docker Bootstrapper Service
      After=network.target

      [Service]
      Type=simple
      User=root
      WorkingDirectory=/opt/elastiflow
      ExecStartPre=/bin/bash -c 'while [ ! -f /var/lib/cloud/instance/boot-finished ]; do sleep 5; done'
      ExecStart=docker-compose up -d

      [Install]
      WantedBy=default.target
    path: /etc/systemd/system/docker-bootstrap.service
  - content: |
      {
        "userland-proxy": false
      }
    path: /etc/docker/daemon.json
mount_default_fields: [ None, None, "auto", "defaults,nofail", "0", "2" ]
!!@mounts@!!

# Additional mounts not  finished yet. Need to add formatting / partitioning, and configure for docker

manage_etc_hosts: true
manage_resolv_conf: true

resolv_conf:
  nameservers: [!!@NameServers@!!]
  searchdomains:
    - !!@DomainName@!!
  domain: !!@DomainName@!!

power_state:
  mode: reboot
  message: Provisioning finished, will reboot ...
  timeout: 15
'@  
    
<# -------------------------------------------------------- Include, Module, Variables ----------------------------------------------------------------------------- #>

# check if running hyper-v host version 8.0 or later
# Get-VMHostSupportedVersion https://docs.microsoft.com/en-us/powershell/module/hyper-v/get-vmhostsupportedversion?view=win10-ps
# or use vmms version: $vmms = Get-Command vmms.exe , $vmms.version. src: https://social.technet.microsoft.com/Forums/en-US/dce2a4ec-10de-4eba-a19d-ae5213a2382d/how-to-tell-version-of-hyperv-installed?forum=winserverhyperv
$vmms = Get-Command vmms.exe
if (([System.Version]$vmms.fileversioninfo.productversion).Major -lt 10) {
  Throw "Unsupported Hyper-V version. Minimum supported version for is Hyper-V 2016."
}

# pwsh (powershell core): try to load module hyper-v
if ($psversiontable.psversion.Major -ge 6) {
  Import-Module hyper-v -SkipEditionCheck
}

<# -------------------------------------------------------- Download binary tools from GSIT R2 storage ------------------------------------------------------------- #>

$wrk = "$env:programdata\gsit"
$tzip = "hv-prov-tools_a.zip"
$zipfile  = "$wrk\$tzip"
$unzip = "$wrk\hv-vm-provision"
$tzip_hash = 'C2D86B5DF1BADF00125B098CBCC1393CC4D54BA50176B8814C3F1AEE07935D30'
Invoke-Webrequest -URI "https://github.com/Luke-Williams9/hyperv-vm-provisioning/raw/master/hv-vm-provison-tools.zip" -outFile $zipfile
New-Item -ItemType Directory -Path $unzip -force | Out-Null
Expand-Archive $zipfile -Destinationpath $unzip -force

# ADK Download - https://www.microsoft.com/en-us/download/confirmation.aspx?id=39982
# You only need to install the deployment tools, src2: https://github.com/Studisys/Bootable-Windows-ISO-Creator
$oscdimgPath = Join-Path $unzip "tools\oscdimg\x64\oscdimg.exe"

# Download qemu-img from here: http://www.cloudbase.it/qemu-img-windows/
$qemuImgPath = Join-Path $unzip "tools\qemu-img\qemu-img.exe"

# Windows version of tar for extracting tar.gz files, src: https://github.com/libarchive/libarchive
$bsdtarPath = Join-Path $unzip "tools\bsdtar.exe"

# BCrypt dot Net, src: https://github.com/BcryptNet/bcrypt.net/releases - download and unzip the nupkg. its in there
$bCryptPath = Join-Path $unzip "tools\BCrypt.Net-Next.dll"

<# -------------------------------------------------------- Hardware validation ------------------------------------------------------------------------------------ #>

# RAM check - leave 1GB free on the host
$freeRAMbytes = (((Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize * 1KB) - (Get-Process | Measure-Object WorkingSet -Sum).Sum)
If ($VMMemoryStartupBytes -gt $freeRAMbytes) {
  Write-Warning "Requested memory ($VMMemoryStartupBytes) exceeds available host memory ($freeRAMbytes)."  
  Do {
    $VMMemoryStartupBytes -= 128MB
  } While ($VMMemoryStartupBytes -gt $freeRAMbytes)
}

# Also do a CPU check
$CPUs = Get-CimInstance Win32_ComputerSystem
If ($CPUs.NumberOfLogicalProcessors -lt $VMProcessorCount) {
  Write-Warning "Requested CPU count is higher than available logical processors (${CPUs.NumberOfLogicalProcessors}). Reducing count."
  $VMprocessorCount = $CPUs.NumberOfLogicalProcessors
}

# Time Zone
# If not specified, then we generate a basic 'etc/GMT' timezone from hosts time zone
if ($TimeZone -in $null, '') {
  $baseTZ = (Get-Timezone).BaseUTCoffset.hours
  if ($baseTZ -ge 0) {
    $tzPre = '-'
  } else {
    $tzPre = '+'
  }
  $TimeZone = 'Etc/GMT' + $tzPre + [string]([math]::abs($baseTZ))
}

<# -------------------------------------------------------- Generate VM parameters --------------------------------------------------------------------------------- #>

# Generate VM / Hostname if blank
If ($VMName -in $null, '') {
  $a = $env:computername
  If ($a -match '-') { 
    $prefix = $a.split('-')[0] 
  } Else { 
    $prefix = $a.substring(0,3) 
  }
  $VMName = $prefix + '-' + (Make-Random 6 -hex)
}
If ($VMHostName -in $null, '') {
  $VMHostname = $VMName
}
# Get host DNS info to use for default network configuration
$hostNetInfo = Get-DnsInfo

If ($NameServers -in $null, '') {
  $NameServers = $hostNetInfo.DnsServers
}

# If no hostname defined, generate a random hostname based on the hosts netbios prefix + some random string
If ($VMHostname -in $null, '') {
  $VMHostname = (((Get-CimInstance -ClassName Win32_ComputerSystem).Name).Substring(0,4) -replace '[-_]','') + (Make-Random 6)
}
 $searchDomain = $hostNetInfo.DomainSuffix.ToLower()
 $FQDN = $VMHostname.ToLower() + "." + $searchDomain

 if ($GuestAdminPassword -in $null, '') {
    #$GuestAdminPassword = 'Passw0rd'
    $GuestAdminPassword = Make-Random 8
    Write-Host "-------------- LOCAL ADMIN -----------------------"
    Write-Host "Username: $GuestAdminUsername"
    Write-Host "Password: $GuestAdminPassword"
    Write-Host ""

 }

$NetAutoconfig = ($NetAddress    -in $null,'') -and
                 ($NetNetmask    -in $null,'') -and
                 ($NetNetwork    -in $null,'') -and
                 ($NetGateway    -in $null,'') 

Write-Verbose "-------------- NETWORK CONFIGURATION ------------------"
Write-Verbose ""

if ($NetAutoconfig -eq $false) {
  If ( -Not $NetAddress) {
    Write-Error "No static IP address specified. Use -NetAddress to specify an IP address."
    Exit 1
  }

  $nSplit = $NetAddress.split('/')
  Switch ($nSplit.count) {
    {$_ -gt 2} {
      Write-Error "IP CIDR not valid...?"
      Write-Error $_
      Exit 1
    }
    {$_ -eq 2} {
      $netAddress = $nSplit[0]
      $netMaskbits = $nSplit[1]
    }
    {$_ -le 1} {
      $netMaskbits = '24'
    }
  }
  If ( -not $NetNetmask) {
    Write-Verbose "No subnet mask specified, assuming 255.255.255.0"
    $NetNetmask = '255.255.255.0'
  }

  If ( -not $NetNetGateway) {
    Write-Verbose "No gateway IP specified, assuming .1"
    $NetGateway = $NetAddress -replace '\.\d+$','.1'
  }

  Write-Verbose "VMStaticMacAddress: '$NetMacAddress'"
  Write-Verbose "NetInterface:     '$NetInterface'"
  Write-Verbose "NetAddress:       '$NetAddress'"
  Write-Verbose "NetNetmask:       '$NetNetmask'"
  Write-Verbose "NetNetmaskbits:   '$netMaskbits'"
  Write-Verbose "NetNetwork:       '$NetNetwork'"
  Write-Verbose "NetGateway:       '$NetGateway'"
  Write-Verbose ""
} else {
  Write-Verbose "DHCP"
}

# Instead of GUID, use 26 digit machine id suitable for BIOS serial number
# src: https://stackoverflow.com/a/67077483/1155121
# $vmMachineId = [Guid]::NewGuid().ToString()
$rSplat = @{
  Minimum = 1000000000000000 
  Maximum = 9999999999999999
}
$VmMachineId = "{0:####-####-####-####}-{1:####-####-##}" -f (Get-Random @rSplat),(Get-Random @rSplat)


# Java heap size for Opensearch - should be around 1/2 VM RAM
$javaHeap = [string]([math]::round(($VMMemoryStartupBytes/1MB)/2)) + 'm'

# Temp path
$tp = Join-Path $tempRoot "temp"
$tempPath = Join-Path $tp $vmMachineId
Remove-Item -path $tp -recurse -force -confirm:$false -ErrorAction SilentlyContinue
New-Item -ItemType Directory -path $tempPath -force | Out-Null
Write-Verbose "Using temp path: $tempPath"

<# -------------------------------------------------------- Cleanup old VM ----------------------------------------------------------------------------------------- #>

# Disabling this by default, since this script wil be in our Ninja tenant. just for safety yunno
# Delete the VM if it is around
$vm = Get-VM $VMName -ErrorAction 'SilentlyContinue'
if ($vm) { 
  #Cleanup-VM $VMName -Force:$Force 
  Throw "VM $VMName already exists. Cleanup-VM is commented out"
}

<# -------------------------------------------------------- Virtual Network ---------------------------------------------------------------------------------------- #>

# Make sure we have a virtual switch to connect to, if not, then error out before we do anything else
If ($virtualSwitchName -notin "",$null) {
    Write-Verbose "Connecting VMnet adapter to virtual switch '$virtualSwitchName'..."
} else {
  Write-Warning "No Virtual network switch given."
  $SwitchList = Get-VMSwitch | Where-Object SwitchType -eq 'External'
  Switch ($SwitchList.Count) {
    {$_ -gt 1} {
      $virtualSwitchName = ((Get-VM).NetworkAdapters.SwitchName | Group-Object | Sort-Object Count | Select-Object -last 1).name
      Write-Warning "Using the most frequently used vSwitch: $virtualSwitchName"  
    }
    1 {
      $virtualSwitchName = $SwitchList.Name
      Write-Warning "Using the only external vSwitch: $virtualSwitchName"
    }
    Default {
      Write-Warning "Attempting to use Default Switch"
      $virtualSwitchName = "Default Switch"
    }
  }
  if ( -not (Get-VMswitch -name $virtualSwitchName)) {
    Throw "Error using virtual switch $virtualSwitchName"
  }
}

<# -------------------------------------------------------- Distro data -------------------------------------------------------------------------------------------- #>

# Update this to the release of Image that you want
# But Azure images can't be used because the waagent is trying to find ephemeral disk
# and it's searching causing 20 / 40 minutes minutes delay for 1st boot
# https://docs.microsoft.com/en-us/troubleshoot/azure/virtual-machines/cloud-init-deployment-delay
# and also somehow causing at sshd restart in password setting task to stuck for 30 minutes.

$distro = [PSCustomObject] @{
  ImageOS = "ubuntu"
  ImageFileExtension  = "img"
  ImageHashFileName   = "SHA256SUMS"
  ImageManifestSuffix = "manifest"
  ImageDefaultVersion = "22"
  imageVersionTable = @{
    "22" = "jammy"
    "20" = "focal"
    "18" = "bionic"
  }
  ImageDownloadURLs = @{
    "22" = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
    "20" = "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img"
    "18" = "https://cloud-images.ubuntu.com/bionic/current/bionic-server-cloudimg-amd64.img"
  }
}
  
<# -------------------------------------------------------- Image URL and local path variables --------------------------------------------------------------------- #>

Write-Verbose "Selected distro:"
Write-Verbose ($distro | Format-List | Out-String)
$ImageFileExtension = $distro.ImageFileExtension
$ImageHashFileName = $distro.ImageHashFileName
$ImageManifestSuffix = $distro.ImageManifestSuffix
$downloadURL = $distro.ImageDownloadURLS.($distro.ImageDefaultVersion)
If ($ImageVersion) {
  If ($ImageVersion -match "^\w+$") {
    $imgv = ($distro.imageVersionTable.PSObject.properties | Where-Object {$_.Value -eq $ImageVersion}).name
    If ($imgv) {
      $ImageVersion = $imgv
    }   
  }
  Write-Verbose "Using image version: $ImageVersion"
  $downloadURL = $distro.ImageDownloadURLS.$ImageVersion
}

If ($downloadURL -in $null, '') {
  Throw "Error getting download URL"
  Exit 1
}

Write-Host "Download URL: $downloadURL"

# URL prefix may be http or https
$URLprefix = $downloadURL.split(':')[0] 
$B = $downloadURL.replace("${URLprefix}://",'').split('/')

$ImageFileName = $B[$B.count-1].replace(".$ImageFileExtension",'')
$ImageBaseURL = "${URLprefix}://" + ($B[(0..($B.count-2))] -join '/')
$ImageHashURL = $ImageBaseURL + '/' + $ImageHashFileName

Try   { $hvInfo = Get-VMHost }
Catch { Throw "Error getting VMHost info $_" }

# Set folders if not defined
if ($VMpath -in $null,'')  { $VMpath = $hvInfo.VirtualMachinePath }
if ($VHDpath -in $null,'') { $VHDpath = $hvInfo.VirtualHardDiskPath }
Foreach ($d in $VMpath, $VHDpath) { New-Item -ItemType Directory -Force -Path $d -ErrorAction SilentlyContinue | Out-Null }

<# -------------------------------------------------------- Metadata ----------------------------------------------------------------------------------------------- #>

# There is a documentation failure not mention needed dsmode setting:
# https://gist.github.com/Informatic/0b6b24374b54d09c77b9d25595cdbd47
# Only in special cloud environments its documented already:
# https://cloudinit.readthedocs.io/en/latest/topics/datasources/cloudsigma.html
# metadata for cloud-init

$metadata = @"
dsmode: local
instance-id: $($VmMachineId)
local-hostname: $($VMHostname)
"@

Write-Verbose "Metadata:"
Write-Verbose $metadata
Write-Verbose ""

<# -------------------------------------------------------- Create Network settings -------------------------------------------------------------------------------- #>

# Just use v2 configuration. we will mostly be using up to date linux images
# Azure:   https://cloudinit.readthedocs.io/en/latest/topics/datasources/azure.html
# NoCloud: https://cloudinit.readthedocs.io/en/latest/topics/datasources/nocloud.html
# with static network examples included

$NameServers = ((($NameServers  | Where-Object {$_ -notin '',$null}) -join ", "))
$searchDomain = ((($searchDomain | Where-Object {$_ -notin '',$null}) -join ", "))
$netV2 = @"
version: 2
renderer: networkd
ethernets:
  ${NetInterface}:
    dhcp4: no
    addresses:
      - ${NetAddress}/${Netmaskbits}
    nameservers:
      search: [${searchDomain}]
      addresses: [${NameServers}]
    routes:
      - to: default
        via: ${NetGateway}
"@
If ( -not $NetAutoconfig ) {
  Write-Verbose "Network autoconfig / DHCP disabled"
  Write-Verbose "NetworkConfig V2:"
  Write-Verbose $netV2
  $networkConfig = $netV2
}

<# -------------------------------------------------------- Create Userdata ---------------------------------------------------------------------------------------- #>

# Gonna still use Render-Template for userdata inside this script
# userdata for cloud-init, https://cloudinit.readthedocs.io/en/latest/topics/examples.html

$env_sshkeys = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJIFojWQgEyg1bfyn4ncMDGTBAcumQcPkOvIBqTAqKVQ luke@GS-RXLar"

$user_settings = @{
  createdDateStamp     = Get-Date -UFormat "%b/%d/%Y %T %Z"
  VMHostname           = $VMHostname
  FQDN                 = $FQDN
  TimeZone             = $TimeZone
  Locale               = $Locale
  GuestAdminUsername   = $GuestAdminUsername
  GuestAdminPassword   = $GuestAdminPassword
  ssh_keys             = '  - ' + ($env_sshkeys -join "`n    - ")
  docker_write_files   = $docker_write_files
  NameServers          = "'" + ($NameServers -join "', '") + "'"
  DomainName           = $hostNetInfo.DomainSuffix.ToLower()
  KeyboardLayout       = $KeyboardLayout
  Mounts               = ''
  JavaHeap             = $JavaHeap
  blumiraSensorInstall = $blumiraSensorInstall

}

If ($VMdataVol) {
  $user_settings.Mounts = "mounts:`n  - [ sdb, $VMdataVolMountPoint ]"
}

# Userdata is large, complex, and full of characters which can require escaping.
# For a monolithic script like this, Its best defined inside a single quote here-string, where nothing needs to be escaped.
# Render-Template will insert all the variables we need
$userdata = Render-Template -Template $userdata_template -Variables $user_settings

Write-Verbose "Userdata:"
Write-Verbose $userdata
Write-Verbose ""
Set-Content "debug-userdata.yml" "$userdata"

<# -------------------------------------------------------- Write all the files ------------------------------------------------------------------------------------ #>

# Make temp location for iso image
New-Item -ItemType Directory -Path "$($tempPath)\Bits" | Out-Null

# Set-Content syntax changed in powershell 6. Now it uses -AsByteStream. use -Encoding Byte for powershell 5
If ($PSVersionTable.PSVersion.Major -ge 6) {
  $cSplat = @{
    AsByteStream = $true
  }
} else {
  $cSplat = @{
    Encoding = 'Byte'
  }
}
Write-Verbose "Write metadata..."
Set-Content "$($tempPath)\Bits\meta-data" ([byte[]][char[]] "$metadata") @cSplat
If ($NetAutoconfig -eq $false) {
  Write-Verbose "Write network-config"
  Set-Content "$($tempPath)\Bits\network-config" ([byte[]][char[]] "$networkconfig") @cSplat
}
Write-Verbose "Write user-data..."
#Set-Content "$($tempPath)\Bits\user-data" ([byte[]][char[]] "$userdata") @cSplat
Set-Content "$tempPath\Bits\user-data" "$userdata" #@cSplat


# Create meta data ISO image, src: https://cloudinit.readthedocs.io/en/latest/topics/datasources/nocloud.html
# both azure and nocloud support same cdrom filesystem 
# https://github.com/canonical/cloud-init/blob/606a0a7c278d8c93170f0b5fb1ce149be3349435/cloudinit/sources/DataSourceAzure.py#L1972

$metaDataIso = "$($VHDpath)\$($VMName)-metadata.iso"
Write-Host "Creating metadata iso for VM provisioning"
Write-Verbose "Filename: $metaDataIso"
cleanupFile $metaDataIso

$oscdimgSplat = @{
  FilePath = $oscdimgPath
  ArgumentList = "`"$($tempPath)\Bits`"","`"$metaDataIso`"","-lCIDATA","-d","-n" 
  Wait = $true
  NoNewWindow = $true
  RedirectStandardOutput = "$($tempPath)\oscdimg.log"
}
Start-Process @oscdimgSplat

If ( -not (test-path "$metaDataIso") ) {
  Throw "Error creating metadata iso"
}
Write-Verbose "Metadata iso written"
Write-Host -ForegroundColor Green " Done."

<# -------------------------------------------------------- Download and parse distro checksum file ---------------------------------------------------------------- #>

# Storage path for base images
$ImageCachePath = Join-Path $tempRoot "BaseImages"
New-Item -ItemType Directory -Path $ImageCachePath -Force | Out-Null
$imageFilenameExt = "${ImageFileName}.${ImageFileExtension}"
# Full path + filename for downloaded image
$ImageFilePath = Join-Path $ImageCachePath $ImageFileNameExt

# Intermediate path to unzipped image - it should go into a newly created folder which contains nothing else
$imageUnzipPath = Join-Path $tempPath "imageTemp"
New-Item -ItemType Directory -Path $imageUnzipPath -Force | Out-Null

Try   { $checksum = Fetch-Checksums $ImageHashURL | Where-Object { $_.filename -eq $imageFilenameExt } }
Catch {
  If ($skipChecksum) {
    Write-Warning "Error fetching checksums from $imageHashURL, but SkipChecksum specified so we'll continue"
  } Else {
    Throw "Error fetching checksums from $imageHashURL $_" 
  }
}
Switch -Wildcard ($ImageHashFilename) {
  '*SHA256*' { $hashAlgo = "SHA256" }
  '*SHA512*' { $hashAlgo = "SHA512" }
  Default    { Throw "$ImageHashFilename hashing algorithm not supported." }
}

<# -------------------------------------------------------- Download and verify install image ---------------------------------------------------------------------- #>

# If image of same name is present, check If checksum matches. Delete If not matched
If (Test-Path $ImageFilePath) {
  Write-Verbose "Found cached image: $ImageFilePath"
  $c = (Get-FileHash $ImageFilePath -Algorithm $hashAlgo).Hash
  If ($c -eq $checksum.checksum) {
    Write-Verbose "Checksum matches - Using cached image"
  } Else {
    Write-Verbose "Checksum does not match - Redownloading image"
    Remove-Item $ImageFilePath -Confirm:$false
  }
}

# If image not found, download
If ( -not (Test-Path $ImageFilePath) ) {
  Write-Verbose "Downloading image: $downloadURL"
  Invoke-WebRequest $downloadURL -OutFile $ImageFilePath -UseBasicParsing
}

# Check If checksum matches, If it fails, then error out
$c = (Get-FileHash $ImageFilePath -Algorithm $hashAlgo).Hash
If ( $c -ne $checksum.checksum) {
  Throw "Checksum mismatch on newly downloaded file $($ImageFilePath) `r`n$($checksum.Checksum)`r`n$c" 
}

<# -------------------------------------------------------- Extract image ------------------------------------------------------------------------------------------ #>

# Delete an existing VHD and re-extract it from the verified image
$imageVHD = "${ImageCachePath}\${ImageFileName}-temp.vhd"
$imageVHDfinal = "${ImageCachePath}\${ImageFileName}.vhd"

Remove-Item $imageVHDfinal -confirm:$false -errorAction SilentlyContinue | Out-Null

Switch ($ImageFileExtension) {
  {$_ -in 'tar.gz','tar.xz'} {
    Write-Host 'Expanding archive using bsdtar...' 
    # using bsdtar - src: https://github.com/libarchive/libarchive/
    # src: https://unix.stackexchange.com/a/23746/353700
    $tarSplat = @{
      FilePath = $bsdtarPath
      ArgumentList = '-x','-C', "`"$($imageUnzipPath)`"",'-f', "`"$ImageFilePath`""
      Wait = $true 
      NoNewWindow = $true
      RedirectStandardOutput = "$($tempPath)\bsdtar.log"
    }

    Start-Process @tarSplat
  }
  'zip' { 
    Expand-Archive $ImageFilePath -DestinationPath $imageUnzipPath -Force
  }
  'img' {
    # Put it in the intermediate folder even though it doesn't need to be unzipped
    Copy-Item $ImageFilePath -Destination $imageUnzipPath -Force
  }
  default { 
    Throw "Unsupported image in archive - $ImageFileExtension"
   }
}

<# -------------------------------------------------------- Convert Image to VHD ----------------------------------------------------------------------------------- #>

# There should be only a single image file in $imageUnzipPath
$fileExpanded = (Get-ChildItem $imageUnzipPath).fullname

Switch -Wildcard ($fileExpanded) {
  '*.vhd' {
    Copy-Item -path $fileExpanded -Destination "$ImageVHD"  
  }
  '*.raw' {
    Write-Host "qemu-img info for source untouched cloud image: "
    & $qemuImgPath info "$fileExpanded"
    Write-Verbose "qemu-img convert to vhd"
    Write-Verbose "$qemuImgPath convert -f raw $fileExpanded -O vpc $($imageVHD)"
    & $qemuImgPath convert -f raw "$fileExpanded" -O vpc "$($imageVHD)"
  }
  '*img' {
    Write-Host "qemu-img info for source untouched cloud image: "
    & $qemuImgPath info "$fileExpanded"
    Write-Verbose "qemu-img convert to vhd"
    Write-Verbose "$qemuImgPath convert -f qcow2 $fileExpanded -O vpc $($ImageVHD)"
    & $qemuImgPath convert -f qcow2 "$fileExpanded" -O vpc "$($ImageVHD)"
  }
  default {
    Throw "Unsupported disk image extracted."
  }
}
# Remove intermediate image
Remove-Item "$fileExpanded" -force -confirm:$false

Write-Host -ForegroundColor Green " Done."

<# -------------------------------------------------------- Convert fixed VHD to dynamic --------------------------------------------------------------------------- #>

Write-Host 'Convert VHD fixed to VHD dynamic...' 
Try {
  Convert-VHD -Path "$imageVHD" -DestinationPath "$imageVHDfinal" -VHDType Dynamic -DeleteSource
  Write-Host -ForegroundColor Green " Done."
} 
Catch {
  Write-Warning $_
  Write-Warning "Failed to convert the disk using 'Convert-VHD', falling back to qemu-img... "
  Write-Host "qemu-img info for source untouched cloud image: "
  & $qemuImgPath info "$($ImageVHD)"
  Write-Verbose "qemu-img convert to vhd"
  & $qemuImgPath convert "$($ImageVHD)" -O vpc -o subformat=dynamic "$($ImageVHDfinal)"
  
  # remove source image after conversion
  Remove-Item $ImageVHD -force
  Write-Host -ForegroundColor Green " Done."
}

Resize-VHD -path $ImageVHDfinal -SizeBytes $VHDSizeBytes

<# -------------------------------------------------------- Deploy VHD --------------------------------------------------------------------------------------------- #>

# File path for to-be provisioned VHD
$VMDiskPath = "$($VHDpath)\$($VMName).vhd"
If ($VMGeneration -eq 2) {
  $VMDiskPath = "$($VHDpath)\$($VMName).vhdx"
}
cleanupFile $VMDiskPath

# Prepare VHD... (could also use copy)
Write-Host "Prepare virtual disk..." 
Try {
  # block size bytes per recommendation https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/best-practices-for-running-linux-on-hyper-v
  Convert-VHD -Path $imageVHDfinal -DestinationPath $VMDiskPath -VHDType Dynamic -BlockSizeBytes 1MB
  Write-Host -ForegroundColor Green " Done."
  If ($VHDSizeBytes -and ($VHDSizeBytes -gt 30GB)) {
    Write-Host "Resize VHD to $([int]($VHDSizeBytes / 1024 / 1024 / 1024)) GB..." 
    Resize-VHD -Path $VMDiskPath -SizeBytes $VHDSizeBytes
    Write-Host -ForegroundColor Green " Done."
  }
} 
Catch {
  Write-Warning "Failed to convert and resize, will just copy it ..."
  Copy-Item $ImageVHDfinal -Destination $VMDiskPath
}

<# -------------------------------------------------------- Create Virtual Machine --------------------------------------------------------------------------------- #>

# Create new virtual machine and start it
$vmSplat = @{
  Name = $VMName
  MemoryStartupBytes = $VMMemoryStartupBytes
  Path = "$VMpath"
  VHDPath = "$VMDiskPath"
  Generation = $VMGeneration
  BootDevice = 'VHD'
  Version = $VMVersion
}
Write-Host "Create VM..." 
$vm = New-VM @vmSplat
$vm | FL | Out-String
Set-VMProcessor -VMName $VMName -Count $VMProcessorCount
Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $VMDynamicMemoryEnabled
If ($VMDynamicMemoryEnabled) {
  Set-VMMemory -VMName $VMName -MaximumBytes $VMMaximumBytes -MinimumBytes $VMMinimumBytes
}

# Data volume
# ------------------ Need to error handle New-VHD for when a VHD of the same name exists
If ($VMDataVol) {
  $vSplat = @{
    Path = "$VHDpath\$VMName-data.vhdx"
    SizeBytes = $VMdataVolSizeBytes
    Dynamic = $true
  }
  New-VHD @vSplat
  Add-VMHardDiskDrive -VMName $VMName -Path $vSplat.Path

}
# make sure VM has DVD drive needed for provisioning
If ( -not (Get-VMDvdDrive -VMName $VMName)) {
  Add-VMDvdDrive -VMName $VMName
}
Set-VMDvdDrive -VMName $VMName -Path "$metaDataIso"
Connect-VMNetworkAdapter -VMName $VMName -SwitchName "$virtualSwitchName"



If ($NetMacAddress -notin $null,'') {
  Write-Verbose "Setting static MAC address '$NetMacAddress' on VMnet adapter..."
  Set-VMNetworkAdapter -VMName $VMName -StaticMacAddress $NetMacAddress
} Else {
  Write-Verbose "Using default dynamic MAC address asignment."
}

Get-VMNetworkAdapter -VMName $VMName
$VMNetworkAdapterName = $VMNetworkAdapter.Name
If ((([int]$VMVlanID -ne 0) -or ([int]$VMNativeVlanID -ne 0)) -and ($VMAllowedVlanIDList -notin $null,'')) {
  If (([int]($VMNativeVlanID) -ne 0) -and ($VMAllowedVlanIDList -notin $null,'')) {
    Write-Host "Setting native Vlan ID $VMNativeVlanID with trunk Vlan IDs '$VMAllowedVlanIDList'"
    Write-Host "on virtual network adapter '$VMNetworkAdapterName'..."
    $trunkSplat = @{
      name = $VMNameCatch 
      VMNetworkAdapterName = "$VMNetworkAdapterName"
      Trunk = $true
      NativeVlanID = $VMNativeVlanID
      AllowedVlanIDList = $VMAllowedVlanIDList
    }
    Set-VMNetworkAdapterVlan @trunkSplat
  } Else {
    $vidSplat = @{
      name = $VMName
      VMNetworkAdapterName = "$VMNetworkAdapterName" 
      Access = $true 
      VlanId = $VMVlanID
    }
    Write-Host "Setting Vlan ID $VMVlanID on virtual network adapter '$VMNetworkAdapterName'..."
    Set-VMNetworkAdapterVlan @vidSplat
  }
} Else {
  Write-Verbose "Let virtual network adapter '$VMNetworkAdapterName' untagged."
}

If ($VMVMQ) {
    Write-Host "Enable Virtual Machine Queue (100)... " 
    Set-VMNetworkAdapter -VMName $VMName -VmqWeight 100
    Write-Host -ForegroundColor Green " Done."
}

If ($VMDhcpGuard) {
    Write-Host "Enable DHCP Guard... " 
    Set-VMNetworkAdapter -VMName $VMName -DhcpGuard On
    Write-Host -ForegroundColor Green " Done."
}

If ($VMRouterGuard) {
    Write-Host "Enable Router Guard... " 
    Set-VMNetworkAdapter -VMName $VMName -RouterGuard On
    Write-Host -ForegroundColor Green " Done."
}

If ($VMAllowTeaming) {
    Write-Host "Enable Allow Teaming... " 
    Set-VMNetworkAdapter -VMName $VMName -AllowTeaming On
    Write-Host -ForegroundColor Green " Done."
}

If ($VMPassthru) {
    Write-Host "Enable Passthru... " 
    Set-VMNetworkAdapter -VMName $VMName -Passthru
    Write-Host -ForegroundColor Green " Done."
}

If ($VMMacAddressSpoofing) {
  Write-Verbose "Enable MAC address Spoofing on VMnet adapter..."
  Set-VMNetworkAdapter -VMName $VMName -MacAddressSpoofing On
} Else {
  Write-Verbose "Using default dynamic MAC address asignment."
}

If ($VMExposeVirtualizationExtensions) {
  Write-Host "Expose Virtualization Extensions to Guest ..."
  Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions $true
  Write-Host -ForegroundColor Green " Done."
}

# hyper-v gen2 specific features
If ($VMGeneration -eq 2) {
  Write-Verbose "Setting secureboot for Hyper-V Gen2..."
  # configure secure boot, src: https://www.altaro.com/hyper-v/hyper-v-2016-support-linux-secure-boot/
  Set-VMFirmware -VMName $VMName -EnableSecureBoot On -SecureBootTemplateId ([guid]'272e7447-90a4-4563-a4b9-8e4ab00526ce')

  If ($(Get-VMHost).EnableEnhancedSessionMode -eq $true) {
    # Ubuntu 18.04+ supports enhanced session and so Debian 10/11
    Write-Verbose "Enable enhanced session mode..."
    Set-VM -VMName $VMName -EnhancedSessionTransportType HvSocket
  } Else {
    Write-Verbose "Enhanced session mode not enabled because host has not activated support for it."
  }

  # For copy&paste service (hv_fcopy_daemon) between host and guest we need also this
  # guest service interface activation which has sadly language dependent setup:
  # PS> Enable-VMIntegrationService -VMName $VMName -Name "Guest Service Interface"
  # PS> Enable-VMIntegrationService -VMName $VMName -Name "Gastdienstschnittstelle"
  # https://administrator.de/forum/hyper-v-cmdlet-powershell-sprachproblem-318175.html
  Get-VMIntegrationService -VMName $VMName | Where-Object {$_.Name -match 'Gastdienstschnittstelle|Guest Service Interface'} | Enable-VMIntegrationService
}

# disable automatic checkpoints, https://github.com/hashicorp/vagrant/issues/10251#issuecomment-425734374
Set-VM -VMName $VMName -AutomaticCheckpointsEnabled $false

Write-Host -ForegroundColor Green " Done."

# redirect com port to pipe for VM serial output, src: https://superuser.com/a/1276263/145585
# $vm | Set-VMComPort -Path \\.\pipe\$VMName-com1 -Number 1
# Write-Verbose "Serial connection: \\.\pipe\$VMName-com1"

# enable guest integration services (could be used for Copy-VMFile)
Get-VMIntegrationService -VMName $VMName | Where-Object Name -match 'guest' | Enable-VMIntegrationService

# Clean up temp directory
Foreach ($d in $tempPath, $imageVHDfinal) { Remove-Item $d -Recurse -Force }

# Make checkpoint when debugging https://stackoverflow.com/a/16297557/1155121
If ($PSBoundParameters.Debug -eq $true) {
  # make VM snapshot before 1st run
  Write-Host "Creating checkpoint..." 
  Checkpoint-VM -Name $VMName -SnapshotName Initial
  Write-Host -ForegroundColor Green " Done."
}

If ($noStart) {
  Write-Host "VM ready for you to start"
} else {
  Write-Host "Starting VM..." 
  Start-VM $VMName
  Write-Host -ForegroundColor Green " Done."
}

Write-Host "Done"