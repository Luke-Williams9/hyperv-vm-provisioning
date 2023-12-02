# this shit doesn't work yet
<#
.SYNOPSIS
  Provision Cloud images on Hyper-V
.EXAMPLE
  PS C:\> .\New-HyperVCloudImageVM.ps1 -VMProcessorCount 2 -VMMemoryStartupBytes 2GB -VHDSizeBytes 60GB -VMName "azure-1" -ImageVersion "20.04" -VirtualSwitchName "SW01" -VMGeneration 2
  PS C:\> .\New-HyperVCloudImageVM.ps1 -VMProcessorCount 2 -VMMemoryStartupBytes 2GB -VHDSizeBytes 8GB -VMName "debian11" -ImageVersion 11 -virtualSwitchName "External Switch" -VMGeneration 2 -GuestAdminUsername admin -GuestAdminPassword admin -VMMachine_StoragePath "D:\Hyper-V\" -NetAddress 192.168.188.12 -NetNetmask 255.255.255.0 -NetGateway 192.168.188.1 -NameServers "192.168.188.1"
  It should download cloud image and create VM, please be patient for first boot - it could take 10 minutes
  and requires network connection on VM
.NOTES
  Original script: https://blogs.msdn.microsoft.com/virtual_pc_guy/2015/06/23/building-a-daily-ubuntu-image-for-hyper-v/

  This projected Forked from: https://github.com/schtritoff/hyperv-vm-provisioning


  References:
  - https://git.launchpad.net/cloud-init/tree/cloudinit/sources/DataSourceAzure.py
  - https://github.com/Azure/azure-linux-extensions/blob/master/script/ovf-env.xml
  - https://cloudinit.readthedocs.io/en/latest/topics/datasources/azure.html
  - https://github.com/fdcastel/Hyper-V-Automation
  - https://bugs.launchpad.net/ubuntu/+source/walinuxagent/+bug/1700769
  - https://gist.github.com/Informatic/0b6b24374b54d09c77b9d25595cdbd47
  - https://www.neowin.net/news/canonical--microsoft-make-azure-tailored-linux-kernel/
  - https://www.altaro.com/hyper-v/powershell-script-change-advanced-settings-hyper-v-virtual-machines/

  Recommended: choco install putty -y
#>

#requires -Modules Hyper-V
#requires -RunAsAdministrator

param (
  [string] $VMName = "CloudVm",
  [int]    $VMGeneration = 1, # create gen1 hyper-v machine because of portability to Azure (https://docs.microsoft.com/en-us/azure/virtual-machines/windows/prepare-for-upload-vhd-image)
  [int]    $VMProcessorCount = 2,
  [bool]   $VMDynamicMemoryEnabled = $false,
  [uint64] $VMMemoryStartupBytes = 1024MB,
  [uint64] $VMMinimumBytes = $VMMemoryStartupBytes,
  [uint64] $VMMaximumBytes = $VMMemoryStartupBytes,
  [uint64] $VHDSizeBytes = 16GB,
  [string] $VirtualSwitchName = $null,
  [string] $VMVlanID = $null,
  [string] $VMNativeVlanID = $null,
  [string] $VMAllowedVlanIDList = $null,
  [switch] $VMVMQ = $false,
  [switch] $VMDhcpGuard = $false,
  [switch] $VMRouterGuard = $false,
  [switch] $VMPassthru = $false,
  #[switch] $VMMinimumBandwidthAbsolute = $null,
  #[switch] $VMMinimumBandwidthWeight = $null,
  #[switch] $VMMaximumBandwidth = $null,
  [switch] $VMMacAddressSpoofing = $false,
  [switch] $VMExposeVirtualizationExtensions = $false,
  [string] $VMVersion = "8.0", # version 8.0 for hyper-v 2016 compatibility , check all possible values with Get-VMHostSupportedVersion
  [string] $VMHostname = $VMName,
  [string] $VMMachine_StoragePath = $null, # if defined setup machine path with storage path as subfolder
  [string] $VMMachinePath = $null, # if not defined here default Virtal Machine path is used
  [string] $VMStoragePath = $null, # if not defined here Hyper-V settings path / fallback path is set below
  [bool]   $ConvertImageToNoCloud = $false, # could be used for other image types that do not support NoCloud, not just Azure
  [bool]   $ImageTypeAzure = $false,
  [string] $DomainName = $null, # Set this automatically based on the hosts domain #########################################
  [string] $VMStaticMacAddress = $null,
  [string] $NetInterface = "eth0",
  [string] $NetAddress = $null,
  [string] $NetNetmask = $null,
  [string] $NetNetwork = $null,
  [string] $NetGateway = $null,
  [array]  $NameServers = @('1.1.1.2','1.0.0.2'), # Set this to the gateway by default?   ############################################
  [string] $NetConfigType = "ENI-file", # ENI, v1, v2, ENI-file, dhclient
  [string] $KeyboardLayout = "us", # 2-letter country code, for more info https://wiki.archlinux.org/title/Xorg/Keyboard_configuration
  [string] $KeyboardModel, # default: "pc105"
  [string] $KeyboardOptions, # example: "compose:rwin"
  [string] $Locale = "en_US", # "en_US.UTF-8",
  [string] $TimeZone = "UTC", # UTC or continental zones of IANA DB like: Europe/Berlin
  [string] $CloudInitPowerState = "reboot", # poweroff, halt, or reboot , https://cloudinit.readthedocs.io/en/latest/reference/modules.html#power-state-change
  [string] $CustomUserDataYamlFile,
  [string] $GuestAdminUsername = "admin",
  [string] $GuestAdminPassword = "Passw0rd",
  [string] $GuestAdminSshPubKey,
  [string] $imageOS = 'debian',
  [string] $ImageVersion = "12", # $ImageName ="focal" # 20.04 LTS , $ImageName="bionic" # 18.04 LTS
  [string] $ImageRelease = "release", # default option is get latest but could be fixed to some specific version for example "release-20210413"
  [string] $ImageBaseUrl = "http://cloud-images.ubuntu.com/releases", # alternative https://mirror.scaleuptech.com/ubuntu-cloud-images/releases
  [bool]   $BaseImageCheckForUpdate = $true, # check for newer image at Distro cloud-images site
  [bool]   $BaseImageCleanup = $true, # delete old vhd image. Set to false if using (TODO) differencing VHD
  [switch] $ShowSerialConsoleWindow = $false,
  [switch] $ShowVmConnectWindow = $false,
  [switch] $Force = $false,
  [switch] $userDataTest = $false
)
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
              $line = $line -replace "!!@$var@!!", $Variables[$var]
          } else {
              # If variable not found or is null, comment out the line with preserved indentation
              $leadingWhitespace = $line -replace '^(\s*).*$','$1'
              $line = $leadingWhitespace + $comment + ($line.trim() -replace $regex, '')
              break  # No need to check further if one variable in the line is null or not found
          }
      }

      $templateContent[$i] = $line
  }

  return $templateContent -join "`n"
}

 # Helper function for no error file cleanup
Function cleanupFile ([string]$file) {
  if (test-path $file) {
    Remove-Item $file -force
  }
}

# ADK Download - https://www.microsoft.com/en-us/download/confirmation.aspx?id=39982
# You only need to install the deployment tools, src2: https://github.com/Studisys/Bootable-Windows-ISO-Creator
#$oscdimgPath = "C:\Program Files (x86)\Windows Kits\8.1\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
$oscdimgPath = Join-Path $PSScriptRoot "tools\oscdimg\x64\oscdimg.exe"

# Download qemu-img from here: http://www.cloudbase.it/qemu-img-windows/
$qemuImgPath = Join-Path $PSScriptRoot "tools\qemu-img\qemu-img.exe"

# Windows version of tar for extracting tar.gz files, src: https://github.com/libarchive/libarchive
$bsdtarPath = Join-Path $PSScriptRoot "tools\bsdtar.exe"


if ($userDataTest) {
  $verbose = $true
}

$NetAutoconfig = ($NetAddress         -in $null,'') -and
                  ($NetNetmask         -in $null,'') -and
                  ($NetNetwork         -in $null,'') -and
                  ($NetNetGateway      -in $null,'') -and
                  ($NetNetmask         -in $null,'') -and
                  ($VMStaticMacAddress -in $null,'')

if ($NetAutoconfig -eq $false) {
  Write-Verbose "Given Network configuration - no checks done in script:"
  Write-Verbose "VMStaticMacAddress: '$VMStaticMacAddress'"
  Write-Verbose "NetInterface:     '$NetInterface'"
  Write-Verbose "NetAddress:       '$NetAddress'"
  Write-Verbose "NetNetmask:       '$NetNetmask'"
  Write-Verbose "NetNetwork:       '$NetNetwork'"
  Write-Verbose "NetGateway:       '$NetGateway'"
  Write-Verbose ""
}

# default error action
$ErrorActionPreference = 'Stop'

# pwsh (powershell core): try to load module hyper-v
if ($psversiontable.psversion.Major -ge 6) {
  Import-Module hyper-v -SkipEditionCheck
}

# check if verbose is present, src: https://stackoverflow.com/a/25491281/1155121
$verbose = $VerbosePreference -ne 'SilentlyContinue'

# check if running hyper-v host version 8.0 or later
# Get-VMHostSupportedVersion https://docs.microsoft.com/en-us/powershell/module/hyper-v/get-vmhostsupportedversion?view=win10-ps
# or use vmms version: $vmms = Get-Command vmms.exe , $vmms.version. src: https://social.technet.microsoft.com/Forums/en-US/dce2a4ec-10de-4eba-a19d-ae5213a2382d/how-to-tell-version-of-hyperv-installed?forum=winserverhyperv
$vmms = Get-Command vmms.exe
if (([System.Version]$vmms.fileversioninfo.productversion).Major -lt 10) {
  throw "Unsupported Hyper-V version. Minimum supported version for is Hyper-V 2016."
}



$FQDN = $VMHostname.ToLower() + "." + $DomainName.ToLower()
# Instead of GUID, use 26 digit machine id suitable for BIOS serial number
# src: https://stackoverflow.com/a/67077483/1155121
# $vmMachineId = [Guid]::NewGuid().ToString()
$VmMachineId = "{0:####-####-####-####}-{1:####-####-##}" -f (Get-Random -Minimum 1000000000000000 -Maximum 9999999999999999),(Get-Random -Minimum 1000000000 -Maximum 9999999999)
$tempPath = [System.IO.Path]::GetTempPath() + $vmMachineId
mkdir -Path $tempPath | out-null
Write-Verbose "Using temp path: $tempPath"




# Make sure we have a virtual switch to connect to, if not, then error out before we do anything else
If ($virtualSwitchName -notin "",$null) {
  Write-Verbose "Connecting VMnet adapter to virtual switch '$virtualSwitchName'..."
} else {
  Write-Warning "No Virtual network switch given."
  $SwitchList = Get-VMSwitch | Select-Object Name
  If ($SwitchList.Count -eq 1 ) {
    Write-Warning "Using single Virtual switch found: '$($SwitchList.Name)'"
    $virtualSwitchName = $SwitchList.Name
  } elseif (Get-VMSwitch | Select-Object Name | Select-String "Default Switch") {
    Write-Warning "Multiple Switches found; using found 'Default Switch'"
    $virtualSwitchName = "Default Switch"
  }
}

If ($virtualSwitchName -in "",$null) {
  Write-Warning "No Virtual network switch given and could not automatically selected."
  Write-Warning "Please use parameter -virtualSwitchName 'Switch Name'."
  exit 1
}

# Update this to the release of Image that you want
# But Azure images can't be used because the waagent is trying to find ephemeral disk
# and it's searching causing 20 / 40 minutes minutes delay for 1st boot
# https://docs.microsoft.com/en-us/troubleshoot/azure/virtual-machines/cloud-init-deployment-delay
# and also somehow causing at sshd restart in password setting task to stuck for 30 minutes.

<#
$selectedDistro = $images.$imageOS
if ( -not $selectedDistro) {
  throw "Unsupported distro: $imageOS"
  exit 1
}
$imageVersionName = $selectedDistro.versionTable.$imageVersion
$imageUrlRoot = $selectedDistro.imageBaseUrl + '/' + $imageVersionName + '/' + $selectedDistro.imageRelease
$imageFileName = "$imageOS-$imageVersion" + $selectedDistro.imageSuffix
$imageManifestSuffix = $selectedDistro.imageManifestSuffix

#>

Switch ($ImageVersion) {
  "18.04" {
    $_ = "bionic"
    $ImageVersion = "18.04"
  }
  "bionic" {
    $ImageOS = "ubuntu"
    $ImageVersionName = "bionic"
    $ImageVersion = "18.04"
    $ImageRelease = "release" # default option is get latest but could be fixed to some specific version for example "release-20210413"
    $ImageBaseUrl = "http://cloud-images.ubuntu.com/releases" # alternative https://mirror.scaleuptech.com/ubuntu-cloud-images/releases
    $ImageUrlRoot = "$ImageBaseUrl/$ImageVersionName/$ImageRelease/" # latest
    $ImageFileName = "$ImageOS-$ImageVersion-server-cloudimg-amd64"
    $ImageFileExtension = "img"
    # Manifest file is used for version check based on last modified HTTP header
    $ImageHashFileName = "SHA256SUMS"
    $ImageManifestSuffix = "manifest"
  }
  "20.04" {
    $_ = "focal"
    $ImageVersion = "20.04"
  }
  "focal" {
    $ImageOS = "ubuntu"
    $ImageVersionName = "focal"
    $ImageVersion = "20.04"
    $ImageRelease = "release" # default option is get latest but could be fixed to some specific version for example "release-20210413"
    $ImageBaseUrl = "http://cloud-images.ubuntu.com/releases" # alternative https://mirror.scaleuptech.com/ubuntu-cloud-images/releases
    $ImageUrlRoot = "$ImageBaseUrl/$ImageVersionName/$ImageRelease/" # latest
    $ImageFileName = "$ImageOS-$ImageVersion-server-cloudimg-amd64"
    $ImageFileExtension = "img"
    # Manifest file is used for version check based on last modified HTTP header
    $ImageHashFileName = "SHA256SUMS"
    $ImageManifestSuffix = "manifest"
  }
  "22.04" {
    $_ = "jammy"
    $ImageVersion = "22.04"
  }
  "jammy" {
    $ImageOS = "ubuntu"
    $ImageVersionName = "jammy"
    $ImageVersion = "22.04"
    $ImageRelease = "release" # default option is get latest but could be fixed to some specific version for example "release-20210413"
    $ImageBaseUrl = "http://cloud-images.ubuntu.com/releases" # alternative https://mirror.scaleuptech.com/ubuntu-cloud-images/releases
    $ImageUrlRoot = "$ImageBaseUrl/$ImageVersionName/$ImageRelease/" # latest
    $ImageFileName = "$ImageOS-$ImageVersion-server-cloudimg-amd64"
    $ImageFileExtension = "img"
    # Manifest file is used for version check based on last modified HTTP header
    $ImageHashFileName = "SHA256SUMS"
    $ImageManifestSuffix = "manifest"
  }
  "22.04-azure" {
    $_ = "jammy-azure"
    $ImageVersion = "22.04-azure"
  }
  "jammy-azure" {
    $ImageTypeAzure = $true
    $ConvertImageToNoCloud = $true
    $ImageOS = "ubuntu"
    #$ImageVersion = "22.04"
    #$ImageVersionName = "jammy"
    $ImageRelease = "release" # default option is get latest but could be fixed to some specific version for example "release-20210413"
    # https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64-azure.vhd.tar.gz
    $ImageBaseUrl = "http://cloud-images.ubuntu.com/releases" # alternative https://mirror.scaleuptech.com/ubuntu-cloud-images/releases
    $ImageUrlRoot = "$ImageBaseUrl/jammy/$ImageRelease/" # latest
    $ImageFileName = "$ImageOS-22.04-server-cloudimg-amd64-azure" # should contain "vhd.*" version
    $ImageFileExtension = "vhd.tar.gz" # or "vhd.zip" on older releases
    # Manifest file is used for version check based on last modified HTTP header
    $ImageHashFileName = "SHA256SUMS"
    $ImageManifestSuffix = "vhd.manifest"
  }
  "10" {
    $_ = "buster"
    $ImageVersion = "10"
  }
  "buster" {
    $ImageOS = "debian"
    $ImageVersionName = "buster"
    $ImageRelease = "latest" # default option is get latest but could be fixed to some specific version for example "release-20210413"
    # http://cloud.debian.org/images/cloud/buster/latest/debian-10-azure-amd64.tar.xz
    $ImageBaseUrl = "http://cloud.debian.org/images/cloud"
    $ImageUrlRoot = "$ImageBaseUrl/$ImageVersionName/$ImageRelease/"
    $ImageFileName = "$ImageOS-$ImageVersion-genericcloud-amd64" # should contain "vhd.*" version
    $ImageFileExtension = "tar.xz" # or "vhd.tar.gz" on older releases
    # Manifest file is used for version check based on last modified HTTP header
    $ImageHashFileName = "SHA512SUMS"
    $ImageManifestSuffix = "json"
  }
  "11" {
    $_ = "bullseye"
    $ImageVersion = "11"
  }
  "bullseye" {
    $ImageOS = "debian"
    $ImageVersionName = "bullseye"
    $ImageRelease = "latest" # default option is get latest but could be fixed to some specific version for example "release-20210413"
    # http://cloud.debian.org/images/cloud/bullseye/latest/debian-11-azure-amd64.tar.xz
    $ImageBaseUrl = "http://cloud.debian.org/images/cloud"
    $ImageUrlRoot = "$ImageBaseUrl/$ImageVersionName/$ImageRelease/"
    $ImageFileName = "$ImageOS-$ImageVersion-genericcloud-amd64" # should contain "raw" version
    $ImageFileExtension = "tar.xz" # or "vhd.tar.gz" on older releases
    # Manifest file is used for version check based on last modified HTTP header
    $ImageHashFileName = "SHA512SUMS"
    $ImageManifestSuffix = "json"
  }
  "12" {
    $_ = "bookworm"
    $ImageVersion = "12"
  }
  "bookworm" {
    $ImageOS = "debian"
    $ImageVersionName = "bookworm"
    $ImageRelease = "latest" # default option is get latest but could be fixed to some specific version for example "release-20210413"
    # http://cloud.debian.org/images/cloud/bookworm/latest/debian-12-azure-amd64.tar.xz
    $ImageBaseUrl = "http://cloud.debian.org/images/cloud"
    $ImageUrlRoot = "$ImageBaseUrl/$ImageVersionName/$ImageRelease/"
    $ImageFileName = "$ImageOS-$ImageVersion-genericcloud-amd64" # should contain "raw" version
    $ImageFileExtension = "tar.xz" # or "vhd.tar.gz" on older releases
    # Manifest file is used for version check based on last modified HTTP header
    $ImageHashFileName = "SHA512SUMS"
    $ImageManifestSuffix = "json"
  }
  "testing" {
    $_ = "sid"
    $ImageVersion = "sid"
  }
  "sid" {
    $ImageOS = "debian"
    $ImageVersionName = "sid"
    $ImageRelease = "daily/latest" # default option is get latest but could be fixed to some specific version for example "release-20210413"
    # http://cloud.debian.org/images/cloud/sid/daily/latest/debian-sid-azure-amd64-daily.tar.xz
    $ImageBaseUrl = "http://cloud.debian.org/images/cloud"
    $ImageUrlRoot = "$ImageBaseUrl/$ImageVersionName/$ImageRelease/"
    #$ImageFileName = "$ImageOS-$ImageVersion-nocloud-amd64" # should contain "raw" version
    $ImageFileName = "$ImageOS-$ImageVersion-azure-amd64-daily" # should contain "raw" version
    $ImageFileExtension = "tar.xz" # or "vhd.tar.gz" on older releases
    # Manifest file is used for version check based on last modified HTTP header
    $ImageHashFileName = "SHA512SUMS"
    $ImageManifestSuffix = "json"
  }
  default {throw "Image version $ImageVersion not supported."}
}

$ImagePath = "$($ImageUrlRoot)$($ImageFileName)"
$ImageHashPath = "$($ImageUrlRoot)$($ImageHashFileName)"

# use Azure specifics only if such cloud image is chosen
if ($ImageTypeAzure) {
  Write-Verbose "Using Azure data source for cloud init in: $ImageFileName"
}

# Set path for storing all VM files
if (-not [string]::IsNullOrEmpty($VMMachine_StoragePath)) {
  $VMMachinePath = $VMMachine_StoragePath.TrimEnd('\')
  $VMStoragePath = "$VMMachine_StoragePath\$VMName\Virtual Hard Disks"
  Write-Verbose "VMStoragePath set: $VMStoragePath"
}

# Get default Virtual Machine path (requires administrative privileges)
if ($VMMachinePath -in $null,'') {
  $vmms = Get-WmiObject -namespace root\virtualization\v2 Msvm_VirtualSystemManagementService
  $vmmsSettings = Get-WmiObject -namespace root\virtualization\v2 Msvm_VirtualSystemManagementServiceSettingData
  $VMMachinePath = $vmmsSettings.DefaultVirtualMachinePath
  # fallback
  if (-not $VMMachinePath) {
    Write-Warning "Couldn't obtain VMMachinePath from Hyper-V settings via WMI"
    $VMMachinePath = "C:\Users\Public\Documents\Hyper-V"
  }
  Write-Verbose "VMMachinePath set: $VMMachinePath"
}
if (!(test-path $VMMachinePath)) {mkdir -Path $VMMachinePath | out-null}

# Get default Virtual Hard Disk path (requires administrative privileges)
if ($VMStoragePath -in $null,'') {
  $vmms = Get-WmiObject -namespace root\virtualization\v2 Msvm_VirtualSystemManagementService
  $vmmsSettings = Get-WmiObject -namespace root\virtualization\v2 Msvm_VirtualSystemManagementServiceSettingData
  $VMStoragePath = $vmmsSettings.DefaultVirtualHardDiskPath
  # fallback
  if (-not $VMStoragePath) {
    Write-Warning "Couldn't obtain VMStoragePath from Hyper-V settings via WMI"
    $VMStoragePath = "C:\Users\Public\Documents\Hyper-V\Virtual Hard Disks"
  }
  Write-Verbose "VMStoragePath set: $VMStoragePath"
}
if (!(test-path $VMStoragePath)) {mkdir -Path $VMStoragePath | out-null}

# Delete the VM if it is around
$vm = Get-VM -VMName $VMName -ErrorAction 'SilentlyContinue'
if ($vm) {
  & .\Cleanup-VM.ps1 $VMName -Force:$Force
}

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

# Azure:   https://cloudinit.readthedocs.io/en/latest/topics/datasources/azure.html
# NoCloud: https://cloudinit.readthedocs.io/en/latest/topics/datasources/nocloud.html
# with static network examples included

$net_settings = @{
  NetInterface = $NetInterface
  NetAutoconfig = $NetAutoconfig
  VMStaticMacAddress = $VMStaticMacAddress
  NetAddress = $NetAddress
  NetGateway = $NetGateway
  NameServers = ''
  DomainName = $DomainName
  FQDN = $FQDN
}
if ( -not $NetAutoconfig ) {
  Write-Verbose "Network autoconfig disabled; preparing networkconfig."
  if ($ImageOS -eq "debian") {
    Write-Verbose "OS 'Debian' found; manual network configuration 'ENI-file' activated."
    $NetConfigType = "ENI-file"
  } else {
    Write-Verbose "NetworkConfigType: '$NetConfigType' assigned."
  }
  Switch ($NetConfigType) {
    ('v1', 'v2') {
      $net_settings.NameServers = "'" + ($NameServers -join "', '") + "'"
    }
    ('ENI','ENI-file','dhclient') {
      $net_settings.NameServers = $NameServers -join ' '
    }
    "v1" { 
      $tPath = Join-Path $PSScriptRoot "templates\v1-static.template" 
    }
    "v2" {
      $tPath = Join-Path $PSScriptRoot "templates\v2.template"
    }
    "ENI" { 
      $tPath = Join-Path $PSScriptRoot "templates\ENI.template"
    }
    "ENI-file" { 
      $tPath = Join-Path $PSScriptRoot "templates\ENI-file.template"
    }
    "dhclient" {
      $tPath = Join-Path $PSScriptRoot "templates\dhclient.template"
    }
    ("v1", "v2", "ENI") {
      $networkconfig = Render-Template -TemplateFilePath $tPath -Variables $net_settings
    }
    ("ENI-file", "dhclient") {
      $network_write_files = Render-Template -TemplateFilePath $tPath -Variables $net_settings
    }
    default {
      Write-Warning "No network configuration version type defined for static IP address setup."
    }
  }
  Write-Verbose ""
  if ($networkconfig) {
    Write-Verbose "Network-Config:"
    Write-Verbose $networkconfig
  }
  if ($network_write_files) {
    Write-Verbose "Network-Config for write_files:"
    Write-Verbose $network_write_files
  }
  Write-Verbose ""

  # userdata for cloud-init, https://cloudinit.readthedocs.io/en/latest/topics/examples.html
}  
$user_settings = @{
  createdDateStamp    = Get-Date -UFormat "%b/%d/%Y %T %Z"
  VMHostname          = $VMHostname
  FQDN                = $FQDN
  TimeZone            = $TimeZone
  packages            = ''
  GuestAdminUsername  = $GuestAdminUsername
  GuestAdminPassword  =  $GuestAdminPassword
  SSHkeys             = ''
  bootcmd             = ''
  azureWAagentDisable = $azureWAagentDisable
  network_write_files = $network_write_files
  NameServers         = "'" + ($NameServers -join "', '") + "'"
  DomainName          = $DomainName
  CloudInitPowerState = $CloudInitPowerState
  KeyboardLayout      = $KeyboardLayout
}

$packages = switch ($ImageOS) {
  "debian" { 'hyperv-daemons' }
  "ubuntu" { 'linux-tools-virtual','linux-cloud-tools-virtual','linux-azure' }
  default  { }
}
$user_settings.packages = "  - " + ($packages -join "`n  - ")

If ($GuestAdminSshPubKey -notin '', $null) {
  $user_settings.SSHkeys = "    ssh_authorized_keys:`n  - $GuestAdminSshPubKey"
}

If ( -not $NetAutoconfig) {
  $user_settings.bootcmd = "bootcmd:`n  - [ cloud-init-per, once, fix-dhcp, sh, -c, sed -e 's/#timeout 60;/timeout 1;/g' -i /etc/dhcp/dhclient.conf ]"
}

If ( (-not $NetAutoconfig) -and ($NetConfigType -ieq "ENI-file")) {
  $user_settings.netAutoConfigENIfile = "  # maybe condition OS based for Debian only and not ENI-file based?`n  # Comment out cloud-init based dhcp configuration for $NetInterface`n  - [ rm, /etc/network/interfaces.d/50-cloud-init ]"
}

If ($ImageTypeAzure) {
  $user_settings.azureWAagentDisable = "`n# dont start waagent service since it useful only for azure/scvmm`n- [ systemctl, stop, walinuxagent.service]`n- [ systemctl, disable, walinuxagent.service]"
}

$userdata = Render-Template -TemplateFilePath (Join-Path $PSScriptRoot "templates\userdata.template") -Variables $user_settings

Write-Verbose "Userdata:"
Write-Verbose $userdata
Write-Verbose ""
if ($testUserdata) {
  Exit 0
}
# override default userdata with custom yaml file: $CustomUserDataYamlFile
# the will be parsed for any powershell variables, src: https://deadroot.info/scripts/2018/09/04/PowerShell-Templating
if (-not [string]::IsNullOrEmpty($CustomUserDataYamlFile) -and (Test-Path $CustomUserDataYamlFile)) {
  Write-Verbose "Using custom userdata yaml $CustomUserDataYamlFile"
  $userdata = $ExecutionContext.InvokeCommand.ExpandString( $(Get-Content $CustomUserDataYamlFile -Raw) ) # parse variables
}

if ($ImageTypeAzure) {
  # cloud-init configuration that will be merged, see https://cloudinit.readthedocs.io/en/latest/topics/datasources/azure.html
  $dscfg = Get-Content (Join-Path $PSScriptRoot "templates\dscfg.conf")

  # src https://github.com/Azure/WALinuxAgent/blob/develop/tests/data/ovf-env.xml
  # src2: https://github.com/canonical/cloud-init/blob/5e6ecc615318b48e2b14c2fd1f78571522848b4e/tests/unittests/sources/test_azure.py#L328
  $ovfen_data = @{
    VMHostname          = $VMHostname
    GuestAdminUsername  = $GuestAdminUsername
    GuestAdminPassword  = $GuestAdminPassword
    userdata_encoded    = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($userdata))
    dscfg_encoded       = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($dscfg))
  }
  
  $ovfenvxml = [xml](Render-Template -TemplateFilePath (Join-Path $PSScriptRoot "templates\ovfenxml.template") -Variables $ovfen_data)
}

# Make temp location for iso image
mkdir -Path "$($tempPath)\Bits"  | out-null

# Output metadata, networkconfig and userdata to file on disk
Set-Content "$($tempPath)\Bits\meta-data" ([byte[]][char[]] "$metadata") -Encoding Byte
if (($NetAutoconfig -eq $false) -and($NetConfigType -in 'v1','v2')) {
  Set-Content "$($tempPath)\Bits\network-config" ([byte[]][char[]] "$networkconfig") -Encoding Byte
}
Set-Content "$($tempPath)\Bits\user-data" ([byte[]][char[]] "$userdata") -Encoding Byte
if ($ImageTypeAzure) {
  $ovfenvxml.Save("$($tempPath)\Bits\ovf-env.xml");
}

# Create meta data ISO image, src: https://cloudinit.readthedocs.io/en/latest/topics/datasources/nocloud.html
# both azure and nocloud support same cdrom filesystem 
# https://github.com/canonical/cloud-init/blob/606a0a7c278d8c93170f0b5fb1ce149be3349435/cloudinit/sources/DataSourceAzure.py#L1972
Write-Host "Creating metadata iso for VM provisioning - " -NoNewline
$metaDataIso = "$($VMStoragePath)\$($VMName)-metadata.iso"
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

if (!(test-path "$metaDataIso")) {throw "Error creating metadata iso"}
Write-Verbose "Metadata iso written"
Write-Host -ForegroundColor Green " Done."

# storage location for base images
$ImageCachePath = Join-Path $PSScriptRoot $("cache\CloudImage-$ImageOS-$ImageVersion")
if (!(test-path $ImageCachePath)) {mkdir -Path $ImageCachePath | out-null}

# Get the timestamp of the target build on the cloud-images site
$BaseImageStampFile = join-path $ImageCachePath "baseimagetimestamp.txt"
[string]$stamp = ''
if (test-path $BaseImageStampFile) {
  $stamp = (Get-Content -Path $BaseImageStampFile | Out-String).Trim()
  Write-Verbose "Timestamp from cache: $stamp"
}
if ($BaseImageCheckForUpdate -or ($stamp -eq '')) {
  $stamp = (Invoke-WebRequest -UseBasicParsing "$($ImagePath).$($ImageManifestSuffix)").BaseResponse.LastModified.ToUniversalTime().ToString("yyyyMMddHHmmss")
  Set-Content -path $BaseImageStampFile -value $stamp -force
  Write-Verbose "Timestamp from web (new): $stamp"
}

# check if local cached cloud image is the target one per $stamp
if (!(test-path "$($ImageCachePath)\$($ImageOS)-$($stamp).$($ImageFileExtension)")) {
  try {
    # If we do not have a matching image - delete the old ones and download the new one
    Write-Verbose "Did not find: $($ImageCachePath)\$($ImageOS)-$($stamp).$($ImageFileExtension)"
    Write-Host 'Removing old images from cache...' -NoNewline
    Remove-Item "$($ImageCachePath)" -Exclude 'baseimagetimestamp.txt',"$($ImageOS)-$($stamp).*" -Recurse -Force
    Write-Host -ForegroundColor Green " Done."

    # get headers for content length
    Write-Host 'Check new image size ...' -NoNewline
    $response = Invoke-WebRequest "$($ImagePath).$($ImageFileExtension)" -UseBasicParsing -Method Head
    $downloadSize = [int]$response.Headers["Content-Length"]
    Write-Host -ForegroundColor Green " Done."

    Write-Host "Downloading new Cloud image ($([int]($downloadSize / 1024 / 1024)) MB)..." -NoNewline
    Write-Verbose $(Get-Date)
    $ProgressPreference = "SilentlyContinue" #Disable progress indicator because it is causing Invoke-WebRequest to be very slow
    # download new image
    Invoke-WebRequest "$($ImagePath).$($ImageFileExtension)" -OutFile "$($ImageCachePath)\$($ImageOS)-$($stamp).$($ImageFileExtension).tmp" -UseBasicParsing
    $ProgressPreference = "Continue" #Restore progress indicator.
    # rename from .tmp to $($ImageFileExtension)
    Remove-Item "$($ImageCachePath)\$($ImageOS)-$($stamp).$($ImageFileExtension)" -Force -ErrorAction 'SilentlyContinue'
    Rename-Item -path "$($ImageCachePath)\$($ImageOS)-$($stamp).$($ImageFileExtension).tmp" `
      -newname "$($ImageOS)-$($stamp).$($ImageFileExtension)"
    Write-Host -ForegroundColor Green " Done."

    # check file hash
    Write-Host "Checking file hash for downloaded image..." -NoNewline
    Write-Verbose $(Get-Date)
    $hashSums = [System.Text.Encoding]::UTF8.GetString((Invoke-WebRequest $ImageHashPath -UseBasicParsing).Content)
    Switch -Wildcard ($ImageHashPath) {
      '*SHA256*' {
        $fileHash = Get-FileHash "$($ImageCachePath)\$($ImageOS)-$($stamp).$($ImageFileExtension)" -Algorithm SHA256
      }
      '*SHA512*' {
        $fileHash = Get-FileHash "$($ImageCachePath)\$($ImageOS)-$($stamp).$($ImageFileExtension)" -Algorithm SHA512
      }
      default {throw "$ImageHashPath not supported."}
    }
    if (($hashSums | Select-String -pattern $fileHash.Hash -SimpleMatch).Count -eq 0) {throw "File hash check failed"}
    Write-Verbose $(Get-Date)
    Write-Host -ForegroundColor Green " Done."

  }
  catch {
    cleanupFile "$($ImageCachePath)\$($ImageOS)-$($stamp).$($ImageFileExtension)"
    $ErrorMessage = $_.Exception.Message
    Write-Host "Error: $ErrorMessage"
    exit 1
  }
}

# check if image is extracted already
if (!(test-path "$($ImageCachePath)\$($ImageOS)-$($stamp).vhd")) {
  try {
    if ($ImageFileExtension.EndsWith("zip")) {
      Write-Host 'Expanding archive...' -NoNewline
      Expand-Archive -Path "$($ImageCachePath)\$($ImageOS)-$($stamp).$($ImageFileExtension)" -DestinationPath "$ImageCachePath" -Force
    } elseif (($ImageFileExtension.EndsWith("tar.gz")) -or ($ImageFileExtension.EndsWith("tar.xz"))) {
      Write-Host 'Expanding archive using bsdtar...' -NoNewline
      # using bsdtar - src: https://github.com/libarchive/libarchive/
      # src: https://unix.stackexchange.com/a/23746/353700
      #& $bsdtarPath "-x -C `"$($ImageCachePath)`" -f `"$($ImageCachePath)\$($ImageOS)-$($stamp).$($ImageFileExtension)`""
      $tarSplat = @{
        FilePath = $bsdtarPath
        ArgumentList = "-x","-C `"$($ImageCachePath)`"","-f `"$($ImageCachePath)\$($ImageOS)-$($stamp).$($ImageFileExtension)`""
        Wait = $true 
        NoNewWindow = $true
        RedirectStandardOutput = "$($tempPath)\bsdtar.log"
      }
      Start-Process @tarSplat
    } elseif ($ImageFileExtension.EndsWith("img")) {
      Write-Verbose 'No need for archive extracting'
    } else {
      Write-Warning "Unsupported image in archive"
      exit 1
    }

    # rename bionic-server-cloudimg-amd64.vhd (or however they pack it) to $ImageFileName.vhd
    $fileExpanded = Get-ChildItem "$($ImageCachePath)\*.vhd","$($ImageCachePath)\*.vhdx","$($ImageCachePath)\*.raw","$($ImageCachePath)\*.img" -File | Sort-Object LastWriteTime | Select-Object -last 1
    Write-Verbose "Expanded file name: $fileExpanded"
    if ($fileExpanded -like "*.vhd") {
      Rename-Item -path $fileExpanded -newname "$ImageFileName.vhd"
    } elseif ($fileExpanded -like "*.raw") {
      Write-Host "qemu-img info for source untouched cloud image: "
      & $qemuImgPath info "$fileExpanded"
      Write-Verbose "qemu-img convert to vhd"
      Write-Verbose "$qemuImgPath convert -f raw $fileExpanded -O vpc $($ImageCachePath)\$ImageFileName.vhd"
      & $qemuImgPath convert -f raw "$fileExpanded" -O vpc "$($ImageCachePath)\$($ImageFileName).vhd"
      # remove source image after conversion
      Remove-Item "$fileExpanded" -force
    } elseif ($fileExpanded -like "*.img") {
      Write-Host "qemu-img info for source untouched cloud image: "
      & $qemuImgPath info "$fileExpanded"
      Write-Verbose "qemu-img convert to vhd"
      Write-Verbose "$qemuImgPath convert -f qcow2 $fileExpanded -O vpc $($ImageCachePath)\$ImageFileName.vhd"
      & $qemuImgPath convert -f qcow2 "$fileExpanded" -O vpc "$($ImageCachePath)\$($ImageFileName).vhd"
      # remove source image after conversion
      Remove-Item "$fileExpanded" -force
    } else {
      Write-Warning "Unsupported disk image extracted."
      exit 1
    }
    Write-Host -ForegroundColor Green " Done."

    Write-Host 'Convert VHD fixed to VHD dynamic...' -NoNewline
    try {
      Convert-VHD -Path "$($ImageCachePath)\$ImageFileName.vhd" -DestinationPath "$($ImageCachePath)\$($ImageOS)-$($stamp).vhd" -VHDType Dynamic -DeleteSource
      Write-Host -ForegroundColor Green " Done."
    } catch {
      Write-Warning $_
      Write-Warning "Failed to convert the disk using 'Convert-VHD', falling back to qemu-img... "
      Write-Host "qemu-img info for source untouched cloud image: "
      & $qemuImgPath info "$($ImageCachePath)\$ImageFileName.vhd"
      Write-Verbose "qemu-img convert to vhd"
      & $qemuImgPath convert "$($ImageCachePath)\$ImageFileName.vhd" -O vpc -o subformat=dynamic "$($ImageCachePath)\$($ImageOS)-$($stamp).vhd"
      # remove source image after conversion
      Remove-Item "$($ImageCachePath)\$ImageFileName.vhd" -force

      #Write-Warning "Failed to convert the disk, will use it as is..."
      #Rename-Item -path "$($ImageCachePath)\$ImageFileName.vhd" -newname "$($ImageCachePath)\$($ImageOS)-$($stamp).vhd" # not VHDX
      Write-Host -ForegroundColor Green " Done."
    }

    if ($ConvertImageToNoCloud) {
      Write-Host 'Modify VHD and convert cloud-init to NoCloud ...' -NoNewline
      $process = Start-Process `
      -FilePath cmd.exe `
      -Wait -PassThru -NoNewWindow `
      -ArgumentList "/c `"`"$(Join-Path $PSScriptRoot "wsl-convert-vhd-nocloud.cmd")`" `"$($ImageCachePath)\$($ImageOS)-$($stamp).vhd`"`""
      # https://stackoverflow.com/a/16018287/1155121
      if ($process.ExitCode -ne 0) {
        throw "Failed to modify/convert VHD to NoCloud DataSource!"
      }
      Write-Host -ForegroundColor Green " Done."
    }

  }
  catch {
    cleanupFile "$($ImageCachePath)\$($ImageOS)-$($stamp).vhd"
    $ErrorMessage = $_.Exception.Message
    Write-Host "Error: $ErrorMessage"
    exit 1
  }
}

# File path for to-be provisioned VHD
$VMDiskPath = "$($VMStoragePath)\$($VMName).vhd"
if ($VMGeneration -eq 2) {
  $VMDiskPath = "$($VMStoragePath)\$($VMName).vhdx"
}
cleanupFile $VMDiskPath

# Prepare VHD... (could also use copy)
Write-Host "Prepare virtual disk..." -NoNewline
try {
  # block size bytes per recommendation https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/best-practices-for-running-linux-on-hyper-v
  Convert-VHD -Path "$($ImageCachePath)\$($ImageOS)-$($stamp).vhd" -DestinationPath $VMDiskPath -VHDType Dynamic -BlockSizeBytes 1MB
  Write-Host -ForegroundColor Green " Done."
  if ($VHDSizeBytes -and ($VHDSizeBytes -gt 30GB)) {
    Write-Host "Resize VHD to $([int]($VHDSizeBytes / 1024 / 1024 / 1024)) GB..." -NoNewline
    Resize-VHD -Path $VMDiskPath -SizeBytes $VHDSizeBytes
    Write-Host -ForegroundColor Green " Done."
  }
} catch {
  Write-Warning "Failed to convert and resize, will just copy it ..."
  Copy-Item "$($ImageCachePath)\$($ImageOS)-$($stamp).vhd" -Destination $VMDiskPath
}

# Create new virtual machine and start it
$vmSplat = @{
  Name = $VMName
  MemoryStartupBytes = $VMMemoryStartupBytes
  Path = "$VMMachinePath"
  VHDPath = "$VMDiskPath"
  Generation = $VMGeneration
  BootDevice = VHD
  Version = $VMVersion
}
Write-Host "Create VM..." -NoNewline
$vm = New-VM @vmSplat
$vm | Set-VMProcessor -Count $VMProcessorCount
$vm | Set-VMMemory -DynamicMemoryEnabled $VMDynamicMemoryEnabled
If ($VMDynamicMemoryEnabled) {
  $vm | Set-VMMemory -MaximumBytes $VMMaximumBytes -MinimumBytes $VMMinimumBytes
}
# make sure VM has DVD drive needed for provisioning
if ( -not (Get-VMDvdDrive)) {
  $vm | Add-VMDvdDrive
}
$vm | Set-VMDvdDrive -Path "$metaDataIso"

$vm | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName "$virtualSwitchName"



if ($VMStaticMacAddress -notin $null,'') {
  Write-Verbose "Setting static MAC address '$VMStaticMacAddress' on VMnet adapter..."
  $vm | Set-VMNetworkAdapter -StaticMacAddress $VMStaticMacAddress
} else {
  Write-Verbose "Using default dynamic MAC address asignment."
}

$VMNetworkAdapter = $vm | Get-VMNetworkAdapter
$VMNetworkAdapterName = $VMNetworkAdapter.Name
If ((([int]$VMVlanID -ne 0) -or ([int]$VMNativeVlanID -ne 0)) -and ($VMAllowedVlanIDList -notin $null,'')) {
  If (([int]($VMNativeVlanID) -ne 0) -and ($VMAllowedVlanIDList -notin $null,'')) {
    Write-Host "Setting native Vlan ID $VMNativeVlanID with trunk Vlan IDs '$VMAllowedVlanIDList'"
    Write-Host "on virtual network adapter '$VMNetworkAdapterName'..."
    $trunkSplat = @{
      VMNetworkAdapterName = "$VMNetworkAdapterName"
      Trunk = $true
      NativeVlanID = $VMNativeVlanID
      AllowedVlanIDList = $VMAllowedVlanIDList
    }
    $vm | Set-VMNetworkAdapterVlan @trunkSplat
  } else {
    $vidSplat = @{
      VMNetworkAdapterName = "$VMNetworkAdapterName" 
      Access = $true 
      VlanId = $VMVlanID
    }
    Write-Host "Setting Vlan ID $VMVlanID on virtual network adapter '$VMNetworkAdapterName'..."
    $vm | Set-VMNetworkAdapterVlan @vidSplat
  }
} else {
  Write-Verbose "Let virtual network adapter '$VMNetworkAdapterName' untagged."
}

If($VMVMQ) {
    Write-Host "Enable Virtual Machine Queue (100)... " -NoNewline
    $vm | Set-VMNetworkAdapter -VmqWeight 100
    Write-Host -ForegroundColor Green " Done."
}

If ($VMDhcpGuard) {
    Write-Host "Enable DHCP Guard... " -NoNewline
    $vm | Set-VMNetworkAdapter -DhcpGuard On
    Write-Host -ForegroundColor Green " Done."
}

If ($VMRouterGuard) {
    Write-Host "Enable Router Guard... " -NoNewline
    $vm | Set-VMNetworkAdapter -RouterGuard On
    Write-Host -ForegroundColor Green " Done."
}

If ($VMAllowTeaming) {
    Write-Host "Enable Allow Teaming... " -NoNewline
    $vm | Set-VMNetworkAdapter -AllowTeaming On
    Write-Host -ForegroundColor Green " Done."
}

If ($VMPassthru) {
    Write-Host "Enable Passthru... " -NoNewline
    $vm | Set-VMNetworkAdapter -Passthru
    Write-Host -ForegroundColor Green " Done."
}

If ($VMMacAddressSpoofing) {
  Write-Verbose "Enable MAC address Spoofing on VMnet adapter..."
  Set-VMNetworkAdapter -VMName $VMName -MacAddressSpoofing On
} else {
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
  } else {
    Write-Verbose "Enhanced session mode not enabled because host has not activated support for it."
  }

  # For copy&paste service (hv_fcopy_daemon) between host and guest we need also this
  # guest service interface activation which has sadly language dependent setup:
  # PS> Enable-VMIntegrationService -VMName $VMName -Name "Guest Service Interface"
  # PS> Enable-VMIntegrationService -VMName $VMName -Name "Gastdienstschnittstelle"
  # https://administrator.de/forum/hyper-v-cmdlet-powershell-sprachproblem-318175.html
  Get-VMIntegrationService -VMName $VMName `
            | Where-Object {$_.Name -match 'Gastdienstschnittstelle|Guest Service Interface'} `
            | Enable-VMIntegrationService
}

# disable automatic checkpoints, https://github.com/hashicorp/vagrant/issues/10251#issuecomment-425734374
If ($null -ne (Get-Command Hyper-V\Set-VM).Parameters["AutomaticCheckpointsEnabled"]){
  Hyper-V\Set-VM -VMName $VMName -AutomaticCheckpointsEnabled $false
}

Write-Host -ForegroundColor Green " Done."

# https://social.technet.microsoft.com/Forums/en-US/d285d517-6430-49ba-b953-70ae8f3dce98/guest-asset-tag?forum=winserverhyperv
Write-Host "Set SMBIOS serial number ..."
$vmserial_smbios = $VmMachineId
If ($ImageTypeAzure) {
  # set chassis asset tag to Azure constant as documented in https://github.com/canonical/cloud-init/blob/5e6ecc615318b48e2b14c2fd1f78571522848b4e/cloudinit/sources/helpers/azure.py#L1082
  Write-Host "Set Azure chasis asset tag ..." -NoNewline
  # https://social.technet.microsoft.com/Forums/en-US/d285d517-6430-49ba-b953-70ae8f3dce98/guest-asset-tag?forum=winserverhyperv
  & .\Set-VMAdvancedSettings.ps1 -VM $VMName -ChassisAssetTag '7783-7084-3265-9085-8269-3286-77' -Force -Verbose:$verbose
  Write-Host -ForegroundColor Green " Done."

  # also try to enable NoCloud via SMBIOS  https://cloudinit.readthedocs.io/en/22.4.2/topics/datasources/nocloud.html
  $vmserial_smbios = 'ds=nocloud'
}
Write-Host "SMBIOS SN: $vmserial_smbios"
& .\Set-VMAdvancedSettings.ps1 -VM $VMName -BIOSSerialNumber $vmserial_smbios -ChassisSerialNumber $vmserial_smbios -Force -Verbose:$verbose
Write-Host -ForegroundColor Green " Done."

# redirect com port to pipe for VM serial output, src: https://superuser.com/a/1276263/145585
Set-VMComPort -VMName $VMName -Path \\.\pipe\$VMName-com1 -Number 1
Write-Verbose "Serial connection: \\.\pipe\$VMName-com1"

# enable guest integration services (could be used for Copy-VMFile)
Get-VMIntegrationService -VMName $VMName | Where-Object Name -match 'guest' | Enable-VMIntegrationService

# Clean up temp directory
Remove-Item -Path $tempPath -Recurse -Force

# Make checkpoint when debugging https://stackoverflow.com/a/16297557/1155121
If ($PSBoundParameters.Debug -eq $true) {
  # make VM snapshot before 1st run
  Write-Host "Creating checkpoint..." -NoNewline
  Checkpoint-VM -Name $VMName -SnapshotName Initial
  Write-Host -ForegroundColor Green " Done."
}

Write-Host "Starting VM..." -NoNewline
Start-VM $VMName
Write-Host -ForegroundColor Green " Done."

# TODO check If VM has got an IP ADDR, if address is missing then write error because provisioning won't work without IP, src: https://stackoverflow.com/a/27999072/1155121


If ($ShowSerialConsoleWindow) {
  # start putty or hvc.exe with serial connection to newly created VM
  try {
    Get-Command "putty" | out-null
    start-sleep -seconds 2
    & "PuTTY" -serial "\\.\pipe\$VMName-com1" -sercfg "115200,8,n,1,N"
  }
  catch {
    Write-Verbose "putty not available, will try Windows Terminal + hvc.exe"
    Start-Process "wt.exe" "new-tab cmd /k hvc.exe serial $VMName" -WindowStyle Normal -errorAction SilentlyContinue
  }

}

If ($ShowVmConnectWindow) {
  # Open up VMConnect
  Start-Process "vmconnect" "localhost","$VMName" -WindowStyle Normal
}

Write-Host "Done"



