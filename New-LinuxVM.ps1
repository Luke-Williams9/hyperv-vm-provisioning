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

<# -------------------------------------------------------- Parameters ----------------------------------------------------------------#>

#requires -Modules Hyper-V
#requires -RunAsAdministrator
[cmdletBinding()]
param (
  [array]  $additionalRuncmd,
  [bool]   $BaseImageCheckForUpdate = $true, # check for newer image at Distro cloud-images site
  [bool]   $BaseImageCleanup = $true, # delete old vhd image. Set to false if using (TODO) differencing VHD
  [bool]   $ConvertImageToNoCloud = $false, # could be used for other image types that do not support NoCloud, not just Azure
  [string] $CloudInitPowerState = "reboot", # poweroff, halt, or reboot , https://cloudinit.readthedocs.io/en/latest/reference/modules.html#power-state-change
  [string] $CustomUserDataYamlFile,
# [string] $DownloadURL = 'https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.tar.xz',
  [string] $DownloadURL = "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img",
  [switch] $Force = $false,
  [Parameter()][Alias("user","username","u")]
  [string] $GuestAdminUsername = "admin",
  [Parameter()][Alias("password","pass","p")]
  [string] $GuestAdminPassword,
  [string] $GuestAdminSshPubKey,
# [string] $imageOS = 'debian',
  [string] $imageOS = $null,
  [bool]   $ImageTypeAzure = $false,
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
  [string] $NetConfigType = "ENI-file", # ENI, v1, v2, ENI-file, dhclient
  [array]  $packages = '',#@('python3','pip','docker','docker-compose'),
  [switch] $ShowSerialConsoleWindow = $false,
  [switch] $ShowVmConnectWindow = $false,
  [switch] $userDataTest = $false,
  [string] $tempRoot = "${env:systemdrive}\hvtemp",
  [string] $TimeZone, # UTC or continental zones of IANA DB like: Europe/Berlin. https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
  [Parameter()][Alias("name")]
  [string] $VMName,
  [int]    $VMGeneration = 1, # create gen1 hyper-v machine because of portability to Azure (https://docs.microsoft.com/en-us/azure/virtual-machines/windows/prepare-for-upload-vhd-image)
  [Parameter()][Alias("CPU","CPUcores","Cores")]
  [int]    $VMProcessorCount = 2,
  [bool]   $VMDynamicMemoryEnabled = $false,
  [Parameter()][Alias("RAM","Memory")]
  [uint64] $VMMemoryStartupBytes = 1024MB,
  [uint64] $VMMinimumBytes = $VMMemoryStartupBytes,
  [uint64] $VMMaximumBytes = $VMMemoryStartupBytes,
  [uint64] $VHDSizeBytes = 16GB,
  [switch] $VMdataVol = $false,
  [uint64] $VMdataVolSizeBytes = 64GB,
  [string] $VMdataVolMountPoint = '/mnt/data',
  [Parameter()][Alias("vSwitch")]
  [string] $VirtualSwitchName,
  [Parameter()][Alias("vlan")]
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
  [Parameter()][Alias("hostname")]
  [string] $VMHostname,
  [string] $VMpath, # if not defined here default Virtal Machine path is used
  [string] $VHDpath # if not defined here Hyper-V settings path / fallback path is set below
)

$ErrorActionPreference = 'Stop'

<# -------------------------------------------------------- Include, Module, Variables ----------------------------------------------------------------#>

# check if running hyper-v host version 8.0 or later
# Get-VMHostSupportedVersion https://docs.microsoft.com/en-us/powershell/module/hyper-v/get-vmhostsupportedversion?view=win10-ps
# or use vmms version: $vmms = Get-Command vmms.exe , $vmms.version. src: https://social.technet.microsoft.com/Forums/en-US/dce2a4ec-10de-4eba-a19d-ae5213a2382d/how-to-tell-version-of-hyperv-installed?forum=winserverhyperv
$vmms = Get-Command vmms.exe
if (([System.Version]$vmms.fileversioninfo.productversion).Major -lt 10) {
  Throw "Unsupported Hyper-V version. Minimum supported version for is Hyper-V 2016."
}

# Include the functions! 
. (Join-Path $PSScriptRoot functions.ps1)

# pwsh (powershell core): try to load module hyper-v
if ($psversiontable.psversion.Major -ge 6) {
  Import-Module hyper-v -SkipEditionCheck
}

# ADK Download - https://www.microsoft.com/en-us/download/confirmation.aspx?id=39982
# You only need to install the deployment tools, src2: https://github.com/Studisys/Bootable-Windows-ISO-Creator
$oscdimgPath = Join-Path $PSScriptRoot "tools\oscdimg\x64\oscdimg.exe"

# Download qemu-img from here: http://www.cloudbase.it/qemu-img-windows/
$qemuImgPath = Join-Path $PSScriptRoot "tools\qemu-img\qemu-img.exe"

# Windows version of tar for extracting tar.gz files, src: https://github.com/libarchive/libarchive
$bsdtarPath = Join-Path $PSScriptRoot "tools\bsdtar.exe"

# RAM check - leave 1GB free on the host
$freeRAMbytes = (((Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize * 1KB) - (Get-Process | Measure-Object WorkingSet -Sum).Sum) #/ 1024MB
If ($VMMemoryStartupBytes -gt $freeRAMbytes) {
  Write-Warning "Requested memory ($VMMemoryStartupBytes) exceeds available host memory ($freeRAMbytes)."  
  Do {
    $VMMemoryStartupBytes -= 128MB
  } While ($VMMemoryStartupBytes -gt $freeRAMbytes)
}

# Time Zone
if ($TimeZone -in $null, '') {
  $baseTZ = (Get-Timezone).BaseUTCoffset.hours
  if ($baseTZ -ge 0) {
    $tzPre = '-'
  } else {
    $tzPre = '+'
  }
  $TimeZone = 'Etc/GMT' + $tzPre + [string]([math]::abs($baseTZ))
}

# Also do a CPU check
$CPUs = Get-CimInstance Win32_ComputerSystem
If ($CPUs.NumberOfLogicalProcessors -lt $VMProcessorCount) {
  Write-Warning "Requested CPU count is higher than available logical processors (${CPUs.NumberOfLogicalProcessors}). Reducing count."
  $VMprocessorCount = $CPUs.NumberOfLogicalProcessors
}

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

 $FQDN = $VMHostname.ToLower() + "." + $hostNetInfo.DomainSuffix.ToLower()

 if ($GuestAdminPassword -in $null, '') {
    #$GuestAdminPassword = 'Passw0rd'
    $GuestAdminPassword = Make-Random 8
    Write-Host "-------------- LOCAL ADMIN -----------------------"
    Write-Host "Username: $GuestAdminUsername"
    Write-Host "Password: $GuestAdminPassword"
    Write-Host ""
      
 }

$NetAutoconfig = ($NetAddress         -in $null,'') -and
                 ($NetNetmask         -in $null,'') -and
                 ($NetNetwork         -in $null,'') -and
                 ($NetNetGateway      -in $null,'') -and
                 ($NetNetmask         -in $null,'') -and
                 ($NetMacAddress -in $null,'')

if ($NetAutoconfig -eq $false) {
  Write-Verbose "-------------- NETWORK CONFIGURATION ------------------"
  Write-Verbose ""
  Write-Verbose "VMStaticMacAddress: '$NetMacAddress'"
  Write-Verbose "NetInterface:     '$NetInterface'"
  Write-Verbose "NetAddress:       '$NetAddress'"
  Write-Verbose "NetNetmask:       '$NetNetmask'"
  Write-Verbose "NetNetwork:       '$NetNetwork'"
  Write-Verbose "NetGateway:       '$NetGateway'"
  Write-Verbose ""
}

# check if verbose is present, src: https://stackoverflow.com/a/25491281/1155121
$verbose = $VerbosePreference -ne 'SilentlyContinue'

# Instead of GUID, use 26 digit machine id suitable for BIOS serial number
# src: https://stackoverflow.com/a/67077483/1155121
# $vmMachineId = [Guid]::NewGuid().ToString()
$rSplat = @{
  Minimum = 1000000000000000 
  Maximum = 9999999999999999
}
$VmMachineId = "{0:####-####-####-####}-{1:####-####-##}" -f (Get-Random @rSplat),(Get-Random @rSplat)
$tp = Join-Path $tempRoot "temp"
$tempPath = Join-Path $tp $vmMachineId
Remove-Item -path $tp -recurse -force -confirm:$false -ErrorAction SilentlyContinue
New-Item -ItemType Directory -path $tempPath -force | Out-Null
Write-Verbose "Using temp path: $tempPath"

<# -------------------------------------------------------- Virtual Network ----------------------------------------------------------------#>

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

# Update this to the release of Image that you want
# But Azure images can't be used because the waagent is trying to find ephemeral disk
# and it's searching causing 20 / 40 minutes minutes delay for 1st boot
# https://docs.microsoft.com/en-us/troubleshoot/azure/virtual-machines/cloud-init-deployment-delay
# and also somehow causing at sshd restart in password setting task to stuck for 30 minutes.

<# -------------------------------------------------------- Image URL and local path variables ----------------------------------------------------------------#>

Write-Host $downloadURL
Switch ($downloadURL) {
  {$_ -match 'debian'} {
    $ImageOS = 'debian'
    $ImageFileExtension = 'tar.xz'
    $ImageHashFileName = "SHA512SUMS"
    $ImageManifestSuffix = "json"
    $imagePackages = 'hyperv-daemons','sudo','vim','ufw','dnsutils','net-tools','curl'
  }
  {$_ -match 'ubuntu'} {
    $ImageOS = 'ubuntu'
    $ImageFileExtension = 'img'
    $ImageHashFileName = "SHA256SUMS"
    $ImageManifestSuffix = "manifest"
    $imagePackages = 'linux-tools-virtual','linux-cloud-tools-virtual','linux-azure'
  }
}


# URL prefix may be http or https
$URLprefix = $downloadURL.split(':')[0] 
$B = $downloadURL.replace("${URLprefix}://",'').split('/')

$ImageFileName = $B[$B.count-1].replace(".$ImageFileExtension",'')
$ImageBaseURL = "${URLprefix}://" + ($B[(0..($B.count-2))] -join '/')
$ImageHashURL = $ImageBaseURL + '/' + $ImageHashFileName

# use Azure specifics only if such cloud image is chosen
if ($ImageTypeAzure) {
  Write-Verbose "Using Azure data source for cloud init in: $ImageFileName"
}

Try   { $hvInfo = Get-VMHost }
Catch { Throw "Error getting VMHost info $_" }

# Set folders if not defined
if ($VMpath -in $null,'')  { $VMpath = $hvInfo.VirtualMachinePath }
if ($VHDpath -in $null,'') { $VHDpath = $hvInfo.VirtualHardDiskPath }
Foreach ($d in $VMpath, $VHDpath) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

<# -------------------------------------------------------- Cleanup old VM ----------------------------------------------------------------#>

# Delete the VM if it is around
$vm = Get-VM $VMName -ErrorAction 'SilentlyContinue'
if ($vm) { Cleanup-VM $VMName -Force:$Force }

# There is a documentation failure not mention needed dsmode setting:
# https://gist.github.com/Informatic/0b6b24374b54d09c77b9d25595cdbd47
# Only in special cloud environments its documented already:
# https://cloudinit.readthedocs.io/en/latest/topics/datasources/cloudsigma.html
# metadata for cloud-init

<# -------------------------------------------------------- Metadata ----------------------------------------------------------------#>

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

<# -------------------------------------------------------- Create Network settings ----------------------------------------------------------------#>


$net_settings = @{
  NetInterface = $NetInterface
  NetAutoconfig = $NetAutoconfig
  VMStaticMacAddress = $NetMacAddress
  NetAddress = $NetAddress
  NetGateway = $NetGateway
  NameServers = ''
  DomainName = $VMhostName
  FQDN = $FQDN
}
If ( -not $NetAutoconfig ) {
  Write-Verbose "Network autoconfig disabled; preparing networkconfig."
  If ($ImageOS -eq "debian") {
    Write-Verbose "OS 'Debian' found; manual network configuration 'ENI-file' activated."
    $NetConfigType = "ENI-file"
  } else {
    Write-Verbose "NetworkConfigType: '$NetConfigType' assigned."
  }
  Switch ($NetConfigType) {
    {$_ -in 'v1', 'v2'} {
      $net_settings.NameServers = "'" + ($NameServers -join "', '") + "'"
    }
    {$_ -in 'ENI','ENI-file','dhclient'} {
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
    {$_ -in "v1", "v2", "ENI"} {
      $networkconfig = Render-Template -TemplateFilePath $tPath -Variables $net_settings
    }
    {$_ -in "ENI-file", "dhclient"} {
      $network_write_files = Render-Template -TemplateFilePath $tPath -Variables $net_settings
    }
    default {
      Write-Warning "No network configuration version type defined for static IP address setup."
    }
  }
  Write-Verbose ""
  If ($networkconfig) {
    Write-Verbose "Network-Config:"
    Write-Verbose $networkconfig
  }
  If ($network_write_files) {
    Write-Verbose "Network-Config for write_files:"
    Write-Verbose $network_write_files
  }
  Write-Verbose ""

  
}

<# -------------------------------------------------------- Create Userdata ----------------------------------------------------------------#>

# userdata for cloud-init, https://cloudinit.readthedocs.io/en/latest/topics/examples.html
$user_settings = @{
  createdDateStamp    = Get-Date -UFormat "%b/%d/%Y %T %Z"
  VMHostname          = $VMHostname
  FQDN                = $FQDN
  TimeZone            = $TimeZone
  Locale              = $Locale
  packages            = ("  - " + (($packages + $imagePackages) -join "`n  - "))
  GuestAdminUsername  = $GuestAdminUsername
  GuestAdminPassword  =  $GuestAdminPassword
  SSHkeys             = ''
  bootcmd             = ''
  azureWAagentDisable = $azureWAagentDisable
  network_write_files = $network_write_files
  NameServers         = "'" + ($NameServers -join "', '") + "'"
  DomainName          = $hostNetInfo.DomainSuffix.ToLower()
  CloudInitPowerState = $CloudInitPowerState
  KeyboardLayout      = $KeyboardLayout
  AdditionalRuncmd    = ("  - " + ($additionalRuncmd -join "`n  - "))
  Mounts              = ''
}

If ($VMdataVol) {
  $user_settings.Mounts = "mounts:`n  - [ sdb, $VMdataVolMountPoint ]"
}
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
If ($testUserdata) {
  Exit 0
}
# override default userdata with custom yaml file: $CustomUserDataYamlFile
# the will be parsed for any powershell variables, src: https://deadroot.info/scripts/2018/09/04/PowerShell-Templating
If (-not [string]::IsNullOrEmpty($CustomUserDataYamlFile) -and (Test-Path $CustomUserDataYamlFile)) {
  Write-Verbose "Using custom userdata yaml $CustomUserDataYamlFile"
  $userdata = $ExecutionContext.InvokeCommand.ExpandString( $(Get-Content $CustomUserDataYamlFile -Raw) ) # parse variables
}

If ($ImageTypeAzure) {
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

<# -------------------------------------------------------- Write all the files ----------------------------------------------------------------#>

# Make temp location for iso image
New-Item -ItemType Directory -Path "$($tempPath)\Bits" | Out-Null

#$metadata | export-clixml "metadata.xml"
# Output metadata, networkconfig and userdata to file on disk
#Write-Host "----------------------------"
#Write-Host "Temppath: $tempPath"
#Write-Host "-------------------------------------------"
#Write-Host "metadata:"
#Write-Host $metadata

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
Set-Content "$($tempPath)\Bits\meta-data" ([byte[]][char[]] "$metadata") @cSplat
If (($NetAutoconfig -eq $false) -and($NetConfigType -in 'v1','v2')) {
  Set-Content "$($tempPath)\Bits\network-config" ([byte[]][char[]] "$networkconfig") @cSplat
}
Set-Content "$($tempPath)\Bits\user-data" ([byte[]][char[]] "$userdata") @cSplat
If ($ImageTypeAzure) {
  $ovfenvxml.Save("$($tempPath)\Bits\ovf-env.xml");
}

# Create meta data ISO image, src: https://cloudinit.readthedocs.io/en/latest/topics/datasources/nocloud.html
# both azure and nocloud support same cdrom filesystem 
# https://github.com/canonical/cloud-init/blob/606a0a7c278d8c93170f0b5fb1ce149be3349435/cloudinit/sources/DataSourceAzure.py#L1972
Write-Host "Creating metadata iso for VM provisioning - " 
$metaDataIso = "$($VHDpath)\$($VMName)-metadata.iso"
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

<# -------------------------------------------------------- Download and parse checksum file ----------------------------------------------------------------#>

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
Write-Host $hashAlgo

<# -------------------------------------------------------- Download and verify image ----------------------------------------------------------------#>

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


<# -------------------------------------------------------- Extract image ----------------------------------------------------------------#>

# Delete an existing VHD and re-extract it from the verified image
$imageVHD = "${ImageCachePath}\${ImageFileName}-temp.vhd"
$imageVHDfinal = "${ImageCachePath}\${ImageFileName}.vhd"

Remove-Item $imageVHDfinal -confirm:$false -errorAction SilentlyContinue | Out-Null

Switch ($ImageFileExtension) {
  {$_ -in 'tar.gz','tar.xz'} {
    Write-Host 'Expanding archive using bsdtar...' 
    # using bsdtar - src: https://github.com/libarchive/libarchive/
    # src: https://unix.stackexchange.com/a/23746/353700
    #& $bsdtarPath "-x -C `"$($ImageCachePath)`" -f `"$($ImageCachePath)\$($ImageOS)-$($stamp).$($ImageFileExtension)`""
    $tarSplat = @{
      FilePath = $bsdtarPath
      ArgumentList = '-x','-C', "`"$($imageUnzipPath)`"",'-f', "`"$ImageFilePath`""
      Wait = $true 
      NoNewWindow = $true
      RedirectStandardOutput = "$($tempPath)\bsdtar.log"
    }
    $tarSplat | FL | Out-String
    
    Start-Process @tarSplat
  }
  'zip' { 
    Expand-Archive $ImageFilePath -DestinationPath $imageUnzipPath -Force
  }
  'img' {
    # Put it in the intermediate folder even though it doesn't need to be unzipped
    Copy-Item $ImageFilePath -DestinationPath $imageUnzipPath -Force
  }
  default { 
    Throw "Unsupported image in archive - $ImageFileExtension"
   }
}

<# -------------------------------------------------------- Convert Image to VHD ---------------------------------------------------------------- #>

# There should be only a single image file in $imageUnzipPath
$fileExpanded = Get-ChildItem $imageUnzipPath 

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

<# -------------------------------------------------------- Convert fixed VHD to dynamic ---------------------------------------------------------------- #>

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

  #Write-Warning "Failed to convert the disk, will use it as is..."
  #Rename-Item -path "$($ImageCachePath)\$ImageFileName.vhd" -newname "$($ImageCachePath)\$($ImageOS)-$($stamp).vhd" # not VHDX
  Write-Host -ForegroundColor Green " Done."
}

Resize-VHD -path $ImageVHDfinal -SizeBytes $VHDSizeBytes

If ($ConvertImageToNoCloud) {
  Write-Host 'Modify VHD and convert cloud-init to NoCloud ...' 
  $noCloudSplat = @{
    FilePath = 'cmd.exe'
    Wait = $true 
    PassThru = $true 
    NoNewWindow = $true
    ArgumentList = "/c `"`"$(Join-Path $PSScriptRoot "wsl-convert-vhd-nocloud.cmd")`" `"$($ImageVHDfinal)`"`""
  }
  $process = Start-Process @noCloudSplat
  
  # https://stackoverflow.com/a/16018287/1155121
  If ($process.ExitCode -ne 0) {
    Throw "Failed to modify/convert VHD to NoCloud DataSource!"
  }
  Write-Host -ForegroundColor Green " Done."
}


<# -------------------------------------------------------- Deploy VHD ---------------------------------------------------------------- #>

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

<# -------------------------------------------------------- Create Virtual Machine ---------------------------------------------------------------- #>
Write-Host "--------------------- $VMMemoryStartupBytes MB ---------------------"
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
If ($null -ne (Get-Command Hyper-V\Set-VM).Parameters["AutomaticCheckpointsEnabled"]){
  Hyper-V\Set-VM -VMName $VMName -AutomaticCheckpointsEnabled $false
}

Write-Host -ForegroundColor Green " Done."

<# Set-VMAdvancedSettings doesn't work with Powershell 7? Also I don't think I need to set the SMBIOS number
# https://social.technet.microsoft.com/Forums/en-US/d285d517-6430-49ba-b953-70ae8f3dce98/guest-asset-tag?forum=winserverhyperv
Write-Host "Set SMBIOS serial number ..."
$vmserial_smbios = $VmMachineId

If ($ImageTypeAzure) {
  # set chassis asset tag to Azure constant as documented in https://github.com/canonical/cloud-init/blob/5e6ecc615318b48e2b14c2fd1f78571522848b4e/cloudinit/sources/helpers/azure.py#L1082
  Write-Host "Set Azure chasis asset tag ..." 
  # https://social.technet.microsoft.com/Forums/en-US/d285d517-6430-49ba-b953-70ae8f3dce98/guest-asset-tag?forum=winserverhyperv
  Set-VMAdvancedSettings -VM $vm -ChassisAssetTag '7783-7084-3265-9085-8269-3286-77' -Force -Verbose:$verbose
  Write-Host -ForegroundColor Green " Done."

  # also try to enable NoCloud via SMBIOS  https://cloudinit.readthedocs.io/en/22.4.2/topics/datasources/nocloud.html
  $vmserial_smbios = 'ds=nocloud'
}

Write-Host "SMBIOS SN: $vmserial_smbios"
Set-VMAdvancedSettings -VM $vm.name -BIOSSerialNumber $vmserial_smbios -ChassisSerialNumber $vmserial_smbios -Force -Verbose
Write-Host -ForegroundColor Green " Done."
#>


# redirect com port to pipe for VM serial output, src: https://superuser.com/a/1276263/145585
$vm | Set-VMComPort -Path \\.\pipe\$VMName-com1 -Number 1
Write-Verbose "Serial connection: \\.\pipe\$VMName-com1"

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

Write-Host "Starting VM..." 
Start-VM $VMName
Write-Host -ForegroundColor Green " Done."

# TODO check If VM has got an IP ADDR, If address is missing then write error because provisioning won't work without IP, src: https://stackoverflow.com/a/27999072/1155121


If ($ShowSerialConsoleWindow) {
  # start putty or hvc.exe with serial connection to newly created VM
  Try {
    Get-Command "putty" | out-null
    start-sleep -seconds 2
    & "PuTTY" -serial "\\.\pipe\$VMName-com1" -sercfg "115200,8,n,1,N"
  }
  Catch {
    Write-Verbose "putty not available, will try Windows Terminal + hvc.exe"
    Start-Process "wt.exe" "new-tab cmd /k hvc.exe serial $VMName" -WindowStyle Normal -errorAction SilentlyContinue
  }

}

If ($ShowVmConnectWindow) {
  # Open up VMConnect
  Start-Process "vmconnect" "localhost","$VMName" -WindowStyle Normal
}

Write-Host "Done"



