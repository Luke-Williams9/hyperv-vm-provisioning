
# Defaults
$imageRelease        = 'latest'
$imageFileExtension  = 'img'
$imageHashFileName   = 'SHA256SUMS'
$imageManifestSuffix = 'manifest'
$images = @(
  @{
    name = 'ubuntu'
    ImageBaseUrl = "http://cloud-images.ubuntu.com/releases"
    imageFileExtension = '.img'
    imageRelease = 'release'
    imageSuffix = '-server-cloudimg-amd64'
    ImageManifestSuffix = 'manifest'
    versionTable = @{
      '22' = 'jammy'
      '20' = 'focal'
      '18' = 'bionic'
      '16' = 'xenial'
      '14' = 'trusty'
    }
  },
  @{
    name = 'debian'
    ImageBaseUrl = 'http://cloud.debian.org/images/cloud'
    imageFileExtension = '.tar.xz'
    imageRelease = 'latest'
    imageSuffix = '-genericcloud-amd64'
    ImageManifestSuffix = 'json'
    versionTable = @{
      '12' = 'bookworm'
      '11' = 'bullseye'
      '10' = 'buster'
      '9' = 'stretch'
      '8' = 'jessie'
      '7' = 'wheezy'
    }
  }
)  
