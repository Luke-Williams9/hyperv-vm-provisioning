# https://poshsecurity.com/blog/2013/4/12/password-hashing-with-bcrypt-and-powershell-part-2.html
# https://httpd.apache.org/docs/2.4/misc/password_encryptions.html
# https://github.com/BcryptNet/bcrypt.net/releases

#this works!


$username = 'admin'
$password = 'derp21412!'


Add-Type -Path ($PWD.path + '\tools\BCrypt.Net-Next.dll')
$salt = [bcrypt.net.bcrypt]::generatesalt()
$hashedpass = [bcrypt.net.bcrypt]::hashpassword($password, $Salt)

$contents = $username + ':' + $hashedpass




<#

admin:$2a$11$/VZDDFv0.tz8z0..LYQWWeGWSPuetbalJ113rVhl8DkBSk0XSSvWS

#>