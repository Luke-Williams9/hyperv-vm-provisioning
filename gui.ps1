# Load assemblies
Add-Type -AssemblyName PresentationFramework

# Define XAML code for the GUI
$xaml = Get-Content gui.xaml

# Parse the XAML
$xamlReader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
$window = [Windows.Markup.XamlReader]::Load($xamlReader)

# Get elements from the window
$createVm = $window.FindName("createVm")
$cancel = $window.FindName("cancel")

# Set default values

$window.FindName("VMName").Text = "DefaultVMName"
$window.FindName("GuestAdminUsername").Text = "admin"
$window.FindName("imageOS").Text = "ubuntu"
$window.FindName("VMProcessorCount").Text = "2"
$window.FindName("VMMemoryStartupBytes").Text = "1073741824"

# Define what happens when the buttons are clicked
$createVm.Add_Click({
    # Call your script with the parameters from the textboxes
    .\New-LinuxVM.ps1 -VMName $window.FindName("VMName").Text -GuestAdminUsername $window.FindName("GuestAdminUsername").Text -GuestAdminPassword $window.FindName("GuestAdminPassword").Password -GuestAdminSshPubKey $window.FindName("GuestAdminSshPubKey").Text -imageOS $window.FindName("imageOS").Text -VMProcessorCount $window.FindName("VMProcessorCount").Text -VMMemoryStartupBytes $window.FindName("VMMemoryStartupBytes").Text
    # Close the window
    $window.Close()
})
$cancel.Add_Click({
    # Close the window
    $window.Close()
})

# Show the window
$window.ShowDialog() | Out-Null


