# Load assemblies
Add-Type -AssemblyName PresentationFramework

# Define XAML code for the GUI
$xaml = @"
<Window 
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    Title="Linux VM Creator" Height="350" Width="525"
    Background="#FF2D2D30" Foreground="#FFFFFF">
    <StackPanel Margin="10">
        <Grid Name="mainGrid">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <Label Content="VM Name" Foreground="#FFFFFF"/>
            <TextBox Name="VMName" Grid.Column="1" Height="23" TextWrapping="Wrap" Width="250"/>
            <Label Content="Admin Username" Grid.Row="1" Foreground="#FFFFFF"/>
            <TextBox Name="GuestAdminUsername" Grid.Row="1" Grid.Column="1" Height="23" TextWrapping="Wrap" Width="250"/>
            <Label Content="Admin Password" Grid.Row="2" Foreground="#FFFFFF"/>
            <PasswordBox Name="GuestAdminPassword" Grid.Row="2" Grid.Column="1" Height="23" Width="250"/>
            <Label Content="Admin SSH Public Key" Grid.Row="3" Foreground="#FFFFFF"/>
            <TextBox Name="GuestAdminSshPubKey" Grid.Row="3" Grid.Column="1" Height="23" TextWrapping="Wrap" Width="250"/>
            <Label Content="Image OS" Grid.Row="4" Foreground="#FFFFFF"/>
            <TextBox Name="imageOS" Grid.Row="4" Grid.Column="1" Height="23" TextWrapping="Wrap" Width="250"/>
            <Label Content="Processor Count" Grid.Row="5" Foreground="#FFFFFF"/>
            <TextBox Name="VMProcessorCount" Grid.Row="5" Grid.Column="1" Height="23" TextWrapping="Wrap" Width="250"/>
            <Label Content="Memory Startup Bytes" Grid.Row="6" Foreground="#FFFFFF"/>
            <TextBox Name="VMMemoryStartupBytes" Grid.Row="6" Grid.Column="1" Height="23" TextWrapping="Wrap" Width="250"/>
        </Grid>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Left" Margin="0,10,0,0">
            <Button Name="createVm" Content="Create VM" Width="75"/>
            <Button Name="cancel" Content="Cancel" Margin="10,0,0,0" Width="75"/>
        </StackPanel>
    </StackPanel>
</Window>
"@


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


