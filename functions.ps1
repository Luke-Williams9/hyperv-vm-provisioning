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

    if (-not (Test-Path $TemplateFilePath -PathType Leaf)) {
        Throw "Template file not found: $TemplateFilePath"
    }
    
    $regex = "$pre(\w+)$post"
    $templateContent = Get-Content $TemplateFilePath

    for ($i = 0; $i -lt $templateContent.Count; $i++) {
        $line = $templateContent[$i]
        $match = [regex]::Matches($line, $regex)

        foreach ($m in $match) {
            $var = $m.Groups[1].Value
            if ($Variables.ContainsKey($var) -and $Variables[$var] -notin $null,'') {
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