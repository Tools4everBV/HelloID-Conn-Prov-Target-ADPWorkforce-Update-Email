############################################################
# HelloID-Conn-Prov-Target-ADPWorkforce-UpdateEmail-Update
#
# Version: 1.0.1
############################################################
# Initialize default value's
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

# Mapping
$account = @{
    workerId    = $p.ExternalId
    workerEmail = $p.Accounts.ActiveDirectory.mail
}

#region debug logging
switch ($($config.IsDebug)) {
    $true {
        $VerbosePreference = 'Continue'
    }
    $false {
        $VerbosePreference = 'SilentyContinue'
    }
}
#endregion

#region functions
function Get-ADPAccessToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]
        $ClientID,

        [Parameter(Mandatory)]
        [String]
        $ClientSecret,

        [Parameter(Mandatory)]
        [X509Certificate]
        $Certificate
    )

    try {
        $splatRestMethodParameters = @{
            Uri         = 'https://accounts.eu.adp.com/auth/oauth/v2/token'
            Method      = 'POST'
            Headers     = @{
                "content-type" = "application/x-www-form-urlencoded"
            }
            Body        = @{
                client_id     = $ClientID
                client_secret = $ClientSecret
                grant_type    = 'client_credentials'
            }
            Certificate = $certificate
        }
        Invoke-RestMethod @splatRestMethodParameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}
#endregion

try {
    # Begin
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($($config.CertificatePath), $($config.CertificatePassword))
    $accessToken = Get-ADPAccessToken -ClientID $($config.ClientID) -ClientSecret $($config.ClientSecret) -Certificate $certificate

    $headers = @{
        "Authorization" = "Bearer $($accessToken.access_token)"
    }

    
    Write-Verbose "Verify if ADPWorkforce account for: [$($p.DisplayName)] exists"
    $splatParams = @{
        Uri         = "$($config.BaseUrl)/hr/v2/worker-demographics/$aRef"
        Method      = 'GET'
        Headers     = $headers
        Certificate = $certificate
    }
    $responseGetUser = Invoke-RestMethod @splatParams

    if ($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri -ne $account.workerEmail) {
        $action = 'Update'
        $msg = "$action ADPWorkforce E-mail address: [$($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri)] to [$($account.workerEmail)] for: [$($p.DisplayName)] will be executed during enforcement"
    }
    elseif ($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri -eq $account.workerEmail) {
        $action = 'Exit'
        $msg = "E-mail address: [$($account.workerEmail)] for: [$($p.DisplayName)] does not require an update"
    }

    switch ($action) {
        'Update' {
            Write-Verbose "Updating ADPWorkforce account: [$($aRef)] for: [$($p.DisplayName)]"
            $body = @{
                events = @(@{
                        eventNameCode = @{
                            codeValue = 'worker.businessCommunication.email.change'
                        }
                        data          = @{
                            eventContext = @{
                                worker = @{
                                    workerID = @{
                                        idValue = $account.workerId
                                    }
                                }
                            }
                            transform    = @{
                                worker = @{
                                    businessCommunication = @{
                                        email = @{
                                            emailUri = $account.workerEmail
                                        }
                                    }
                                }
                            }
                        }
                    })
            } | ConvertTo-Json -Depth 10

            $splatParams = @{
                Uri         = "$($config.BaseUrl)/events/hr/v1/worker.business-communication.email.change"
                Method      = 'POST'
                Body        = $body
                Headers     = $headers
                Certificate = $certificate
                ContentType = 'application/json'
            }
            if (-not($dryRun -eq $true)) {
                $responseUpdateUser = Invoke-RestMethod @splatParams
                if ($responseUpdateUser.events[0].eventStatusCode.codeValue -eq 'submitted') {
                    $accountReference = $responseGetUser.Workers[0].associateOID
                    $success = $true
                    $auditLogs.Add([PSCustomObject]@{
                            Message = "Updated E-mail address for: $($p.DisplayName) from: [$($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri)] to: [$($account.workerEmail)]"
                            IsError = $false
                        })
                }
            }
        }

        'Exit' {
            $success = $true
            $auditLogs.Add([PSCustomObject]@{
                    Message = $msg
                    IsError = $false
                })
            break
        }
    }
    
}
catch {
    $success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -ErrorObject $ex
        $errorMessage = "Could not update ADPWorkforce E-mail address for: [$($p.DisplayName)]. Error: $($errorObj.ErrorMessage)"
    }
    else {
        $errorMessage = "Could not update ADPWorkforce E-mail address for: [$($p.DisplayName)]. Error: $($ex.Exception.Message)"
    }
    Write-Verbose $errorMessage
    $auditLogs.Add([PSCustomObject]@{
            Message = $errorMessage
            IsError = $true
        })
}
finally {
    $result = [PSCustomObject]@{
        Success   = $success
        Account   = $account
        Auditlogs = $auditLogs
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}