############################################################
# HelloID-Conn-Prov-Target-ADPWorkforce-UpdateEmail-Update
#
# Version: 1.0.0
############################################################
# Initialize default value's
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$success = $false
$auditLogs = New-Object Collections.Generic.List[PSCustomObject]

# Mapping
$account = @{
    workerId    = $p.ExternalId
    workerEmail = $p.Contact.Business.Email
}

#region debug logging
switch ($($config.IsDebug)) {
    $true {
        $VerbosePreference = "Continue"
    }
    $false {
        $VerbosePreference = "SilentyContinue"
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
    } catch {
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
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}
#endregion

try {
    # Begin
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($($config.CertificatePath), $(config.CertificatePassword))
    $accessToken = Get-ADPAccessToken -ClientID $($config.ClientID) -ClientSecret $($config.ClientSecret) -Certificate $certificate

    Write-Verbose "Verify if ADPWorkforce account for: [$($p.DisplayName)] exists"
    $splatParams = @{
        Url         = "$($config.BaseUrl)/hr/v2/worker-demographics/$aRef"
        Method      = 'GET'
        AccessToken = $accessToken.access_token
        Certificate = $certificate
    }
    $responseGetUser = Invoke-RestMethod @splatParams

    if ($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri -ne $p.Contact.Business.Email){
        $action = 'Update'
        $msg = "$action ADPWorkforce eMailAddress: [$($p.Contact.Business.Email)] for: [$($p.DisplayName)] will be executed during enforcement"
    } elseif ($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri -eq $p.Contact.Business.Email){
        $action = 'Exit'
        $msg = "eMailAddress: [$($p.Contact.Business.Email)] for: [$($p.DisplayName)] does not require an update"
    }

    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun -eq $true){
        $auditLogs.Add([PSCustomObject]@{
            Message = $msg
        })
    }

    if (-not($dryRun -eq $true)) {
        switch ($action){
            'Update' {
                Write-Verbose "Updating ADPWorkforce account: [$($aRef)] for: [$($p.DisplayName)]"
                $body = @{
                    events = @(@{
                        eventNameCode = @{
                            codeValue = 'worker.businessCommunication.email.change'
                        }
                        data = @{
                            eventContext = @{
                                worker = @{
                                    workerID = @{
                                        idValue = $account.workerId
                                    }
                                }
                            }
                            transform = @{
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
                    Url         = "$($config.BaseUrl)/events/hr/v1/worker.business-communication.email.change"
                    Method      = 'POST'
                    Body        = $body
                    AccessToken = $accessToken.access_token
                    Certificate = $certificate
                    ContentType = 'application/json'
                }
                $responseUpdateUser = Invoke-RestMethod @splatParams
                if ($responseUpdateUser.events[0].eventStatusCode.codeValue -eq 'submitted'){
                    $accountReference = $responseGetUser.Workers[0].associateOID
                    $success = $true
                    $auditLogs.Add([PSCustomObject]@{
                        Message = "Updated emailAddress for: $($p.DisplayName)"
                        IsError = $false
                    })
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
} catch {
    $success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
    $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -ErrorObject $ex
        $errorMessage = "Could not update ADPWorkforce emailAddress for: [$($p.DisplayName)]. Error: $($errorObj.ErrorMessage)"
    } else {
        $errorMessage = "Could not update ADPWorkforce emailAddress for: [$($p.DisplayName)]. Error: $($ex.Exception.Message)"
    }
    Write-Verbose $errorMessage
    $auditLogs.Add([PSCustomObject]@{
        Message = $errorMessage
        IsError = $true
    })
} finally {
    $result = [PSCustomObject]@{
        Success   = $success
        Account   = $account
        Auditlogs = $auditLogs
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}