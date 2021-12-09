############################################################
# HelloID-Conn-Prov-Target-ADPWorkforce-UpdateEmail-Create
#
# Version: 1.0.0
############################################################
$VerbosePreference = "Continue"

# Initialize default value's
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$success = $false
$auditLogs = New-Object Collections.Generic.List[PSCustomObject]

# Mapping
$account = @{
    workerId    = $p.ExternalId
    workerEmail = $p.Contact.Business.Email
}

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
        Url         = "$($config.BaseUrl)/hr/v2/worker-demographics/$($p.Custom.AssociateOID)"
        Method      = 'GET'
        AccessToken = $accessToken.access_token
        Certificate = $certificate
    }
    $responseGetUser = Invoke-RestMethod @splatParams

    if ($responseGetUser.Workers[0].associateOID -eq $($p.Custom.AssociateOID)){
        # If the eMailAddress in HelloID matches with the eMailAddress in ADPWorkforce -> Correlate
        Write-Verbose "Verifying if the emailAddress for: [$($p.DisplayName)] must be updated"
        if ($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri -eq $o.Contact.Business.Email){
            $action = 'Correlate'
            # If the eMailAddress in HelloID differs from the eMailAddress in ADPWorkforce -> Correlate-Update
        } elseif ($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri -ne $o.Contact.Business.Email){
            $action = 'Correlate-Update'
        }

        $msg = "$action ADPWorkforce account for: [$($p.DisplayName)] will be executed during enforcement"
    }

    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun -eq $true){
        $auditLogs.Add([PSCustomObject]@{
            Message = $msg
            IsError = $false
        })
    }

    # Process
    if (-not($dryRun -eq $true)){
        switch ($action){
            'Correlate' {
                Write-Verbose "Correlating ADPWorkforce account for: [$($p.DisplayName)]"
                $accountReference = $responseGetUser.Workers[0].associateOID
                $success = $true
                $auditLogs.Add([PSCustomObject]@{
                    Message = "Correlated ADPWorkforce account for: $($p.DisplayName)"
                    IsError = $false
                })
                break
            }

            'Correlate-Update' {
                Write-Verbose "Correlating and updating ADPWorkforce account for: [$($p.DisplayName)]"
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
                        Message = "Correlated ADPWorkforce account and updated emailAddress for: $($p.DisplayName)"
                        IsError = $false
                    })
                }
            }
        }
    }
} catch {
    $success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
    $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -ErrorObject $ex
        $errorMessage = "Could not $action ADPWorkforce emailAddress account for: [$($p.DisplayName)]. Error: $($errorObj.ErrorMessage)"
    } else {
        $errorMessage = "Could not $action ADPWorkforce emailAddress account for: [$($p.DisplayName)]. Error: $($ex.Exception.Message)"
    }
    Write-Verbose $errorMessage
    $auditLogs.Add([PSCustomObject]@{
        Message = $errorMessage
        IsError = $true
    })
# End
} finally {
   $result = [PSCustomObject]@{
        Success          = $success
        AccountReference = $accountReference
        Auditlogs        = $auditLogs
        Account          = $account
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
