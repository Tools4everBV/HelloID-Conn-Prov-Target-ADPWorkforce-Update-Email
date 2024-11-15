############################################################
# HelloID-Conn-Prov-Target-ADPWorkforce-UpdateEmail-Create
# PowerShell V2
#
# Version: 1.0.0
############################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

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
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

    if (-not[string]::IsNullOrEmpty($certificateBase64)) {
        # Use for cloud PowerShell flow
        $rawCertificate = [system.convert]::FromBase64String($certificateBase64)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $($actionContext.Configuration.CertificatePassword))
    }
    elseif (-not [string]::IsNullOrEmpty($certificatePathertificatePath)) {
        # Use for local machine with certificate file
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($($actionContext.Configuration.CertificatePath, $($actionContext.Configuration.CertificatePassword)))
    }
    else {
        throw "No certificate configured"
    }

    $accessToken = Get-ADPAccessToken -ClientID $($actionContext.Configuration.ClientID) -ClientSecret $($actionContext.Configuration.ClientSecret) -Certificate $certificate
    $headers = @{
        "Authorization" = "Bearer $($accessToken.access_token)"
    }

    Write-Information "Verifying if a ADPWorkforce account for [$($personContext.Person.DisplayName)] exists"
    $splatParams = @{
        Uri         = "$($actionContext.Configuration.BaseUrl)/hr/v2/worker-demographics/$($actionContext.References.Account)"
        Method      = 'GET'
        Headers     = $headers
        Certificate = $certificate
    }
    $correlatedAccount = Invoke-RestMethod @splatParams

    if ($correlatedAccount.Workers[0].businessCommunication.emails[0].emailUri -ne $actionContext.Data.workerEmail) {
        $action = 'Update'
        $dryRunMessage = "$action ADPWorkforce E-mail address: [$($correlatedAccount.Workers[0].businessCommunication.emails[0].emailUri)] to [$($actionContext.Data.workerEmail)] for: [$($personContext.Person.DisplayName)] will be executed during enforcement"
    }
    elseif ($responscorrelatedAccounteGetUser.Workers[0].businessCommunication.emails[0].emailUri -eq $actionContext.Data.workerEmail) {
        $action = 'Exit'
        $dryRunMessage = "E-mail address: [$($actionContext.Data.workerEmail)] for: [$($personContext.Person.DisplayName)] does not require an update"
    }
    $outputContext.PreviousData = $correlatedAccount

    # Add a message and the result of each of the validations showing what will happen during enforcement
    if ($actionContext.DryRun -eq $true) {
        Write-Information "[DryRun] $dryRunMessage"
    }

    # Process
    if (-not($actionContext.DryRun -eq $true)) {
        switch ($action) {
            'UpdateAccount' {
                Write-Verbose "Updating ADPWorkforce account: [$($aRef)] for: [$($personContext.Person.DisplayName)]"
                $body = @{
                    events = @(@{
                            eventNameCode = @{
                                codeValue = 'worker.businessCommunication.email.change'
                            }
                            data          = @{
                                eventContext = @{
                                    worker = @{
                                        workerID = @{
                                            idValue = $actionContext.Data.workerId
                                        }
                                    }
                                }
                                transform    = @{
                                    worker = @{
                                        businessCommunication = @{
                                            email = @{
                                                emailUri = $actionContext.Data.workerEmail
                                            }
                                        }
                                    }
                                }
                            }
                        })
                } | ConvertTo-Json -Depth 10

                $splatParams = @{
                    Uri         = "$($actionContext.Configuration.BaseUrl)/events/hr/v1/worker.business-communication.email.change"
                    Method      = 'POST'
                    Body        = $body
                    Headers     = $headers
                    Certificate = $certificate
                    ContentType = 'application/json'
                }
                if (-not($dryRun -eq $true)) {
                    $responseUpdateUser = Invoke-RestMethod @splatParams
                    if ($responseUpdateUser.events[0].eventStatusCode.codeValue -eq 'submitted') {
                        $outputContext.AccountReference = $responseGetUser.Workers[0].associateOID
                        $outputContext.Success = $true
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = "Updated E-mail address for: $($personContext.Person.DisplayName) from: [$($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri)] to: [$($actionContext.Data.workerEmail)]"
                            IsError = $false
                        })
                    }
                }
            }

            'NoChanges' {
                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "No changes needed for account $($personContext.Person.DisplayName)"
                        IsError = $false
                    })
                break
            }

            'NotFound' {
                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "ADPWorkforce account for: [$($personContext.Person.DisplayName)] not found. Possibly deleted."
                        IsError = $false
                    })
                break
            }
        }
    }
} catch {
    $outputContext.Success  = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -ErrorObject $ex
        $auditMessage = "Could not update ADPWorkforce account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not update ADPWorkforce account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}