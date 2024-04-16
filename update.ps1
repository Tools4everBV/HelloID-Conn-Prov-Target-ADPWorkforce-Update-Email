############################################################
# HelloID-Conn-Prov-Target-ADPWorkforce-UpdateEmail-Create
# PowerShell V2
#
# Version: 2.0.1
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


function Resolve-ADPWorkforceError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
            # Make sure to inspect the error result object and add only the error message as a FriendlyMessage.
            # $httpErrorObj.FriendlyMessage = $errorDetailsObject.message
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails # Temporarily assignment
        } catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
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

    Write-Information "Verifying if a ADPWorkfroce account for [$($personContext.Person.DisplayName)] exists"
    
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($($actionContext.Configuration.CertificatePath), $($actionContext.Configuration.CertificatePassword))
    $accessToken = Get-ADPAccessToken -ClientID $($actionContext.Configuration.ClientID) -ClientSecret $($actionContext.Configuration.ClientSecret) -Certificate $certificate

    $headers = @{
        "Authorization" = "Bearer $($accessToken.access_token)"
    }

        $splatParams = @{
            Uri         = "$($actionContext.Configuration.BaseUrl)/hr/v2/worker-demographics/$($actionContext.References.Account)"
            Method      = 'GET'
            Headers     = $headers
            Certificate = $certificate
        }
        $responseGetUser = Invoke-RestMethod @splatParams

    if ($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri -ne $actionContext.Data.workerEmail) {
        $action = 'Update'
        $msg = "$action ADPWorkforce E-mail address: [$($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri)] to [$($actionContext.Data.workerEmail)] for: [$($personContext.Person.DisplayName)] will be executed during enforcement"
    }
    elseif ($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri -eq $actionContext.Data.workerEmail) {
        $action = 'Exit'
        $msg = "E-mail address: [$($actionContext.Data.workerEmail)] for: [$($personContext.Person.DisplayName)] does not require an update"
    }


    $correlatedAccount = $responseGetUser
    $outputContext.PreviousData = $responseGetUser

    # Always compare the account against the current account in target system
    if ($null -ne $correlatedAccount) {
        $splatCompareProperties = @{
            ReferenceObject  = $correlatedAccount.PSObject.Properties
            DifferenceObject = $actionContext.Data.PSObject.Properties
        }
        $propertiesChanged = Compare-Object @splatCompareProperties -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
        if ($propertiesChanged) {
            $action = 'UpdateAccount'
            $dryRunMessage = "Account property(s) required to update: $($propertiesChanged.Name -join ', ')"
        } else {
            $action = 'NoChanges'
            $dryRunMessage = 'No changes will be made to the account during enforcement'
        }
    } else {
        $action = 'NotFound'
        $dryRunMessage = "ADPWorkforce account for: [$($personContext.Person.DisplayName)] not found. Possibly deleted."
    }


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
        $errorObj = Resolve-ADPWorkforceError -ErrorObject $ex
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