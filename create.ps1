############################################################
# HelloID-Conn-Prov-Target-ADPWorkforce-UpdateEmail-Create
# PowerShell V2
#
# Version: 2.0.1
############################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#TEST
#$actionContext.DryRun = $false

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
    # Initial Assignments
    $outputContext.AccountReference = 'Currently not available'

    # Validate correlation configuration
    if ($actionContext.CorrelationConfiguration.Enabled) {
        $correlationField = $actionContext.CorrelationConfiguration.accountField
        $correlationValue = $actionContext.CorrelationConfiguration.accountFieldValue

        if ([string]::IsNullOrEmpty($($correlationField))) {
            throw 'Correlation is enabled but not configured correctly'
        }
        if ([string]::IsNullOrEmpty($($correlationValue))) {
            throw 'Correlation is enabled but [accountFieldValue] is empty. Please make sure it is correctly mapped'
        }

        # Verify if a user must be either [created] or just [correlated]
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($actionContext.Configuration.CertificatePath, $actionContext.Configuration.CertificatePassword)
        $accessToken = Get-ADPAccessToken -ClientID $($actionContext.Configuration.ClientID) -ClientSecret $($actionContext.Configuration.ClientSecret) -Certificate $certificate
        
        $headers = @{
            "Authorization" = "Bearer $($accessToken.access_token)"
        }
    
        Write-Verbose "Verify if ADPWorkforce account for: [$($personContext.Person.DisplayName)] exists"
     
        $splatParams = @{
            Uri         = "$($actionContext.Configuration.BaseUrl)/hr/v2/worker-demographics/$($correlationValue)"
            Method      = 'GET'
            Headers     = $headers
            Certificate = $certificate
        }
        $responseGetUser = Invoke-RestMethod @splatParams


        if ($responseGetUser.Workers[0].associateOID -eq $($correlationValue)) {
            # If the E-mail address in HelloID matches with the E-mail address in ADPWorkforce -> Correlate
            Write-Verbose "Verifying if the E-mail address for: [$($personContext.Person.DisplayName)] must be updated" -verbose
            if ($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri -eq $actionContext.Data.workerEmail) {
                $action = 'Correlate'
            } # If the E-mail address in HelloID differs from the E-mail address in ADPWorkforce -> CorrelateUpdate
            elseif ($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri -ne $actionContext.Data.workerEmail) {
                $action = 'Correlate-Update'
            }
        }
        $correlatedAccount = $responseGetUser
    }

    # Add a message and the result of each of the validations showing what will happen during enforcement
    if ($actionContext.DryRun -eq $true) {
        Write-Information "[DryRun] $action ADPWorkforce account for: [$($personContext.Person.DisplayName)], will be executed during enforcement"
        $outputContext.Success = $true
    }
    
    # Process
    if (-not($actionContext.DryRun -eq $true)) {
    switch ($action) {
        'Correlate' {
            Write-Verbose "Correlating ADPWorkforce account for: [$($personContext.Person.DisplayName)]"
            $outputContext.AccountReference = $responseGetUser.Workers[0].associateOID
            $outputContext.success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Correlated ADPWorkforce account for: $($personContext.Person.DisplayName) - does not require an update"
                    IsError = $false
                })
            break
        }

        'Correlate-Update' {
            Write-Verbose "Correlating and updating ADPWorkforce account for: [$($personContext.Person.DisplayName)]"
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
                    $outputContext.success = $true
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = "Correlated ADPWorkforce account and updated E-mail address for: $($personContext.Person.DisplayName) from: [$($responseGetUser.Workers[0].businessCommunication.emails[0].emailUri)] to: [$($actionContext.Data.workerEmail)]"
                            IsError = $false
                        })
                }
            }
        }
    }}
} catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-ADPWorkforceError -ErrorObject $ex
        $auditMessage = "Could not update or correlate ADP-UpdateEmail account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not update or correlate ADP-UpdateEmail account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}