# HelloID-Conn-Prov-Target-ADPWorkforce-UpdateEmail

<p align="center">
  <img src="https://www.adp.nl/roxen-local/img/logo.png">
</p>

## Table of contents

- [Introduction](#Introduction)
- [Getting started](#Getting-started)
  + [Connection settings](#Connection-settings)
  + [Prerequisites](#Prerequisites)
  + [Remarks](#Remarks)
- [Getting help](#Getting-help)
- [HelloID Docs](#HelloID-docs)

## Introduction

_HelloID-Conn-Prov-Target-ADPWorkforce-UpdateEmail_ is a _target_ connector. ADP Workforce provides a set of REST API's that allow you to programmatically interact with it's data.

> This connector only updates the email address for a worker

## Getting started

Note that this connector only updates the email address for a worker. The _create.ps1_ does not create accounts but merely correlates a HelloID person with an ADP Workforce worker.

### Connection settings

The following settings are required to connect to the ADP Workforce:

| Setting      | Description                        | Mandatory   |
| ------------ | -----------                        | ----------- |
| BaseUrl      | The BaseUrl to the ADP Workforce environment | Yes |
| ClientID     | The ClientID for the ADP Workforce environment. This will be provided by ADP | Yes |
| ClientSecret | The ClientSecret for the ADP Workforce environment. This will be provided by ADP | Yes |
| CertificatePath | The location to the 'private key of the x.509 certificate' on the server where the HelloID agent and provisioning agent are running. Make sure to use the private key for the certificate that's used to generate a ClientID and ClientSecret and for activating the required API's | Yes |
| CertificatePassword | The password for the *.pfx certificat | Yes |

### Prerequisites

- Windows PowerShell 5.1 installed on the server where the 'HelloID agent and provisioning agent' are running.

- The public key *.pfx certificate belonging to the X.509 certificate that's used to activate the required API's.

- The password for the public key *.pfx certificate.

- The 'Execute on-premises' switch on the 'System' tab is toggled.

#### X.509 certificate / public key

To obtain access to the ADP Workforce API's, a x.509 certificate is needed. This certificate has to be created by the customer.

The public key belonging to the certificate, must be send ADP. ADP will then generate a ClientID and ClientSecret and will activate the required API's.

There are a few options for creating certificates. One of them being the 'OpenSSL' utility. Available on Linux/Windows. https://www.openssl.org/

APD will register an application that's allowed to access the specified API's. _worker-demographics_ and _organizational_departments_. Other API's within your ADP Workforce environment may not be accessible.

### Remarks

#### CustomField `Custom.AssociateOID`

This connector uses the `Custom.AssociateOID` field from HelloID. This field must be created and mapped in the HelloID ADP Workforce source connector.

#### EmailAddress

This connector is meant to update the emailAddress for a worker in ADP Workforce

## Getting help

> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012558020-Configure-a-custom-PowerShell-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
