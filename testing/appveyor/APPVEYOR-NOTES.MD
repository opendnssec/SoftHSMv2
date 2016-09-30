# AppVeyor integration with SoftHSMv2 on GitHub

This document describes the process of integrating AppVeyor with SoftHSMv2 on GitHub.

## Integration

### Add project

To add the project, click on the following:

1. New Project
2. GitHub
3. opendnssec -> SoftHSMv2 -> Add

### Settings

The following settings where changed.

#### General

* Custom configuration .yml file name: .appveyor.yml
* Skip branches without appveyor.yml: check

## Dependencies

Prebuilt dependencies (OpenSSL and CppUnit) are currently hosted in a dedicated
repository by [disig/SoftHSM2-AppVeyor](https://github.com/disig/SoftHSM2-AppVeyor/)
