# winhello

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ctap/winhello.svg)](https://pkg.go.dev/github.com/go-ctap/winhello)
[![Go](https://github.com/go-ctap/winhello/actions/workflows/go.yml/badge.svg)](https://github.com/go-ctap/winhello/actions/workflows/go.yml)

winhello is a Go library that provides bindings to the Windows WebAuthn API (Windows Hello), enabling authentication
using Windows Hello biometrics or security keys in Go applications.

## Features

- Create and manage WebAuthn credentials
- Authenticate users with Windows Hello
- Support for WebAuthn extensions (`hmac-secret`, `prf`, `credBlob`, etc.)
- Hidden window management for authentication dialogs

## Method support

- [x] WebAuthNAuthenticatorGetAssertion
    - [x] WebAuthNFreeAssertion
- [x] WebAuthNAuthenticatorMakeCredential
    - [x] WebAuthNFreeCredentialAttestation
- [x] WebAuthNCancelCurrentOperation
- [x] WebAuthNDeletePlatformCredential
- [x] WebAuthNGetApiVersionNumber
- [x] WebAuthNGetCancellationId
- [x] WebAuthNGetErrorName
- [x] WebAuthNGetPlatformCredentialList
    - [x] WebAuthNFreePlatformCredentialList
- [x] WebAuthNGetW3CExceptionDOMError
- [x] WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable

## Installation

```bash
go get github.com/go-ctap/winhello
```

## Usage

See a small [example](/example).

## Requirements

- Windows 10 or later
- Go 1.24 or later
