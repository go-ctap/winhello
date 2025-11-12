package main

import (
	"github.com/go-ctap/winhello"
	"golang.org/x/sys/windows"
)

type PluginRequestType uint32

const (
	PluginRequestTypeCTAP2CBOR PluginRequestType = iota
)

type PluginOperationRequest struct {
	WindowHandle                 windows.HWND
	TransactionID                windows.GUID
	RequestSignature             []byte
	RequestType                  PluginRequestType
	EncodedRequest               []byte
	DecodedMakeCredentialRequest *winhello.MakeCredentialRequest
	DecodedGetAssertionRequest   *winhello.CTAPCBORGetAssertionRequest
}

type PluginCancelOperationRequest struct {
	TransactionID    windows.GUID
	RequestSignature []byte
}

type PluginLockStatus uint32

const (
	PluginLockStatusUnlocked PluginLockStatus = iota
	PluginLockStatusLocked
)
