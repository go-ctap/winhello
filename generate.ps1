go tool cgo -godefs types_webauthn.go |
        ForEach-Object { $_.Replace('package winhello', "package winhello`r`n`r`nimport `"golang.org/x/sys/windows`"") } |
        ForEach-Object { $_.Replace('_Ctype_struct__GUID', 'windows.GUID') } |
        ForEach-Object { $_.Replace('*_Ctype_struct_HWND__', 'windows.HWND') } |
        Set-Content -Path ztypes_webauthn.go -Encoding UTF8
