# Sandbox

## Disable Tamper Protection


## Disabling Windows Defender

1. Open Windows Security
1. Disable `Real-time protection` and `Tamper protection`
1. Open the registry editor
1. Navigate to `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender`
1. Create a new `DWORD (32-bit) Value` key called `DisableAntiSpyware`
1. Set the value to `1`
1. Restart the machine.

## References

1. https://answers.microsoft.com/en-us/windows/forum/all/how-can-i-permanently-disable-or-remove-windows/7e3ce6d4-231f-4bee-912c-3cc031a9bf8d
