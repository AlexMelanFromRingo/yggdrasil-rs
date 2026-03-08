# contrib/windows

## wintun.dll

To build with `--features embedded-wintun` (embeds wintun.dll in the binary),
place the correct `wintun.dll` here before building.

### Where to get it

Download from https://wintun.net — the official WireGuard/Wintun release site.
The driver is MIT licensed (same as WireGuard).

Unzip and copy the DLL matching your target architecture:

| Target                        | DLL path in zip         |
|-------------------------------|-------------------------|
| x86_64-pc-windows-msvc        | `amd64\wintun.dll`      |
| i686-pc-windows-msvc          | `x86\wintun.dll`        |
| aarch64-pc-windows-msvc       | `arm64\wintun.dll`      |

### Build with embedded DLL

```powershell
# Copy the DLL here first
copy path\to\wintun\amd64\wintun.dll contrib\windows\wintun.dll

# Build with embedded-wintun feature
cargo build --release --features embedded-wintun
```

The resulting `yggdrasil.exe` will extract `wintun.dll` to
`%TEMP%\yggdrasil-rs\wintun.dll` at startup — users do not need to manage
the DLL manually.

### Without embedding

Without `--features embedded-wintun`, place `wintun.dll` in the same directory
as `yggdrasil.exe` and run as Administrator.
