# CVE-2026-54124 Bounds-Check Bypass PoC

This proof of concept sends a crafted `WM_COPYDATA` handoff payload to an
x86 Windows Terminal process. In overflow mode, the serialized `args` length
has bit 31 set while the physical command string remains NUL-terminated.

On x86, multiplying the declared length by `sizeof(wchar_t)` wraps to the
physical byte length. The vulnerable build therefore accepts the field and
dispatches the command, which creates a harmless marker file. The patched
build rejects the overflowing multiplication with `SizeTMult` and does not
create the marker.

## Test targets

- Vulnerable: Windows Terminal `v1.24.10921.0` x86
- Patched: Windows Terminal `v1.24.11321.0` x86
- Operating system: Windows 10 22H2 x86

## Build

Run this command in an **x86 Native Tools Command Prompt for VS 2022**:

```bat
cl /nologo /W4 /EHsc /O2 wt_copydata_poc.cpp user32.lib /Fe:wt_copydata_poc.exe
```

## Run

Start the target `WindowsTerminal.exe`, then run the overflow case:

```bat
wt_copydata_poc.exe
```

Run the valid-length control case with:

```bat
wt_copydata_poc.exe --normal-control
```

Expected results:

| Target | Input | Marker file |
| --- | --- | --- |
| Vulnerable | Overflow | Created |
| Patched | Overflow | Not created |
| Vulnerable | Normal control | Created |
| Patched | Normal control | Created |

This PoC demonstrates the x86 integer overflow, bounds-check bypass, and
downstream command-dispatch reachability. It does not demonstrate arbitrary
memory corruption or remote code execution.
