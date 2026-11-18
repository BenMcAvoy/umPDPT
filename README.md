# umPDPT

umPDPT is a Windows kernel-driver and user-mode client communication experiment. The solution contains a WDK driver, a small client and an IOCTL path for sharing diagnostic data between them.

## Build

Open `umPDPT.sln` in Visual Studio with the Windows Driver Kit installed, then build the x64 configuration.

## Status

This is a low-level systems prototype, not a general-purpose driver. Some request handlers are still placeholders; use only in a controlled development environment.
