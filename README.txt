VMCLIP - VMware Clipboard Sync for Windows NT
=============================================
Version 1.0
Author: WINNT35
Contact: WINNT35@outlook.com
Release Date: 2026-04-10

DESCRIPTION
-----------
VMCLIP enables clipboard sync (text only) between a VMware host and a Windows NT guest. Copy text on the host and paste in the guest, or vice versa. No VMware Tools installation required.


DOWNLOAD
--------
Precompiled binaries are available on the GitHub Releases page:
https://github.com/WINNT35/VMCLIP/releases


TESTED ON
---------
- Windows NT 3.51 or 4.0 (primary targets)
- ReactOS 0.4.15 (x86)
- VMware Workstation 10 and 15.5 pro.


INSTALLATION
------------
Loading the files onto an ISO or IMG file is the best way
to transfer them to the guest virtual machine.

Run VMCLIP.EXE to start clipboard sync. To start it
automatically at login, place VMCLIP.EXE in your Startup
folder in Program Manager.


FILES
-----
readme.txt   - This file
vmclip.exe   - Clipboard sync program


KNOWN LIMITATIONS
-----------------
- Text only. Images, files, and rich content are not supported.
- Maximum clipboard size: 64 KB


KNOWN COMPATIBILITY NOTES
--------------------------
Windows NT 5.0 and later (Windows 2000, XP, etc.) are not tested.
Real VMware Tools is fully supported on those versions -- use that
instead. Tested on Windows Vista, 7, and 10 hosts.


HOW IT WORKS
------------
VMware exposes a hidden communication channel between the host and guest via a special I/O port. VMCLIP uses this channel to exchange clipboard data with the host using the same protocol that VMware's own tools use internally. Every 300 ms it checks the guest clipboard for changes and sends them to the host, while also receiving any clipboard updates the host has waiting. No kernel driver, no hooking; just a hidden window and a timer.


REFERENCES
----------
open-vm-tools - VMware open source tools for Linux
https://github.com/vmware/open-vm-tools


LICENSE
-------
This software is licensed under the GNU General Public License
version 2 or later. It may be licensed under different terms with written permission of the author.

Contact WINNT35@outlook.com for alternative licensing inquiries.


SOURCE CODE
-----------
Built with MSVC 4 and the Windows NT 3.51 DDK. To build from source, run nmake.
Source code available at:
https://github.com/WINNT35/VMCLIP