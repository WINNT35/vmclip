# VMCLIP - VMware Clipboard Sync for Windows NT
# Usage: nmake
#
# Requires either MSDEVDIR (SDK) or NTDDK (DDK) to be set
# Example: set MSDEVDIR=C:\MSDEV
#      or: set NTDDK=C:\NTDDK
CC   = cl
LINK = link
# ---------------------------------------------------------------
# Validate required environment variables
# Supports either MSDEVDIR (SDK) or NTDDK (DDK)
# ---------------------------------------------------------------
!IF !DEFINED(MSDEVDIR) && !DEFINED(NTDDK)
!ERROR Neither MSDEVDIR nor NTDDK environment variable is set.
!ERROR Set one of:
!ERROR   set MSDEVDIR=C:\MSDEV   (SDK)
!ERROR   set NTDDK=C:\NTDDK      (DDK)
!ENDIF
!IFDEF MSDEVDIR
SDK_INC = $(MSDEVDIR)\INCLUDE
SDK_LIB = $(MSDEVDIR)\LIB
!ELSE
SDK_INC = $(NTDDK)\inc
SDK_LIB = $(NTDDK)\lib\i386\free
!ENDIF
# ---------------------------------------------------------------
# Compiler and linker flags
# ---------------------------------------------------------------
CFLAGS = -c -G3 -nologo -D_X86_ -O2 -W3
INCLUDES = -I$(SDK_INC)
LFLAGS = /NOLOGO \
         /SUBSYSTEM:WINDOWS \
         /MACHINE:IX86 \
         /INCREMENTAL:NO
LIBS = $(SDK_LIB)\kernel32.lib \
       $(SDK_LIB)\user32.lib
# ---------------------------------------------------------------
# Targets
# ---------------------------------------------------------------
all: VMCLIP.exe

VMCLIP.obj: VMCLIP.c
	$(CC) $(CFLAGS) $(INCLUDES) VMCLIP.c

VMCLIP.exe: VMCLIP.obj
	$(LINK) $(LFLAGS) /OUT:VMCLIP.exe VMCLIP.obj $(LIBS)
# ---------------------------------------------------------------
# Clean
# ---------------------------------------------------------------
clean:
	-del *.obj
	-del VMCLIP.exe