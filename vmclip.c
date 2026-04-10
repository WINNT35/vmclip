/*
 * vmclip.c - VMware Clipboard Sync for Windows NT
 * Author: WINNT35 (Contact: WINNT35@outlook.com)
 * Copyright (C) 2026 WINNT35
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Alternative licensing terms may be available from the author upon request.
 *
 * Standalone EXE. No VMware Tools dependency.
 * Compatible with VMware Workstation 10-26, guests NT 3.51/4.0 and ReactOS.
 *
 * Build: nmake
 *
 * Layer order (low to high):
 *   Backdoor -> RPCI Channel -> Clipboard -> Sync -> WinMain
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


/* ============================================================
 * CONSTANTS AND TYPES
 * ============================================================ */

#define VMWARE_MAGIC            0x564D5868UL
#define VMWARE_CMD_PORT         0x5658
#define BDOOR_CMD_MESSAGE       0x1E

#define MESSAGE_TYPE_OPEN           0
#define MESSAGE_TYPE_SENDSIZE       1
#define MESSAGE_TYPE_SENDPAYLOAD    2
#define MESSAGE_TYPE_RECVSIZE       3
#define MESSAGE_TYPE_RECVPAYLOAD    4
#define MESSAGE_TYPE_RECVSTATUS     5
#define MESSAGE_TYPE_CLOSE          6

#define MESSAGE_STATUS_SUCCESS      0x0001
#define MESSAGE_STATUS_DORECV       0x0002

#define GUESTMSG_FLAG_COOKIE        0x80000000UL

#define RPCI_PROTO              0x49435052UL
#define TCLO_PROTO              0x4F4C4354UL

#define CLIP_MAX_BYTES          65435
#define POLL_INTERVAL_MS        300
#define TIMER_ID                1

#define CP_CMD_SEND_CLIPBOARD   2003
#define DND_CP_MSG_TYPE_CP      3
#define DND_CP_MSG_SRC_GUEST    2
#define DND_CP_MSG_HEADERSIZE_V4 (14 * sizeof(unsigned long))

typedef struct {
    unsigned long eax;
    unsigned long ebx;
    unsigned long ecx;
    unsigned long edx;
    unsigned long esi;
    unsigned long edi;
} BackdoorRegs;

typedef struct {
    char *data;
    int   len;
} RpciResponse;

typedef struct {
    int           id;
    unsigned long cookieHigh;
    unsigned long cookieLow;
} RpciChannel;

#pragma pack(push, 1)
typedef struct {
    unsigned long cmd;
    unsigned long type;
    unsigned long src;
    unsigned long sessionId;
    unsigned long status;
    unsigned long param1;
    unsigned long param2;
    unsigned long param3;
    unsigned long param4;
    unsigned long param5;
    unsigned long param6;
    unsigned long binarySize;
    unsigned long payloadOffset;
    unsigned long payloadSize;
} DnDCPMsgHdrV4;
#pragma pack(pop)

/* ============================================================
 * GLOBALS
 * ============================================================ */

static char        g_tcloReply[512];
static int         g_tcloReplyPending = 0;
static char        g_lastSentText[CLIP_MAX_BYTES + 1];
static char        g_guestClipText[CLIP_MAX_BYTES + 1];
static RpciChannel g_tcloChannel;
static int         g_tcloOpen = 0;
static unsigned long g_lastRespondedSessionId = 0xFFFFFFFFUL;

/* ============================================================
 * BACKDOOR LAYER
 * ============================================================ */

static void Backdoor_Execute(BackdoorRegs *regs)
{
    __asm {
        push esi
        push edi
        push ebx

        mov  eax, regs
        mov  ebx, [eax+4]
        mov  ecx, [eax+8]
        mov  edx, [eax+12]
        mov  esi, [eax+16]
        mov  edi, [eax+20]
        mov  eax, [eax]

        in   eax, dx

        push eax
        mov  eax, regs
        pop  dword ptr [eax]
        mov  [eax+4],  ebx
        mov  [eax+8],  ecx
        mov  [eax+12], edx
        mov  [eax+16], esi
        mov  [eax+20], edi

        pop  ebx
        pop  edi
        pop  esi
    }
}

static void Backdoor_SendData(unsigned long channel, unsigned long cookieHigh,
                              unsigned long cookieLow, const char *buf, int len)
{
    BackdoorRegs r;
    const unsigned char *p = (const unsigned char *)buf;
    int remaining = len;

    while (remaining > 0) {
        unsigned long dword = 0;

        if (remaining >= 4) {
            dword = *(const unsigned long *)p;
            remaining -= 4;
        } else if (remaining == 3) {
            dword = p[0] | ((unsigned long)p[1]<<8) | ((unsigned long)p[2]<<16);
            remaining = 0;
        } else if (remaining == 2) {
            dword = p[0] | ((unsigned long)p[1]<<8);
            remaining = 0;
        } else {
            dword = p[0];
            remaining = 0;
        }

        memset(&r, 0, sizeof(r));
        r.eax = VMWARE_MAGIC;
        r.ebx = dword;
        r.ecx = (MESSAGE_TYPE_SENDPAYLOAD << 16) | BDOOR_CMD_MESSAGE;
        r.edx = (channel << 16) | VMWARE_CMD_PORT;
        r.esi = cookieHigh;
        r.edi = cookieLow;
        Backdoor_Execute(&r);
        p += 4;
    }
}

static void Backdoor_RecvData(unsigned long channel, unsigned long cookieHigh,
                              unsigned long cookieLow, unsigned char *buf, int len)
{
    BackdoorRegs r;
    unsigned char *p = buf;
    int remaining = len;

    while (remaining > 0) {
        memset(&r, 0, sizeof(r));
        r.eax = VMWARE_MAGIC;
        r.ebx = MESSAGE_STATUS_SUCCESS;
        r.ecx = (MESSAGE_TYPE_RECVPAYLOAD << 16) | BDOOR_CMD_MESSAGE;
        r.edx = (channel << 16) | VMWARE_CMD_PORT;
        r.esi = cookieHigh;
        r.edi = cookieLow;
        Backdoor_Execute(&r);

        if (remaining >= 4) {
            *(unsigned long *)p = r.ebx;
            remaining -= 4;
        } else if (remaining == 3) {
            p[0] = (unsigned char)(r.ebx & 0xff);
            p[1] = (unsigned char)((r.ebx>>8) & 0xff);
            p[2] = (unsigned char)((r.ebx>>16) & 0xff);
            remaining = 0;
        } else if (remaining == 2) {
            p[0] = (unsigned char)(r.ebx & 0xff);
            p[1] = (unsigned char)((r.ebx>>8) & 0xff);
            remaining = 0;
        } else {
            p[0] = (unsigned char)(r.ebx & 0xff);
            remaining = 0;
        }
        p += 4;
    }
}

/* ============================================================
 * RPCI CHANNEL LAYER
 * ============================================================ */

static int RPCI_OpenChannel(RpciChannel *ch, unsigned long proto)
{
    BackdoorRegs r;

    memset(&r, 0, sizeof(r));
    r.eax = VMWARE_MAGIC;
    r.ebx = proto | GUESTMSG_FLAG_COOKIE;
    r.ecx = (MESSAGE_TYPE_OPEN << 16) | BDOOR_CMD_MESSAGE;
    r.edx = VMWARE_CMD_PORT;
    Backdoor_Execute(&r);

    if (!(r.ecx >> 16 & MESSAGE_STATUS_SUCCESS)) return 0;

    ch->id         = (int)(r.edx >> 16);
    ch->cookieHigh = r.esi;
    ch->cookieLow  = r.edi;
    return 1;
}

static void RPCI_CloseChannel(RpciChannel *ch)
{
    BackdoorRegs r;

    memset(&r, 0, sizeof(r));
    r.eax = VMWARE_MAGIC;
    r.ecx = (MESSAGE_TYPE_CLOSE << 16) | BDOOR_CMD_MESSAGE;
    r.edx = ((unsigned long)ch->id << 16) | VMWARE_CMD_PORT;
    r.esi = ch->cookieHigh;
    r.edi = ch->cookieLow;
    Backdoor_Execute(&r);
}

static int RPCI_Send(RpciChannel *ch, const char *request, int requestLen,
                     RpciResponse *resp)
{
    BackdoorRegs   r;
    int            responseLen;
    unsigned char *respBuf;

    if (resp) { resp->data = NULL; resp->len = 0; }

    memset(&r, 0, sizeof(r));
    r.eax = VMWARE_MAGIC;
    r.ebx = (unsigned long)requestLen;
    r.ecx = (MESSAGE_TYPE_SENDSIZE << 16) | BDOOR_CMD_MESSAGE;
    r.edx = ((unsigned long)ch->id << 16) | VMWARE_CMD_PORT;
    r.esi = ch->cookieHigh;
    r.edi = ch->cookieLow;
    Backdoor_Execute(&r);

    if (!(r.ecx >> 16 & MESSAGE_STATUS_SUCCESS)) return 0;

    if (requestLen > 0)
        Backdoor_SendData((unsigned long)ch->id, ch->cookieHigh, ch->cookieLow,
                          request, requestLen);

    memset(&r, 0, sizeof(r));
    r.eax = VMWARE_MAGIC;
    r.ecx = (MESSAGE_TYPE_RECVSIZE << 16) | BDOOR_CMD_MESSAGE;
    r.edx = ((unsigned long)ch->id << 16) | VMWARE_CMD_PORT;
    r.esi = ch->cookieHigh;
    r.edi = ch->cookieLow;
    Backdoor_Execute(&r);

    if (!(r.ecx >> 16 & MESSAGE_STATUS_SUCCESS)) return 0;

    responseLen = (int)r.ebx;
    respBuf = (unsigned char *)calloc(1, responseLen + 1);
    if (!respBuf) return 0;

    if (responseLen > 0)
        Backdoor_RecvData((unsigned long)ch->id, ch->cookieHigh, ch->cookieLow,
                          respBuf, responseLen);
    respBuf[responseLen] = '\0';

    memset(&r, 0, sizeof(r));
    r.eax = VMWARE_MAGIC;
    r.ebx = MESSAGE_STATUS_SUCCESS;
    r.ecx = (MESSAGE_TYPE_RECVSTATUS << 16) | BDOOR_CMD_MESSAGE;
    r.edx = ((unsigned long)ch->id << 16) | VMWARE_CMD_PORT;
    r.esi = ch->cookieHigh;
    r.edi = ch->cookieLow;
    Backdoor_Execute(&r);

    if (resp) {
        resp->data = (char *)respBuf;
        resp->len  = responseLen;
    } else {
        free(respBuf);
    }
    return 1;
}

static int RPCI_SendCommand(const char *command, RpciResponse *resp)
{
    RpciChannel ch;
    int         result;

    if (!RPCI_OpenChannel(&ch, RPCI_PROTO)) return 0;
    result = RPCI_Send(&ch, command, (int)strlen(command), resp);
    RPCI_CloseChannel(&ch);
    return result;
}

static int RPCI_Receive(RpciChannel *ch, RpciResponse *resp)
{
    BackdoorRegs   r;
    int            msgLen;
    unsigned char *msgBuf;

    if (resp) { resp->data = NULL; resp->len = 0; }

    {
        RpciResponse sendResp;
        const char  *sendData = "";
        int          sendLen  = 0;

        if (g_tcloReplyPending) {
            sendData = g_tcloReply;
            sendLen  = (int)strlen(g_tcloReply);
            sendLen  = (sendLen + 3) & ~3;
            g_tcloReplyPending = 0;
        }

        if (!RPCI_Send(ch, sendData, sendLen, &sendResp)) return 0;

        if (sendResp.data && sendResp.len > 0) {
            if (resp) {
                resp->data = sendResp.data;
                resp->len  = sendResp.len;
            } else {
                free(sendResp.data);
            }
            return 1;
        }
        if (sendResp.data) free(sendResp.data);
    }

    memset(&r, 0, sizeof(r));
    r.eax = VMWARE_MAGIC;
    r.ecx = (MESSAGE_TYPE_RECVSIZE << 16) | BDOOR_CMD_MESSAGE;
    r.edx = ((unsigned long)ch->id << 16) | VMWARE_CMD_PORT;
    r.esi = ch->cookieHigh;
    r.edi = ch->cookieLow;
    Backdoor_Execute(&r);

    if (!(r.ecx >> 16 & MESSAGE_STATUS_SUCCESS)) return 0;
    if (!(r.ecx >> 16 & MESSAGE_STATUS_DORECV))  return 0;

    msgLen = (int)r.ebx;
    msgBuf = (unsigned char *)calloc(1, msgLen + 1);
    if (!msgBuf) return 0;

    Backdoor_RecvData((unsigned long)ch->id, ch->cookieHigh, ch->cookieLow,
                      msgBuf, msgLen);
    msgBuf[msgLen] = '\0';

    memset(&r, 0, sizeof(r));
    r.eax = VMWARE_MAGIC;
    r.ebx = MESSAGE_STATUS_SUCCESS;
    r.ecx = (MESSAGE_TYPE_RECVSTATUS << 16) | BDOOR_CMD_MESSAGE;
    r.edx = ((unsigned long)ch->id << 16) | VMWARE_CMD_PORT;
    r.esi = ch->cookieHigh;
    r.edi = ch->cookieLow;
    Backdoor_Execute(&r);

    if (resp) {
        resp->data = (char *)msgBuf;
        resp->len  = msgLen;
    } else {
        free(msgBuf);
    }
    return 1;
}

/* ============================================================
 * CLIPBOARD LAYER
 * ============================================================ */

static int Clipboard_Read(char *bufOut, int maxLen)
{
    HANDLE  hMem;
    WCHAR  *pWide;
    int     wideLen, i, j, utf8Len;
    char   *utf8;

    if (!OpenClipboard(NULL)) return 0;
    hMem = GetClipboardData(CF_UNICODETEXT);
    if (!hMem) { CloseClipboard(); return 0; }
    pWide = (WCHAR *)GlobalLock(hMem);
    if (!pWide) { CloseClipboard(); return 0; }

    wideLen = 0;
    while (pWide[wideLen]) wideLen++;
    if (wideLen == 0) { GlobalUnlock(hMem); CloseClipboard(); return 0; }

    utf8Len = WideCharToMultiByte(65001, 0, pWide, wideLen, NULL, 0, NULL, NULL);
    if (utf8Len <= 0)
        utf8Len = WideCharToMultiByte(CP_ACP, 0, pWide, wideLen, NULL, 0, NULL, NULL);
    if (utf8Len <= 0) { GlobalUnlock(hMem); CloseClipboard(); return 0; }

    utf8 = (char *)malloc(utf8Len + 1);
    if (!utf8) { GlobalUnlock(hMem); CloseClipboard(); return 0; }

    if (!WideCharToMultiByte(65001, 0, pWide, wideLen, utf8, utf8Len, NULL, NULL))
        WideCharToMultiByte(CP_ACP, 0, pWide, wideLen, utf8, utf8Len, NULL, NULL);
    utf8[utf8Len] = 0;

    GlobalUnlock(hMem);
    CloseClipboard();

    j = 0;
    for (i = 0; i < utf8Len && j < maxLen - 1; i++)
        if (utf8[i] != '\r') bufOut[j++] = utf8[i];
    bufOut[j] = 0;

    free(utf8);
    return j > 0 ? 1 : 0;
}

static int Clipboard_Write(const char *buf, int len)
{
    int     wideChars, i, crCount;
    WCHAR  *pWide;
    WCHAR  *pDst;
    HGLOBAL hMem;
    HANDLE  hResult;

    if (!buf || len <= 0) return 0;

    wideChars = MultiByteToWideChar(65001, 0, buf, len, NULL, 0);
    if (wideChars <= 0)
        wideChars = MultiByteToWideChar(CP_ACP, 0, buf, len, NULL, 0);
    if (wideChars <= 0) return 0;

    pWide = (WCHAR *)malloc((wideChars + 1) * sizeof(WCHAR));
    if (!pWide) return 0;

    if (!MultiByteToWideChar(65001, 0, buf, len, pWide, wideChars))
        MultiByteToWideChar(CP_ACP, 0, buf, len, pWide, wideChars);
    pWide[wideChars] = 0;

    crCount = 0;
    for (i = 0; i < wideChars; i++)
        if (pWide[i] == L'\n') crCount++;

    if (!OpenClipboard(NULL)) { free(pWide); return 0; }
    if (!EmptyClipboard()) { CloseClipboard(); free(pWide); return 0; }

    hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT,
                       (wideChars + crCount + 1) * sizeof(WCHAR));
    if (!hMem) { CloseClipboard(); free(pWide); return 0; }

    pDst = (WCHAR *)GlobalLock(hMem);
    if (!pDst) { GlobalFree(hMem); CloseClipboard(); free(pWide); return 0; }

    for (i = 0; i < wideChars; i++) {
        if (pWide[i] == L'\n') *pDst++ = L'\r';
        *pDst++ = pWide[i];
    }
    *pDst = 0;

    free(pWide);
    GlobalUnlock(hMem);
    hResult = SetClipboardData(CF_UNICODETEXT, hMem);
    CloseClipboard();

    return hResult != NULL;
}

/* ============================================================
 * COPYPASTE TRANSPORT LAYER
 * ============================================================ */

static int CopyPaste_BuildClipboardBinary(const char *text, int textLen,
                                          unsigned char **outBuf, int *outLen)
{
    int totalSize = 4 + 1 + 4 + textLen + 1 + 30 + 1;
    unsigned char *buf = (unsigned char *)calloc(1, totalSize);
    unsigned char *p = buf;
    unsigned long val;

    if (!buf) return 0;

    val = 8;
    memcpy(p, &val, 4); p += 4;

    *p++ = 1;

    val = (unsigned long)textLen + 1;
    memcpy(p, &val, 4); p += 4;

    memcpy(p, text, textLen); p += textLen;
    *p++ = 0;

    p += 30;
    *p++ = 1;

    *outBuf = buf;
    *outLen = totalSize;
    return 1;
}

static void CopyPaste_SendTransport(const char *text, int textLen,
                                    unsigned long sessionId)
{
    RpciChannel     ch;
    RpciResponse    resp;
    unsigned char  *binary    = NULL;
    int             binaryLen = 0;
    unsigned char  *packet    = NULL;
    int             packetLen = 0;
    DnDCPMsgHdrV4   hdr;

    if (!CopyPaste_BuildClipboardBinary(text, textLen, &binary, &binaryLen))
        return;

    memset(&hdr, 0, sizeof(hdr));
    hdr.cmd           = CP_CMD_SEND_CLIPBOARD;
    hdr.type          = DND_CP_MSG_TYPE_CP;
    hdr.src           = DND_CP_MSG_SRC_GUEST;
    hdr.sessionId     = sessionId;
    hdr.param1        = 4;
    hdr.binarySize    = (unsigned long)binaryLen;
    hdr.payloadOffset = 0;
    hdr.payloadSize   = (unsigned long)binaryLen;

    packetLen = 20 + (int)DND_CP_MSG_HEADERSIZE_V4 + binaryLen;
    packet = (unsigned char *)calloc(1, packetLen);
    if (!packet) { free(binary); return; }

    memcpy(packet, "copypaste.transport ", 20);
    memcpy(packet + 20, &hdr, DND_CP_MSG_HEADERSIZE_V4);
    memcpy(packet + 20 + DND_CP_MSG_HEADERSIZE_V4, binary, binaryLen);

    if (RPCI_OpenChannel(&ch, RPCI_PROTO)) {
        RPCI_Send(&ch, (char *)packet, packetLen, &resp);
        if (resp.data) free(resp.data);
        RPCI_CloseChannel(&ch);
    }

    free(binary);
    free(packet);
}

static void CopyPaste_SendPing(void)
{
    RpciChannel   ch;
    RpciResponse  resp;
    unsigned char packet[20 + 14 * sizeof(unsigned long)];
    DnDCPMsgHdrV4 hdr;

    memset(&hdr, 0, sizeof(hdr));
    hdr.cmd    = 10001;
    hdr.type   = 1;
    hdr.src    = 0;
    hdr.param1 = 0x1555;

    memcpy(packet, "copypaste.transport ", 20);
    memcpy(packet + 20, &hdr, DND_CP_MSG_HEADERSIZE_V4);

    if (RPCI_OpenChannel(&ch, RPCI_PROTO)) {
        RPCI_Send(&ch, (char *)packet, sizeof(packet), &resp);
        if (resp.data) free(resp.data);
        RPCI_CloseChannel(&ch);
    }
}

static const char *CopyPaste_ParseTransport(const char *buf, int len, int *textLen)
{
    const unsigned char *p = (const unsigned char *)buf;
    const unsigned char *end = p + len;
    unsigned long pktType;
    unsigned long strLen;

    if (len < 76) return NULL;

    p += 20;
    pktType = p[0] | ((unsigned long)p[1]<<8) |
              ((unsigned long)p[2]<<16) | ((unsigned long)p[3]<<24);
    if (pktType != 0x07D2) return NULL;

    p += 16;
    p += 32;
    p += 8;

    if (p + 9 > end) return NULL;

    p += 4;
    p += 1;

    strLen = p[0] | ((unsigned long)p[1]<<8) |
             ((unsigned long)p[2]<<16) | ((unsigned long)p[3]<<24);
    p += 4;

    if (strLen == 0 || strLen > 65535) return NULL;
    if (p + strLen > end) return NULL;
    if (strLen > 0 && p[strLen-1] == 0) strLen--;
    if (strLen == 0) return NULL;

    *textLen = (int)strLen;
    return (const char *)p;
}

/* ============================================================
 * SYNC LOGIC LAYER
 * ============================================================ */

static void Sync_SendCapabilities(void)
{
    RpciResponse resp;

    RPCI_SendCommand("tools.capability.dnd_version 4", &resp);
    if (resp.data) free(resp.data);

    RPCI_SendCommand("vmx.capability.dnd_version", &resp);
    if (resp.data) free(resp.data);

    RPCI_SendCommand("tools.capability.copypaste_version 4", &resp);
    if (resp.data) free(resp.data);

    RPCI_SendCommand("vmx.capability.copypaste_version", &resp);
    if (resp.data) free(resp.data);

    CopyPaste_SendPing();
}

static void Sync_Init(void)
{
    Sync_SendCapabilities();

    if (!RPCI_OpenChannel(&g_tcloChannel, TCLO_PROTO))
        g_tcloOpen = 0;
    else
        g_tcloOpen = 1;

    memset(g_lastSentText,    0, sizeof(g_lastSentText));
    memset(g_guestClipText,   0, sizeof(g_guestClipText));
}

static void Sync_HandleTcloCommand(const char *cmd, int len)
{
    if (strcmp(cmd, "reset") == 0) {
        _snprintf(g_tcloReply, sizeof(g_tcloReply), "OK ATR toolbox-dnd");
        g_tcloReplyPending = 1;

    } else if (strcmp(cmd, "ping") == 0) {
        _snprintf(g_tcloReply, sizeof(g_tcloReply), "OK ");
        g_tcloReplyPending = 1;

    } else if (strncmp(cmd, "Capabilities_Register", 21) == 0) {
        Sync_SendCapabilities();
        _snprintf(g_tcloReply, sizeof(g_tcloReply), "OK ");
        g_tcloReplyPending = 1;

    } else if (strncmp(cmd, "unity.show.taskbar", 18) == 0) {
        _snprintf(g_tcloReply, sizeof(g_tcloReply), "OK ");
        g_tcloReplyPending = 1;

	} else if (strncmp(cmd, "copypaste.transport", 19) == 0) {
		const unsigned char *hdrp = (const unsigned char *)cmd + 20;
		unsigned long pktCmd;
		unsigned long sessionId;
		const char *text;
		int textLen;
		static char tmp[CLIP_MAX_BYTES + 1];
		int copyLen;

		pktCmd = hdrp[0] | ((unsigned long)hdrp[1]<<8) |
				 ((unsigned long)hdrp[2]<<16) | ((unsigned long)hdrp[3]<<24);
		sessionId = hdrp[12] | ((unsigned long)hdrp[13]<<8) |
					((unsigned long)hdrp[14]<<16) | ((unsigned long)hdrp[15]<<24);

		if (pktCmd == 0x7D0) {
			if (g_guestClipText[0] != '\0') {
				g_lastRespondedSessionId = sessionId;
				CopyPaste_SendTransport(g_guestClipText,
									   (int)strlen(g_guestClipText), sessionId);
			}
			_snprintf(g_tcloReply, sizeof(g_tcloReply), "OK ");
			g_tcloReplyPending = 1;
			return;
		}

		/* Ignore echo of our last send */
		if (sessionId == g_lastRespondedSessionId) {
			_snprintf(g_tcloReply, sizeof(g_tcloReply), "OK ");
			g_tcloReplyPending = 1;
			return;
		}

		text = CopyPaste_ParseTransport(cmd, len, &textLen);
		if (text && textLen > 0) {
			copyLen = textLen < CLIP_MAX_BYTES ? textLen : CLIP_MAX_BYTES;
			memcpy(tmp, text, copyLen);
			tmp[copyLen] = 0;
			if (strcmp(tmp, g_guestClipText) != 0)
				Clipboard_Write(text, textLen);
		}
		_snprintf(g_tcloReply, sizeof(g_tcloReply), "OK ");
		g_tcloReplyPending = 1;
    } else {
        _snprintf(g_tcloReply, sizeof(g_tcloReply), "ERROR Unknown command");
        g_tcloReplyPending = 1;
    }
}

static void Sync_Poll(void)
{
    char buf[CLIP_MAX_BYTES + 1];

    if (g_tcloOpen) {
        RpciResponse tcloResp;
        if (RPCI_Receive(&g_tcloChannel, &tcloResp)) {
            if (tcloResp.data) {
                Sync_HandleTcloCommand(tcloResp.data, tcloResp.len);
                free(tcloResp.data);
            }
        }
    }

    if (!Clipboard_Read(buf, sizeof(buf))) return;
    if (strcmp(buf, g_lastSentText) == 0) return;

    strncpy(g_lastSentText,  buf, CLIP_MAX_BYTES);
    g_lastSentText[CLIP_MAX_BYTES] = 0;
    strncpy(g_guestClipText, buf, CLIP_MAX_BYTES);
    g_guestClipText[CLIP_MAX_BYTES] = 0;

	CopyPaste_SendTransport(buf, (int)strlen(buf), 0);
}

/* ============================================================
 * WINMAIN
 * ============================================================ */

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg,
                                 WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_TIMER && wParam == TIMER_ID) {
        Sync_Poll();
        return 0;
    }
    if (msg == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASS wc;
    MSG      msg;
    HWND     hwnd;

    (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = "vmclip";
    if (!RegisterClass(&wc)) return 1;

    hwnd = CreateWindow("vmclip", "vmclip",
                          WS_OVERLAPPEDWINDOW,
                          0, 0, 0, 0,
                          NULL, NULL, hInstance, NULL);
    if (!hwnd) return 1;

    memset(g_lastSentText, 0, sizeof(g_lastSentText));

    Sync_Init();

    SetTimer(hwnd, TIMER_ID, POLL_INTERVAL_MS, NULL);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    KillTimer(hwnd, TIMER_ID);
    if (g_tcloOpen) RPCI_CloseChannel(&g_tcloChannel);
    return (int)msg.wParam;
}