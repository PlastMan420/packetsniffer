#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <iostream>
#include "ipv4_struct.h"

#pragma comment(lib, "Ws2_32.lib")
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

class PacketSniffer {
    public:
    bool Init();
    void Sniff(SOCKET* sniffer);
    ~PacketSniffer();
    WSADATA wsaData;
    SOCKET sniffer;

    private:
    bool StartWinSock();
    void displayLastError();
    void PrintTcpPacket(char* Buffer, int Size);
    void ProcessPacket(char* Buffer, int Size, wchar_t ipStringBuffer[INET_ADDRSTRLEN]);
    void PrintIcmpPacket(char* Buffer, int Size);

    INT bindSocket(SOCKET* snifferm);

    const int packetSize = 65536;
};
    