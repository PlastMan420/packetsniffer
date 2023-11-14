#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <malloc.h>
#include <memory>
#include <iostream>
#include <chrono>
#include <thread>
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

        //void PrintTcpPacket(char* Buffer, int Size);

        //void PrintIpHeader(char* Buffer);

        //void ProcessPacket(char* Buffer, int Size);
        
        void displayLastError();

        INT bindSocket(SOCKET* snifferm, BOOL* bNewBehavior);

        const int packetSize = 65536;


        // local is a HOSTENT pointer that contains the list of local ip addresses.

        int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0;
};
    