#include "PacketSniffer.h"

bool PacketSniffer::Init() {
    std::string hostname(new char[256]);
    BOOL bNewBehavior = TRUE;
    DWORD dwBytesReturnedBuffer = 0;
    LPDWORD dwBytesReturned = &dwBytesReturnedBuffer;

    // Init Winsock.
    bool initwinsockres = StartWinSock();
    if (!initwinsockres) {
        return false;
    }

    /*
     * If you use it (IPPROTO_IP), and if the socket type is SOCK_STREAM and the family is AF_INET,
     * then the protocol will automatically be TCP (exactly the same as if you'd used IPPROTO_TCP).
     * Buf if you use IPPROTO_IP together with AF_INET and SOCK_RAW, you will have an error,
     * because the kernel (linux in their case) cannot choose a protocol automatically in this case.
     * sauce: https://stackoverflow.com/questions/24590818/what-is-the-difference-between-ipproto-ip-and-ipproto-raw
     *
     * tl;dr: IPPROTO_IP + AF_INET + SOCK_STREAP = TCP
     */

    /*
     * AF_INET = IPv4, AF_INET6 for IPv6
     */

    // 1 Create a raw socket
    fmt::print("Creating socket\n");
    sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

    if(sniffer == INVALID_SOCKET)
    {
        fmt::print("Error: Socket init failed\n");
        displayLastError();
        return false;
    }

    // 2. Bind the socket to the local IP over which the traffic is to be sniffed.
    if (bindSocket(&sniffer) < 0) {
        return false;
    }

    // 3. set socket options
    // specify the protocol type for the socket
    if (setsockopt(sniffer, IPPROTO_IP, IP_HDRINCL, (char*)&bNewBehavior, sizeof(bNewBehavior)) == -1) {
        fmt::print("Error in setsockopt()\n");
        displayLastError();
        return -1;
    }

    // 4. Call WSAIoctl() on the socket with SIO_RCVALL option to give it sniffing powers.
    // Sets socket mode.
    int WSAIoctl_result = WSAIoctl(
        sniffer,
        SIO_RCVALL,
        &bNewBehavior, // Pass the option in a buffer
        sizeof(bNewBehavior), // Length of the option buffer
        NULL, // No output buffer
        0, // No output buffer, so 0
        dwBytesReturned, // Size of bytes returned
        NULL, // No overlapped structure
        NULL  // No completion routine
    );

    if (WSAIoctl_result == SOCKET_ERROR)
    {
        fmt::print( "WSAIoctl() failed.\n");
        displayLastError();
        return false;
    }
     
    fmt::print("Socket set\n");

    // To get the local IP’s associated with the machine all that needs to be done is:
    gethostname(hostname.data(), sizeof(hostname)); //its a char hostname[100] for local hostname
    fmt::print("Host name: {0}\n", hostname.data());

    Sniff(&sniffer);
}

void PacketSniffer::Sniff(SOCKET* sniffer) {
    std::string buffer(new char[packetSize]);

    // 4. Put the socket in an infinite loop of recvfrom.
    int i = 0;

    while(1){
        // 5. recvfrom gets the packet in the string buffer.
        int receivedPacketSize = recvfrom(*sniffer, buffer.data(), packetSize, 0, 0, 0);
        if (receivedPacketSize > 0)
        {
                std::wstring ipStringBuffer(new wchar_t[INET_ADDRSTRLEN]);
                InetNtopW(AF_INET, buffer.data()+i, ipStringBuffer.data(), INET_ADDRSTRLEN);
                IPV4_HDR* iphdr = (IPV4_HDR*)buffer.data();

                ProcessPacket(buffer.data(), receivedPacketSize, ipStringBuffer);
        }
        else
        {
            fmt::print("recvfrom() failed.");
            displayLastError();
        }
        i++;
    }

    return;
}

void PacketSniffer::ProcessPacket(char* Buffer, int Size, std::wstring ipStringBufferW)
{
    IPV4_HDR* iphdr = (IPV4_HDR*)Buffer;
    
    fmt::print(L"\nSource: {0} : ", ipStringBufferW);

    switch (iphdr->ip_protocol) //Check the Protocol and do accordingly...
    {
    case 1: //ICMP Protocol
        fmt::print(L"ICMP");
        PrintIcmpPacket(Buffer, Size);
        break;

    case 2: //IGMP Protocol
        fmt::print(L"IGMP");
        break;

    case 6: //TCP Protocol
        fmt::print(L"TCP");
        PrintTcpPacket(Buffer, Size);
        break;

    case 17: //UDP Protocol
        fmt::print(L"UDP");
        PrintUdpPacket(Buffer, Size);
        break;

    default: //Some Other Protocol like ARP etc.
        fmt::print(L"Other");
        break;
    }
}

PacketSniffer::~PacketSniffer()
{
    closesocket(sniffer);
    WSACleanup();
}

bool PacketSniffer::StartWinSock() {
    int iResult;
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        displayLastError();
        return false;
    }

    fmt::print(L"WSAStartup DONE.\n");
    return true;
}

INT PacketSniffer::bindSocket(SOCKET* sniffer)
{
    std::wstring localAddr = L"127.0.0.1";
    sockaddr_in dest;

    ZeroMemory(&dest, sizeof(dest));
    dest.sin_family = AF_INET;

    // Port 0 can be used by applications when calling the bind() command 
    //  to request the next available dynamically allocated source port number.
    dest.sin_port = PacketSniffer::portNumber; // = 0

    InetPtonW(AF_INET, localAddr.data(), &dest.sin_addr.s_addr);

    fmt::print(L"Binding socket to local system and port 0 ... \n");

    sockaddr* addr = reinterpret_cast<sockaddr*>(&dest);
    INT iResult = bind(*sniffer, addr, sizeof(dest));
    if (iResult == SOCKET_ERROR)
    {
        //The inet_ntoa function converts an (Ipv4) Internet network address into an ASCII string in Internet standard dotted-decimal format.
        std::wstring ipStringBuffer;

        fmt::print(L"\nbind failed: {0} \n", InetNtopW(AF_INET, &dest.sin_addr, ipStringBuffer.data(), INET_ADDRSTRLEN));
        displayLastError();
    }
    else {
        fmt::print(L"Binding successful\n");
    }
    
    return iResult;
}

void PacketSniffer::displayLastError() {
    fmt::print(L"\nError : {0} \n", WSAGetLastError());
}

void PacketSniffer::PrintTcpPacket(char* Buffer, int Size)
{
    USHORT iphdrlen;
    IPV4_HDR* iphdr;
    iphdr = reinterpret_cast<IPV4_HDR*>(Buffer);
    iphdrlen = iphdr->ip_header_len * 4;

    TCP_HDR* tcpheader = (TCP_HDR*)(Buffer + iphdrlen);

    fmt::print("\nTCP Header\n");
    fmt::print(L" |-Source Port : {0}\n", ntohs(tcpheader->source_port));
    fmt::print(L" |-Destination Port : {0}\n", ntohs(tcpheader->dest_port));
    fmt::print(L" |-CWR Flag : {0}\n", (UINT)tcpheader->cwr);
    fmt::print(L" |-Checksum : {0}\n", ntohs(tcpheader->checksum));
    fmt::print("\n");
}

void PacketSniffer::PrintIcmpPacket(char* Buffer, int Size)
{
    USHORT iphdrlen;
    IPV4_HDR* iphdr;
    iphdr = reinterpret_cast<IPV4_HDR*>(Buffer);
    iphdrlen = iphdr->ip_header_len * 4;

    ICMP_HDR*  icmpheader = (ICMP_HDR*)(Buffer + iphdrlen);

    fmt::print("\nICMP Header\n");

    if ((UINT)(icmpheader->type) == 11)
    {
        fmt::print(" (TTL Expired)\n");
    }
    else if ((UINT)(icmpheader->type) == 0)
    {
        fmt::print(" (ICMP Echo Reply)\n");
    }

    fmt::print(" |-Code : {0}\n", (UINT)(icmpheader->code));
    fmt::print(" |-Checksum : {0}\n", ntohs(icmpheader->checksum));
    fmt::print(" |-ID : {0}\n", ntohs(icmpheader->id));
    fmt::print(" |-Sequence : {0}\n", ntohs(icmpheader->seq));
    fmt::print("\n");
}

void PacketSniffer::PrintUdpPacket(char* Buffer, int Size)
{
    USHORT iphdrlen;
    IPV4_HDR* iphdr;
    iphdr = reinterpret_cast<IPV4_HDR*>(Buffer);
    iphdrlen = iphdr->ip_header_len * 4;

    UDP_HDR* udpheader = (UDP_HDR*)(Buffer + iphdrlen);

    fmt::print("\nUDP Header\n");
    fmt::print(" |-Source Port : {0}\n", ntohs(udpheader->source_port));
    fmt::print(" |-Destination Port : {0}\n", ntohs(udpheader->dest_port));
    fmt::print(" |-UDP Length : {0}\n", ntohs(udpheader->udp_length));
    fmt::print(" |-UDP Checksum : {0}\n", ntohs(udpheader->udp_checksum));
    fmt::print("\n");
}
