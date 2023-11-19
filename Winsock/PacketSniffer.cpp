#include "PacketSniffer.h"

bool PacketSniffer::Init() {
    char hostname[256];
    INT iResult;
    ADDRINFOW* result = NULL;
    ADDRINFOW hints;
    BOOL bNewBehavior = TRUE;
    DWORD dwBytesReturnedBuffer = 0;
    LPDWORD dwBytesReturned = &dwBytesReturnedBuffer;
    DWORD dwRetval;
    PCWSTR pNodeName;

    sockaddr_in Source;

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

    // 1 Create a raw socket
    std::cout << "Creating socket" << std::endl;
    sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

    if(sniffer == INVALID_SOCKET)
    {
        std::cout << "Error: Socket init failed" << std::endl;
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
        printf("Error in setsockopt(): %d\n", WSAGetLastError());
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
        std::cout <<  "WSAIoctl() failed." << std::endl;
        printf("Error: %d\n", WSAGetLastError());
        return false;
    }
     
    std::cout << "Socket set." << std::endl;

    // To get the local IP’s associated with the machine all that needs to be done is:
    gethostname(hostname, sizeof(hostname)); //its a char hostname[100] for local hostname
    std::cout << "Host name: " << hostname << std::endl;

    while (result != NULL) {
        SOCKADDR* curAddr = result->ai_addr;
        curAddr = result->ai_addr;

        wchar_t ipStringBuffer[INET_ADDRSTRLEN];
        std::wcout << InetNtopW(AF_INET, &curAddr->sa_data, ipStringBuffer, INET_ADDRSTRLEN) << std::endl;

        result = result->ai_next;
    }

    Sniff(&sniffer);
}

void PacketSniffer::Sniff(SOCKET* sniffer) {
    std::unique_ptr<char, void (*)(void*)> buffer((char*)malloc(packetSize), free);

    if (buffer.get() == NULL)
    {
        std::cout << "malloc() failed." << std::endl;
        return;
    }

    // 4. Put the socket in an infinite loop of recvfrom.
    int i = 0;

    while(1){
        // 5. recvfrom gets the packet in the string buffer.
        int receivedPacketSize = recvfrom(*sniffer, buffer.get(), packetSize, 0, 0, 0);
        if (receivedPacketSize > 0)
        {
                wchar_t ipStringBuffer[INET_ADDRSTRLEN];
                InetNtopW(AF_INET, buffer.get()+i, ipStringBuffer, INET_ADDRSTRLEN);
                IPV4_HDR* iphdr = (IPV4_HDR*)buffer.get();
                ProcessPacket(buffer.get(), receivedPacketSize, ipStringBuffer);
        }
        else
        {
            std::cout << "recvfrom() failed." << std::endl;
            displayLastError();
        }
        i++;
    }

    return;
}

void PacketSniffer::ProcessPacket(char* Buffer, int Size, wchar_t ipStringBuffer[INET_ADDRSTRLEN])
{
    IPV4_HDR* iphdr = (IPV4_HDR*)Buffer;
    
    printf("\n");
    std::wcout << L"Source: " << ipStringBuffer;

    switch (iphdr->ip_protocol) //Check the Protocol and do accordingly...
    {
    case 1: //ICMP Protocol
        std::wcout << ": " << "ICMP" << std::endl;
        PrintIcmpPacket(Buffer, Size);
        break;

    case 2: //IGMP Protocol
        std::wcout << ": " << "IGMP" << std::endl;
        break;

    case 6: //TCP Protocol
        std::wcout << ": " << "TCP" << std::endl;
        PrintTcpPacket(Buffer, Size);
        break;

    case 17: //UDP Protocol
        std::wcout << ": " << "UDP" << std::endl;
        //PrintUdpPacket(Buffer, Size);
        break;

    default: //Some Other Protocol like ARP etc.
        //++others;
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

    std::cout << "WSAStartup DONE." << std::endl;
    return true;
}

INT PacketSniffer::bindSocket(SOCKET* sniffer)
{
    PCWSTR localAddr = L"127.0.0.1\0";

    sockaddr_in dest;
    ZeroMemory(&dest, sizeof(dest));

    dest.sin_family = AF_INET;
    dest.sin_port = 0;

    InetPtonW(AF_INET, localAddr, &dest.sin_addr.s_addr);
    //dest.sin_port = htons(0);

    printf("\nBinding socket to local system and port 0 ... \n");
    sockaddr* addr = reinterpret_cast<sockaddr*>(&dest);

    INT iResult = bind(*sniffer, addr, sizeof(dest));

    if (iResult == SOCKET_ERROR)
    {
        //The inet_ntoa function converts an (Ipv4) Internet network address into an ASCII string in Internet standard dotted-decimal format.
       // printf("bind(%s) failed.\n", InetNtopW(AF_INET, addr));
        wchar_t ipStringBuffer[INET_ADDRSTRLEN];
        std::wcout << L"bind failed: " << InetNtopW(AF_INET, &dest.sin_addr, ipStringBuffer, INET_ADDRSTRLEN) << std::endl;
        displayLastError();
    }
    else {
        printf("\nBinding successful\n");
    }
    
    return iResult;
}

void PacketSniffer::displayLastError() {
    std::cout << "Error : %d." << WSAGetLastError() << std::endl;
}

void PacketSniffer::PrintTcpPacket(char* Buffer, int Size)
{
    USHORT iphdrlen;
    IPV4_HDR* iphdr;

    iphdr = (IPV4_HDR*)Buffer;
    iphdrlen = iphdr->ip_header_len * 4;

    TCP_HDR* tcpheader = (TCP_HDR*)(Buffer + iphdrlen);

    printf("TCP Header\n");
    printf(" |-Source Port : %u\n", ntohs(tcpheader->source_port));
    printf(" |-Destination Port : %u\n", ntohs(tcpheader->dest_port));
    printf(" |-CWR Flag : %d\n", (UINT)tcpheader->cwr);
    printf(" |-Checksum : %d\n", ntohs(tcpheader->checksum));
}

void PacketSniffer::PrintIcmpPacket(char* Buffer, int Size)
{
    USHORT iphdrlen;

    IPV4_HDR*  iphdr = (IPV4_HDR*)Buffer;
    iphdrlen = iphdr->ip_header_len * 4;

    ICMP_HDR*  icmpheader = (ICMP_HDR*)(Buffer + iphdrlen);

    printf("ICMP Header\n");

    if ((UINT)(icmpheader->type) == 11)
    {
        printf(" (TTL Expired)\n");
    }
    else if ((UINT)(icmpheader->type) == 0)
    {
        printf(" (ICMP Echo Reply)\n");
    }

    printf(" |-Code : %d\n", (UINT)(icmpheader->code));
    printf(" |-Checksum : %d\n", ntohs(icmpheader->checksum));
    printf(" |-ID : %d\n", ntohs(icmpheader->id));
    printf(" |-Sequence : %d\n", ntohs(icmpheader->seq));
    printf("\n");
}
