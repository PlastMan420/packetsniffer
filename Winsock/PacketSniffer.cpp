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

    // Init Winsock.
    bool initwinsockres = StartWinSock();
    if (!initwinsockres) {
        return false;
    }

    // 1 Create a raw socket
    std::cout << "Creating socket" << std::endl;
    sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if(sniffer == INVALID_SOCKET)
    {
        std::cout << "Error: Socket init failed" << std::endl;
        displayLastError();
        return false;
    }

    //Retrive the available IPs of the local host

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // 2. Bind the socket to the local IP over which the traffic is to be sniffed.
    if (bindSocket(&sniffer, &bNewBehavior) < 0) {
        return false;
    }

    // 3. Call WSAIoctl() on the socket with SIO_RCVALL option to give it sniffing powers.
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
        std::cout <<  "Error : %d.\n" << std::endl;
        return false;
    }
     
    std::cout << "Socket set." << std::endl;

    // To get the local IP’s associated with the machine all that needs to be done is:
    gethostname(hostname, sizeof(hostname)); //its a char hostname[100] for local hostname

    std::cout << "Host name: " << hostname << std::endl;

    PCWSTR pServiceName = L"1042";
    dwRetval = GetAddrInfoW(L"Droog-Machine", pServiceName, &hints, &result);
    if (dwRetval != 0)
    {
        displayLastError();
        FreeAddrInfoW(result);
        return false;
    }

    while (result != NULL) {
        SOCKADDR* curAddr = result->ai_addr;
        curAddr = result->ai_addr;

        wchar_t ipStringBuffer[INET_ADDRSTRLEN];
        std::wcout << InetNtopW(AF_INET, &curAddr->sa_data, ipStringBuffer, INET_ADDRSTRLEN) << std::endl;

        result = result->ai_next;
    }

    Sniff(&sniffer);
}

void PacketSniffer::displayLastError() {
    std::cout << "Error : %d." << WSAGetLastError() << std::endl;
}

void PacketSniffer::Sniff(SOCKET* sniffer) {
    //char* Buffer = (char*)malloc(packetSize);
    std::unique_ptr<char, void (*)(void*)> buffer((char*)malloc(packetSize), free);

    int result = 0;
    std::chrono::milliseconds interval(400);

    if (buffer.get() == NULL)
    {
        std::cout << "malloc() failed." << std::endl;
        return;
    }

    // 4. Put the socket in an infinite loop of recvfrom.
    int i = 0;
        std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
        while(1){
        // ... Place the logic you want to execute here ...
        // 5. recvfrom gets the packet in the string buffer.
        result = recvfrom(*sniffer, buffer.get(), packetSize, 0, 0, 0); //ring-a-ring-a roses
        if (result > 0)
        {
            //ProcessPacket(buffer.get(), result);
                wchar_t ipStringBuffer[INET_ADDRSTRLEN];
                InetNtopW(AF_INET, buffer.get()+i, ipStringBuffer, INET_ADDRSTRLEN);
                //printf("%d \n", ipStringBuffer);
                std::wcout << ipStringBuffer << std::endl;
            
        }
        else
        {
            std::cout << "recvfrom() failed." << std::endl;
            displayLastError();
        }

        // Get the end time
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();

        // Calculate the time taken for the loop iteration
        std::chrono::duration<double> elapsed = end - start;

        // Wait for the rest of the interval, if needed
        if (elapsed < interval) {
            std::this_thread::sleep_for(interval - elapsed);
        }

        i++;
    }

    //free(Buffer);

    return;
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

INT PacketSniffer::bindSocket(SOCKET* sniffer, BOOL* bNewBehavior)
{
    PCWSTR localAddr = L"127.0.0.1\0";

    sockaddr_in dest;
    ZeroMemory(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
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

    if (setsockopt(*sniffer, IPPROTO_IP, IP_HDRINCL, (char*)&*bNewBehavior, sizeof(*bNewBehavior)) == -1) {
        printf("Error in setsockopt(): %d\n", WSAGetLastError());
        return -1;
    }
    
    return iResult;
}
