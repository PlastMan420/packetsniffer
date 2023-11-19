/*
* References
* https://gist.github.com/Accalmie/d328287c05f0a417892f
* https://www.binarytides.com/packet-sniffer-code-in-c-using-winsock/
* https://learn.microsoft.com/en-us/windows/win32/api/winsock2
* 
* SOF
* https://stackoverflow.com/questions/61701164/winsock2-raw-socket-recvfrom-returns-error-10022-invalid-argument
*/

#include "PacketSniffer.h"

int main() {
    PacketSniffer sniffer;    

    bool initRes = sniffer.Init();
    if (!initRes) {
        system("pause");
        return -1;
    }

    //sniffer.Sniff();

    return 0;
}
