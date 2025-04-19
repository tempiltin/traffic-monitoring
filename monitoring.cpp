#include <iostream>
#include <pcap.h>
#include <windows.h>
#include <string>
#include <sstream>

// WinAPI uchun oyna yaratish
LRESULT CALLBACK WindowProcedure(HWND, UINT, WPARAM, LPARAM);

class NetworkMonitor {
public:
    static void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        std::ostringstream packet_info;
        packet_info << "Packet captured! Length: " << pkthdr->len << " bytes";
        
        // Oyna oynasida natijalarni ko'rsatish
        SetWindowText(hwnd, packet_info.str().c_str());
    }

    static void start_monitoring(const std::string &interface) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        // Tarmoq interfeysini ochish
        handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            std::cerr << "PCAP open error: " << errbuf << std::endl;
            return;
        }

        // Trafikni eshitish
        if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
            std::cerr << "Error in pcap_loop: " << pcap_geterr(handle) << std::endl;
            return;
        }

        // PCAPni yopish
        pcap_close(handle);
    }

    static HWND hwnd; // Oyna qo'yilishi uchun o'zgaruvchi
};

HWND NetworkMonitor::hwnd = NULL; // Oyna uchun global o'zgaruvchi

int main() {
    const char CLASS_NAME[] = "Window Class";

    // WinAPI oynasini yaratish
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProcedure; 
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    NetworkMonitor::hwnd = CreateWindowEx(
        0,
        CLASS_NAME,
        "Tarmoq Monitoring Dasturi",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 600, 400,
        NULL, NULL, wc.hInstance, NULL
    );

    ShowWindow(NetworkMonitor::hwnd, SW_SHOWNORMAL);

    // Tarmoq monitoringini boshlash
    std::string interface = "eth0";  // Tarmoq interfeysi nomini o'zgartiring
    std::thread monitoring_thread(NetworkMonitor::start_monitoring, interface);

    // Windows oynasini yangilab turish
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    monitoring_thread.join();  // Monitoring tugashini kutish

    return 0;
}

LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, msg, wp, lp);
    }
    return 0;
}
