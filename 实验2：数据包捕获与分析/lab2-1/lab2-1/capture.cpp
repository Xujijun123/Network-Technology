#include <Winsock2.h>
#include <Windows.h>
#include <iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "stdio.h"
#include <time.h>
#include <string>

#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
#pragma warning( disable : 4996 )//要使用旧函数
#define _WINSOCK_DEPRECATED_NO_WARNINGS

using namespace std;
int packet_number = 1;
#pragma pack(1)
struct ethernet_header
{
    uint8_t DesMAC[6];  //  目的地址
    uint8_t SrcMAC[6];//    源网地址
    uint16_t FrameType;//   帧类型
};

struct ip_header
{
    uint8_t Header_Length : 4,	//首部长度
        Version : 4;				//版本
    uint8_t TOS;				//服务类型
    uint16_t Total_Length;		//总长度
    uint16_t Id;				//标识,用于将分片的IP数据包重新组装为完整数据包
    uint8_t TTL;				//生存时间,指示数据包在网络中的最大寿命，以避免在网络中无限循环
    uint8_t Protocol;			//协议类型(TCP/UDP/ICMP)
    uint16_t Header_Check;		//首部检验和,用于检测IP首部是否损坏
    struct in_addr Ip_Src_Addr; //源IP (struct表示一个32位的IPv4地址)
    struct in_addr Ip_Des_Addr; //目的IP
    uint16_t ip_offset;//片偏移
};
void packet_callback(u_char* argument, const pcap_pkthdr* packet_header, const u_char* packet_content)
{
    uint16_t FrameType;
    ethernet_header* Protocol = (ethernet_header*)packet_content;
    uint8_t* SrcMAC;
    uint8_t* DesMAC;

    FrameType = ntohs(Protocol->FrameType);     //获得以太网类型
    Protocol = (ethernet_header*)packet_content;//获得以太网协议数据内容
    SrcMAC = Protocol->SrcMAC;                  //Mac源地址
    DesMAC = Protocol->DesMAC;                  //Mac目的地址

    printf("第【 %d 】个IP数据包被捕获\n", packet_number);
    printf("类型为 :%04x\n", FrameType);
    printf("帧长度: %d bytes\n", packet_header->len);// 输出帧长度

    switch (FrameType)//判断以太网类型的值
    {
    case 0x0800:
        cout << "网络层使用的是IPv4协议" << endl;
        break;
    case 0x08DD:
        cout << "网络层使用的是IPv6协议" << endl;
        break; 
    case 0x0806:
        cout << "网络层使用的是ARP协议" << endl;
        break;
    case 0x8100:
        cout << "网络层使用的是VLAN 标签帧" << endl;
        break;
    case 0x8035:
        cout << "网络层使用的是RARP协议" << endl;
        break;
    case 0x8137:
        cout << "网络层使用的是IPX 协议" << endl;
        break;
    default:
        break;
    }
    //获得Mac源地址
    printf("Mac源地址:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *SrcMAC, *(SrcMAC + 1), *(SrcMAC + 2), *(SrcMAC + 3), *(SrcMAC + 4), *(SrcMAC + 5));
    //获得Mac目的地址
    printf("Mac目的地址:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *DesMAC, *(DesMAC + 1), *(DesMAC + 2), *(DesMAC + 3), *(DesMAC + 4), *(DesMAC + 5));
    packet_number++;
}
void Capture()
{
    pcap_if_t* allAdapters;// 所有网卡设备保存
    char errbuf[PCAP_ERRBUF_SIZE];//错误缓冲区，大小为256
    int index = 1;
    // 获取本地机器设备列表，并打印
    //pcap.h抓包库中的函数
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapters, errbuf) != -1)
    {	/* 打印网卡信息列表 */
        pcap_if_t* ptr;
        for (ptr = allAdapters; ptr != NULL; ptr = ptr->next)
        {
            if (ptr->description)
                printf("ID %d  Name: %s \n", index, ptr->description);
            index++;
        }
        index--;
    }
    else
    {
        printf("Error in pcap_findalldevs_ex: %s\n", errbuf);
    }

    if (index == 0)
    {
        cout << "没有找到接口" << endl;
    }

    //打开想要监控的网卡
    cout << "请输入想要监控的网卡的ID" << endl;
    int num;
    cin >> num;

    while (num < 1 || num > index)
    {
        cout << "不存在该设备，请重新输入合适的ID" << endl;
        cin >> num;
    }

    int i = 0;
    pcap_if_t* ptr;
    for (ptr = allAdapters, i = 0; i < num - 1; ptr = ptr->next, i++);

    //选择网卡

     //打开网卡
    pcap_t* pcap_handle = pcap_open_live(ptr->name,    //设备名称
        65536,										//包长度最大值 65536允许整个包在所有mac电脑上被捕获
        PCAP_OPENFLAG_PROMISCUOUS,					/* 混杂模式*/
        1000,										//读超时为1秒
        errbuf);									//错误缓冲池;//打开网络适配器，捕捉实例,是pcap_open返回的对象
    if (pcap_handle == NULL)
    {
        cout << "无法打开该网卡接口" << endl;
        pcap_freealldevs(allAdapters);
        exit(0);
    }

    cout << "正在监听" << ptr->description << endl;
    //不再需要设备列表，释放
    pcap_freealldevs(allAdapters);

    cout << "请输入想要捕获数据包的个数:" << endl;
    cin >> num;
    //-1表示无限捕获，0表示捕获所有数据包，直到读取到EOF

    pcap_loop(pcap_handle, num, packet_callback, NULL);
    //捕获数据包,不会响应pcap_open_live()函数设置的超时时间
    cout << "监听数据包结束" << endl;
}

int main()
{
    Capture();
    system("Pause");
    return 0;
}



