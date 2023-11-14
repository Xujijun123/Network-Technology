#include <Winsock2.h>
#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <string>
#include <iomanip>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")
#pragma pack(1)//以1byte方式对齐
#pragma warning(disable:4996)
using namespace std;

typedef struct FrameHeader_t
{
    uint8_t DesMAC[6];  //  目的地址
    uint8_t SrcMAC[6];//    源网地址
    uint16_t FrameType;//   帧类型
}FrameHeader_t;

typedef struct ARPFrame_t
{//IP首部
    FrameHeader_t FrameHeader;
    uint16_t Hardware_Type;     //硬件类型
    uint16_t Protocol_Type;     //协议类型
    uint8_t HALen;             //硬件地址长度
    uint8_t PALen;             //协议地址长度
    uint16_t Operation;         //操作码
    uint8_t SendMAC[6];//发送方MAC地址
    uint32_t SendIP;//发送方IP地址
    uint8_t RecvMAC[6];//接收方MAC地址
    uint32_t RecvIP;//接收方IP地址
}ARPFrame_t;

void print_MAC(uint8_t MAC[6])
{
    for (int i = 0; i < 5; i++)
    {
        cout << setw(2) << setfill('0') << hex << (int)MAC[i]<<"-";
    }
    cout << setw(2) << setfill('0') << hex << (int)MAC[5] << endl;
}

void print_IP(uint32_t IP)
{
    uint8_t* temp = (uint8_t*)&IP;
    for (int i = 0; i < 3; i++)
    {
        cout << dec << (int)*temp<<'.';
        temp++;
    }
    cout << dec << (int)*temp << endl;
}


int main()
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
            
            for (pcap_addr_t* addr = ptr->addresses; addr != nullptr; addr = addr->next)
            {
                if (addr->addr->sa_family == AF_INET)
                {

                    cout << "  IP地址：" << inet_ntoa(((struct sockaddr_in*)(addr->addr))->sin_addr) << endl;
                }
            }
            cout  << endl;
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

    while (1)
    {
        //打开想要监控的网卡
        cout << "请输入想要监控的网卡的ID（0表示结束）" << endl;
        int num;
        cin >> num;
        if (num == 0)
        {
            cout << "结束获取，关闭进程" << endl;
            pcap_freealldevs(allAdapters);
            return 0;
        }
        while (num < 1 || num > index)
        {
            cout << "不存在该设备，请重新输入合适的ID" << endl;
            cin >> num;
        }

        int i = 0;
        pcap_if_t* ptr;
        for (ptr = allAdapters, i = 0; i < num - 1; ptr = ptr->next, i++);

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

        
        //报文内容
        ARPFrame_t ARPFrame;
        for (int i = 0; i < 6; i++)
        {
            ARPFrame.FrameHeader.DesMAC[i] = 0xff;      //广播
            ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;
            ARPFrame.SendMAC[i] = 0x0f;
            ARPFrame.RecvMAC[i] = 0;
        }
            

        ARPFrame.FrameHeader.FrameType = htons(0x806);  //帧类型为ARP
        ARPFrame.Hardware_Type = htons(0x0001);         //硬件类型为以太网
        ARPFrame.Protocol_Type = htons(0x0800);         //协议类型为IP
        ARPFrame.HALen = 6;                             //硬件地址长度为6
        ARPFrame.PALen = 4;                             //协议地址长为4
        ARPFrame.Operation = htons(0x0001);             //操作为ARP请求

        uint32_t LocalIP= htonl(0x00000000);//设置为任意IP地址
        ARPFrame.SendIP = htonl(0x00000000); //本机网卡上绑定的IP地址
        
        uint32_t RecvIP; //接收方的IP
        ARPFrame_t* RecvPacket;
        for (pcap_addr_t*addr = ptr->addresses; addr != NULL; addr = addr->next)
        {
            if (addr->addr->sa_family == AF_INET)
            {
                RecvIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(addr->addr))->sin_addr)); //把接收方的IP设置为打开的网卡的IP
            }
        }


        // 向以太网广播ARP请求
        struct pcap_pkthdr* RecvHeader;
        const u_char* RecvData;

        if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
        {
            pcap_freealldevs(allAdapters);
            return 0;
        } //发送失败的处理
        else
        {
            while (true) {
                pcap_next_ex(pcap_handle, &RecvHeader, &RecvData);
                RecvPacket = (ARPFrame_t*)RecvData;

                
                // 根据网卡号寻找IP地址，并输出IP地址与MAC地址映射关系
                if (LocalIP == RecvPacket->RecvIP && RecvIP == RecvPacket->SendIP) {
                    cout << "IP地址与MAC地址的对应关系如下：" << endl << "IP：";
                    print_IP(RecvPacket->SendIP);
                    cout << "MAC：";
                    print_MAC(RecvPacket->SendMAC);
                    cout << endl;
                    break;  
                }
            }
        }

        // 输入远程同网段下的IP地址然后找到并输出对应MAC地址
        cout << endl;
        char IP[16];
        cout << "=====================请输入远程目的IP地址===================" << endl;
        cin >> IP;
        RecvIP = ARPFrame.RecvIP = inet_addr(IP);

        LocalIP = ARPFrame.SendIP = RecvPacket->SendIP;
        for (i = 0; i < 6; i++) {
            ARPFrame.SendMAC[i] = ARPFrame.FrameHeader.SrcMAC[i] = RecvPacket->SendMAC[i];
        }

        if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0) {
            cout << "发送失败！" << endl;
            pcap_freealldevs(allAdapters);
            throw - 6;
        }
        else {
            while (true) {
                pcap_next_ex(pcap_handle, &RecvHeader, &RecvData);
                RecvPacket = (ARPFrame_t*)RecvData;

                
                if (LocalIP == RecvPacket->RecvIP && RecvIP == RecvPacket->SendIP) {
                    cout << "IP地址与MAC地址的对应关系如下：" << endl << "IP：";
                    print_IP(RecvPacket->SendIP);
                    cout << "MAC：";
                    print_MAC(RecvPacket->SendMAC);
                    cout << endl;
                    break;  // 结束循环，已经找到并输出了对应关系
                }
            }
        }
    }
}
