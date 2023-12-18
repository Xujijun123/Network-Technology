#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Winsock2.h>
#include "pcap.h"
#include "stdio.h"
//#include<time.h>
#include <string.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")
#pragma warning(disable : 4996)
#pragma pack(1)//字节对齐方式

typedef struct FrameHeader_t {		//帧首部
	uint8_t DesMAC[6];//目的地址
	uint8_t SrcMAC[6];//源地址
	uint16_t FrameType;//帧类型
}FrameHeader_t;

typedef struct IPHeader_t {		//IP首部
	uint8_t Header_Length;//IP协议版本和IP首部长度：高4位为版本，低4位为首部的长度
	uint8_t TOS;//服务类型
	uint16_t Total_Length;//总长度
	uint16_t ID;//标识
	uint16_t ip_offset;//标志 片偏移
	uint8_t TTL;//生存周期
	uint8_t Protocol;//协议
	uint16_t Checksum;//头部校验和
	uint32_t SrcIP;//源IP
	uint32_t DesIP;//目的IP
}IPHeader_t;

typedef struct ARPFrame_t {//IP首部
	FrameHeader_t FrameHeader;
	uint16_t Hardware_Type;//硬件类型
	uint16_t Protocol_Type;//协议类型
	uint8_t HALen;//硬件地址长度
	uint8_t PALen;//协议地址长度
	uint16_t Operation;//操作类型
	uint8_t SendMAC[6];//发送方MAC地址
	uint32_t SendIP;//发送方IP地址
	uint8_t RecvMAC[6];//接收方MAC地址
	uint32_t RecvIP;//接收方IP地址
}ARPFrame_t;

typedef struct DataPackage {		//数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}DataPackage;

typedef struct ICMP {//ICMP报文
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
	char buf[0x80];
}ICMP_t;

#pragma pack()//恢复缺省对齐方式

class arpitem
{
public:
	uint32_t ip;
	uint8_t mac[6];
};

class ipitem
{
public:
	uint32_t sip, dip;
	uint8_t smac[6], dmac[6];
};
char ip[10][20];
char mask[10][20];
uint8_t MyMAC[6];
pcap_t* pcap_handle;
//多线程
HANDLE hThread;
DWORD dwThreadId;
int n;
FILE* fp = nullptr;

uint8_t broadcast[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };
void GetMac(uint32_t ip0, uint8_t mac[])
{
	memset(mac, 0, sizeof(mac));
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;      //广播
		ARPFrame.FrameHeader.SrcMAC[i] = MyMAC[i];
		ARPFrame.SendMAC[i] = MyMAC[i];
		ARPFrame.RecvMAC[i] = 0;
	}

	ARPFrame.FrameHeader.FrameType = htons(0x806);  //帧类型为ARP
	ARPFrame.Hardware_Type = htons(0x0001);         //硬件类型为以太网
	ARPFrame.Protocol_Type = htons(0x0800);         //协议类型为IP
	ARPFrame.HALen = 6;                             //硬件地址长度为6
	ARPFrame.PALen = 4;                             //协议地址长为4
	ARPFrame.Operation = htons(0x0001);             //操作为ARP请求

	ARPFrame.SendIP = inet_addr(ip[0]);
	//将ARPFrame.RecvIP设置为请求的IP地址
	ARPFrame.RecvIP = ip0;
	if (pcap_handle == nullptr)
	{
		printf("网卡接口打开错误\n");
	}
	else
	{
		if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
		{
			//发送错误处理
			printf("发送错误\n");
			return;
		}
		else
		{
			//发送成功
			while (1)
			{
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
				if (rtn == 1)
				{
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x0806)
					{//输出目的MAC地址
						if (ntohs(IPPacket->Operation) == 0x0002)//如果帧类型为ARP并且操作为ARP应答
						{
							fp = fopen("log.txt", "a+");//文件以及打开方式
							fprintf(fp, "ARP\t");
							in_addr addr;
							addr.s_addr = IPPacket->SendIP;
							char* temp = inet_ntoa(addr);
							fprintf(fp, "IP:\t");
							fprintf(fp, "%s\t", temp);
							fprintf(fp, "MAC:\t");
							for (int i = 0; i < 6; i++)
							{
								fprintf(fp, "%02x:", IPPacket->SendMAC[i]);
							}
							fprintf(fp, "\n");
							fclose(fp);
							//输出源MAC地址
							for (int i = 0; i < 6; i++)
								mac[i] = IPPacket->FrameHeader.SrcMAC[i];
							break;
						}
					}
				}
			}
		}
	}
}

#pragma pack(1)
class RouterItem//路由表表项,链表存储
{
public:
	uint32_t Mask;//掩码
	uint32_t Net;//目的网络
	uint32_t NextIP;//下一跳
	int index;
	int type;//0为直接连接，1为用户添加
	RouterItem* NextItem;
	RouterItem() { memset(this, 0, sizeof(*this)); }//全部初始化为0
};
#pragma pack()

#pragma pack(1)
class RouterTable//路由表
{
public:
	RouterItem* head, * tail;
	RouterTable();//初始化，添加直接相连的网络
	void RouterAdd(RouterItem* temp);
	void RouterRemove(int index);
	void print();
	uint32_t RouterFind(uint32_t IP);
};
RouterTable::RouterTable()
{
	head = new RouterItem;
	tail = new RouterItem;
	head->NextItem = tail;
	for (int i = 0; i < 2; i++)
	{
		RouterItem* temp = new RouterItem;
		temp->Net = (inet_addr(ip[i])) & (inet_addr(mask[i]));//本机网卡的ip和掩码进行按位与即为所在网络
		temp->Mask = inet_addr(mask[i]);
		temp->type = 0;
		this->RouterAdd(temp);
	}
}
void RouterTable::RouterAdd(RouterItem* temp)
{
	RouterItem* ptr;
	if (!temp->type)
	{
		temp->NextItem = head->NextItem;
		head->NextItem = temp;
		temp->type = 0;
	}
	else//按照掩码由长至短找到合适的位置
	{
		for (ptr = head->NextItem; ptr != tail ; ptr = ptr->NextItem)
		{
			if ((temp->Mask < ptr->Mask && temp->Mask >= ptr->NextItem->Mask) || ptr->NextItem == tail)
			{
				break;
			}
		}
		temp->NextItem = ptr->NextItem;
		ptr->NextItem = temp;
	}

	ptr = head->NextItem;
	for (int i = 0; ptr != tail; ptr = ptr->NextItem, i++)
	{
		ptr->index = i;
	}
}
void RouterTable::RouterRemove(int index) {
	RouterItem* ptr;
	for ( ptr = head; ptr != tail; ptr = ptr->NextItem)
	{
		if (ptr->NextItem->index == index)
		{
			if (ptr->NextItem->type == 0)
			{
				printf("该项不可删除\n");
				return;
			}
			else
			{
				ptr->NextItem = ptr->NextItem->NextItem;

				ptr = head->NextItem;
				for (int i = 0; ptr != tail; ptr = ptr->NextItem, i++)
				{
					ptr->index = i;
				}
				return;
			}
		}
	}
	printf("无该表项\n");
	
}
uint32_t RouterTable::RouterFind(uint32_t IP)
{
	for (RouterItem* ptr = head->NextItem; ptr != tail; ptr = ptr->NextItem)
	{
		if ((ptr->Mask & IP) == ptr->Net)
		{
			return ptr->NextIP;
		}
	}
	return 0;
}

void RouterTable::print() 
{
	for (RouterItem* ptr = head->NextItem; ptr != tail; ptr = ptr->NextItem)
	{
		// 打印索引值
		printf("%d ", ptr->index);

		// 依次打印 Mask、Net 和 NextIP 的点分十进制形式的 IP 地址
		struct in_addr addr;

		addr.s_addr = ptr->Mask;
		printf("%s\t", inet_ntoa(addr));

		addr.s_addr = ptr->Net;
		printf("%s\t", inet_ntoa(addr));

		addr.s_addr = ptr->NextIP;
		printf("%s\t", inet_ntoa(addr));

		// 打印类型 type
		printf("%d\n", ptr->type);

	}
}
#pragma pack()

#pragma pack(1)
class ArpTable//ARP表（将IP和MAC的对应关系存储在一张表里）
{
public:
	uint32_t ip;
	uint8_t mac[6];
	static int num;
	static void InsertArp(uint32_t ip, uint8_t mac[6])
	{
		arptable[num].ip = ip;
		GetMac(ip, arptable[num].mac);
		memcpy(mac, arptable[num].mac, 6);
		num++;
	}
	static int FindArp(uint32_t ip, uint8_t mac[6])
	{
		memset(mac, 0, 6);
		for (int i = 0; i < num; i++)
		{
			if (ip == arptable[i].ip)
			{
				memcpy(mac, arptable[i].mac, 6);
				return 1;
			}
		}
		return 0;
	}
}arptable[50];
#pragma pack()

void SetCheckSum(DataPackage* temp)
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//每16位为一组
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//如果溢出，则进行回卷
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//结果取反
}

bool CheckSum(DataPackage* temp)
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//如果溢出，则进行回卷
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

int ArpTable::num = 0;
void resend(ICMP_t data, BYTE desmac[])
{
	DataPackage* temp = (DataPackage*)&data;
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//源MAC为本机MAC
	memcpy(temp->FrameHeader.DesMAC, desmac, 6);//目的MAC为下一跳MAC
	temp->IPHeader.TTL -= 1;
	if (temp->IPHeader.TTL == 0)
	{
		printf("aaa\n");
		ICMP_t icmpPacket;
		memcpy(&icmpPacket.FrameHeader.DesMAC, &data.FrameHeader.SrcMAC, 6); // 目的MAC为原始数据包的源MAC
		memcpy(&icmpPacket.FrameHeader.SrcMAC, &data.FrameHeader.DesMAC, 6); // 源MAC为本机MAC
		icmpPacket.FrameHeader.FrameType = 0x0800; // 填写 ICMP 数据包的帧类型（IP类型）
		icmpPacket.IPHeader.Header_Length = 0x45; // 版本为 IPv4，头部长度为 20 字节
		icmpPacket.IPHeader.TOS = 0; // 服务类型为 0
		icmpPacket.IPHeader.Total_Length = htons(sizeof(ICMP_t) - sizeof(FrameHeader_t)); // IP数据报长度
		icmpPacket.IPHeader.ID = htons(0); // 填写 ID
		icmpPacket.IPHeader.ip_offset = htons(0x4000); // 标志和偏移量
		icmpPacket.IPHeader.TTL = 64; // TTL 设置为 64 或者其他你想要的值
		icmpPacket.IPHeader.Protocol = 1; // ICMP 协议
		icmpPacket.IPHeader.Checksum = 0; // 先将校验和置为 0
		icmpPacket.IPHeader.SrcIP = inet_addr(ip[0]); // ICMP 数据包的源IP为原始数据包的目的IP
		icmpPacket.IPHeader.DesIP = data.IPHeader.SrcIP; // ICMP 数据包的目的IP为原始数据包的源IP
		icmpPacket.buf[0] = 11;
		icmpPacket.buf[1] = 0;
		temp= (DataPackage*)&icmpPacket;
		// 计算 ICMP 校验和
		SetCheckSum((DataPackage*)&icmpPacket);;
		int rtn = pcap_sendpacket(pcap_handle, (const u_char*)&icmpPacket, 70);
		if (rtn == 0)
		{
			printf("kkk\n");
		}
		return;
	}
	SetCheckSum(temp);//重新设置校验和
	int rtn = pcap_sendpacket(pcap_handle, (const u_char*)temp, 74);//发送数据报
	if (rtn == 0)
	{
		fp = fopen("log.txt", "a+");
		fprintf(fp, "IP\t");
		fprintf(fp, "转发");
		fprintf(fp, "\t");

		in_addr addr;
		addr.s_addr = temp->IPHeader.SrcIP;
		char* srcTemp = inet_ntoa(addr);
		fprintf(fp, "源IP：\t");
		fprintf(fp, "%s\t", srcTemp);

		addr.s_addr = temp->IPHeader.DesIP;
		char* desTemp = inet_ntoa(addr);
		fprintf(fp, "目的IP：\t");
		fprintf(fp, "%s\t", desTemp);

		fprintf(fp, "源MAC：\t");
		for (int i = 0; i < 6; i++)
			fprintf(fp, "%02x:", temp->FrameHeader.SrcMAC[i]);
		fprintf(fp, "目的MAC：\t");
		for (int i = 0; i < 6; i++)
			fprintf(fp, "%02x:", temp->FrameHeader.DesMAC[i]);
		fprintf(fp, "\n");
		fclose(fp);
	}
}

//线程函数
DWORD WINAPI Thread(LPVOID lparam)
{
	RouterTable Routertable = *(RouterTable*)(LPVOID)lparam;
	while (true)
	{
		pcap_pkthdr* RecvHeader;
		const u_char* RecvData;
		while (true)
		{
			if (pcap_next_ex(pcap_handle, &RecvHeader, &RecvData))//接收到消息
				break;
		}
		FrameHeader_t* RecvPacket = (FrameHeader_t*)RecvData;
		if (memcmp(RecvPacket->DesMAC, MyMAC,sizeof(MyMAC))==0) 
		{
			//printf("sss\n");
			if (ntohs(RecvPacket->FrameType) == 0x0806)//收到ARP
			{
				ARPFrame_t* ARPRequest = (ARPFrame_t*)RecvData;
				if (ntohs(ARPRequest->Operation) == 0x0001) // 是 ARP 请求包
				{
					ARPFrame_t ARPPacket;
					memcpy(ARPPacket.FrameHeader.DesMAC, ARPRequest->FrameHeader.SrcMAC, sizeof(ARPRequest->FrameHeader.SrcMAC));
					memcpy(ARPPacket.FrameHeader.SrcMAC, MyMAC, sizeof(MyMAC));
					ARPPacket.FrameHeader.FrameType = htons(0x0806);  // 帧类型为 ARP

					ARPPacket.Hardware_Type = htons(0x0001);         // 硬件类型为以太网
					ARPPacket.Protocol_Type = htons(0x0800);         // 协议类型为 IP
					ARPPacket.HALen = 6;                             // 硬件地址长度为6
					ARPPacket.PALen = 4;                             // 协议地址长为4
					ARPPacket.Operation = htons(0x0002);             // ARP 应答

					memcpy(ARPPacket.SendMAC, MyMAC, sizeof(MyMAC));
					ARPPacket.SendIP = inet_addr(ip[0]);

					memcpy(ARPPacket.RecvMAC, ARPRequest->SendMAC, sizeof(ARPRequest->SendMAC));
					ARPPacket.RecvIP = ARPRequest->SendIP;

					if (pcap_sendpacket(pcap_handle, (u_char*)&ARPPacket, sizeof(ARPFrame_t)) != 0)
					{
						printf("发送 ARP 应答失败\n");
					}
					else
					{
						printf("发送 ARP 应答成功\n");
					}
				}
			}
			else if (ntohs(RecvPacket->FrameType) == 0x0800)//收到IP
			{
				//printf("kkk\n");
				DataPackage* data = (DataPackage*)RecvData;
				fp = fopen("log.txt", "a+");
				fprintf(fp, "IP\t");
				fprintf(fp, "接收");
				fprintf(fp, "\t");

				in_addr addr;
				addr.s_addr = data->IPHeader.SrcIP;
				char* srcTemp = inet_ntoa(addr);
				fprintf(fp, "源IP：\t");
				fprintf(fp, "%s\t", srcTemp);

				addr.s_addr = data->IPHeader.DesIP;
				char* desTemp = inet_ntoa(addr);
				fprintf(fp, "目的IP：\t");
				fprintf(fp, "%s\t", desTemp);

				fprintf(fp, "源MAC：\t");
				for (int i = 0; i < 6; i++)
					fprintf(fp, "%02x:", data->FrameHeader.SrcMAC[i]);
				fprintf(fp, "目的MAC：\t");
				for (int i = 0; i < 6; i++)
					fprintf(fp, "%02x:", data->FrameHeader.DesMAC[i]);
				fprintf(fp, "\n");
				fclose(fp);
				uint32_t DesIP = data->IPHeader.DesIP;
				uint32_t IFip = Routertable.RouterFind(DesIP);//查找是否有对应表项

				//struct in_addr addr;
				//addr.s_addr = IFip;
				//char* ipStr = inet_ntoa(addr);

				//// 打印转换后的 IP 地址字符串
				//printf("IP 地址为：%s\n", ipStr);
				if (IFip == -1)
				{
					printf("mmm\n");
					continue;
				}
				
				if (data->IPHeader.DesIP != inet_addr(ip[0]) && data->IPHeader.DesIP != inet_addr(ip[1]))
				{
					
						//printf("bbb\n");
						//ICMP报文包含IP数据包报头和其它内容
						ICMP_t* temp_ = (ICMP_t*)RecvData;
						ICMP_t temp = *temp_;
						BYTE mac[6];
						if (IFip == 0)
						{
							//如果ARP表中没有所需内容，则需要获取ARP
							if (!ArpTable::FindArp(DesIP, mac))
							{
								//printf("aaa\n");
								ArpTable::InsertArp(DesIP, mac);
							}
							resend(temp, mac);
						}
						else if (IFip != -1)//非直接投递，查找下一条IP的MAC
						{
							//printf("ccc\n");
							if (!ArpTable::FindArp(IFip, mac))
							{
								ArpTable::InsertArp(IFip, mac);
								//for (int i = 0; i < 6; ++i) {
								//	printf("%02X", mac[i]); // %02X 格式化输出每个字节的十六进制数，补齐为两位
								//	if (i < 5) {
								//		printf(":"); // 添加 MAC 地址的分隔符
								//	}
								//}
								//printf("\n");
							}
							//for (int i = 0; i < 6; ++i) {
							//	printf("%02X", mac[i]); // %02X 格式化输出每个字节的十六进制数，补齐为两位
							//	if (i < 5) {
							//		printf(":"); // 添加 MAC 地址的分隔符
							//	}
							//}
							//printf("\n");
							resend(temp, mac);
						}
					
				}
				else if (data->IPHeader.DesIP == inet_addr(ip[0]) || data->IPHeader.DesIP == inet_addr(ip[1]))
				{
					ICMP_t* temp_ = (ICMP_t*)RecvData;
					ICMP_t temp = *temp_;
					BYTE mac[6];
					temp.IPHeader.SrcIP = temp_->IPHeader.DesIP;  // 源 IP 设为原始目的 IP
					temp.IPHeader.DesIP = temp_->IPHeader.SrcIP;
					IFip = Routertable.RouterFind(temp.IPHeader.DesIP);
					temp.IPHeader.TTL = 129;
					temp.buf[0] = 0;
					struct in_addr addr;
					addr.s_addr = IFip;
					char* ipStr = inet_ntoa(addr);

					// 打印转换后的 IP 地址字符串
					printf("IP 地址为：%s\n", ipStr);
					if (IFip == 0)
					{
						//如果ARP表中没有所需内容，则需要获取ARP
						if (!ArpTable::FindArp(DesIP, mac))
						{
							//printf("ggg\n");
							ArpTable::InsertArp(DesIP, mac);
						}
						resend(temp, mac);
					}
					else if (IFip != -1)//非直接投递，查找下一条IP的MAC
					{
						//printf("iii\n");
						if (!ArpTable::FindArp(IFip, mac))
						{
							ArpTable::InsertArp(IFip, mac);
							//for (int i = 0; i < 6; ++i) {
							//	printf("%02X", mac[i]); // %02X 格式化输出每个字节的十六进制数，补齐为两位
							//	if (i < 5) {
							//		printf(":"); // 添加 MAC 地址的分隔符
							//	}
							//}
							//printf("\n");
						}
						resend(temp, mac);
					}
				}
			}
		}
	}
}


int main()
{
	pcap_if_t* allAdapters; // 保存所有网卡设备
	char errbuf[PCAP_ERRBUF_SIZE]; // 错误缓冲区，大小为256
	int index = 1;
	int n = 0;
	// 获取本地机器设备列表，并打印
	// pcap.h抓包库中的函数
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapters, errbuf) != -1)
	{
		/* 打印网卡信息列表 */
		pcap_if_t* ptr;
		for (ptr = allAdapters; ptr != NULL; ptr = ptr->next)
		{
			if (ptr->description)
				printf("ID %d  Name: %s \n", index, ptr->description);
			index++;

			for (pcap_addr_t* addr = ptr->addresses; addr != nullptr; addr = addr->next)
			{
				if (addr->addr->sa_family == AF_INET)
				{
					printf("%s\t%s\n", "IP_Address:", inet_ntoa(((struct sockaddr_in*)addr->addr)->sin_addr));
					printf("%s\t%s\n", "MASK_Address:", inet_ntoa(((struct sockaddr_in*)addr->netmask)->sin_addr));
					strcpy(ip[n], inet_ntoa(((struct sockaddr_in*)addr->addr)->sin_addr));
					strcpy(mask[n], inet_ntoa(((struct sockaddr_in*)addr->netmask)->sin_addr));
				}
				n++;
			}
		}
		index--;
	}
	else
	{
		printf("Error in pcap_findalldevs_ex: %s\n", errbuf);
	}

	if (index == 0)
	{
		printf("没有找到接口\n");
	}

	// 打开想要监控的网卡
	printf("请输入想要监控的网卡的ID（0表示结束）: ");
	int num;
	scanf("%d", &num);
	if (num == 0)
	{
		printf("结束获取，关闭进程\n");
		pcap_freealldevs(allAdapters);
		return 0;
	}
	while (num < 1 || num > index)
	{
		printf("不存在该设备，请重新输入合适的ID: ");
		scanf("%d", &num);
	}

	int i = 0;
	pcap_if_t* ptr;
	for (ptr = allAdapters, i = 0; i < num - 1; ptr = ptr->next, i++);

	pcap_handle = pcap_open(ptr->name,    // 设备名称
		65536,       // 包长度最大值 65536允许整个包在所有mac电脑上被捕获
		PCAP_OPENFLAG_PROMISCUOUS, /* 混杂模式*/
		1000,        // 读超时为1秒
		NULL,
		errbuf);     // 错误缓冲池
	if (pcap_handle == NULL)
	{
		printf("无法打开该网卡接口\n");
		pcap_freealldevs(allAdapters);
		exit(0);
	}
	printf("正在监听 %s\n", ptr->description);

	for (int i = 0; i < 2; i++)
	{
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}

	//伪造ARP报文获取本机MAC
	memset(MyMAC, 0, sizeof(MyMAC));

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
	
	//将ARPFrame.RecvIP设置为请求的IP地址
	ARPFrame.RecvIP = inet_addr(ip[0]);
	pcap_pkthdr* RecvHeader;
	const u_char* RecvData;
	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		printf("发送失败，退出程序\n");
		return 0;
	}
	else
	{
		ARPFrame_t* RecvPacket;
		while (true)
		{
			pcap_next_ex(pcap_handle, &RecvHeader, &RecvData);
			RecvPacket = (ARPFrame_t*)RecvData;
			for (int i = 0; i < 6; i++)
			{
				MyMAC[i] = RecvPacket->FrameHeader.SrcMAC[i];
			}
			if ((ntohs(RecvPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(RecvPacket->Operation) == 0x0002))//如果帧类型为ARP并且操作为ARP应答
			{
				fp = fopen("log.txt", "a+");//文件以及打开方式
				fprintf(fp, "ARP\t");
				in_addr addr;
				addr.s_addr = RecvPacket->SendIP;
				char* temp = inet_ntoa(addr);
				fprintf(fp, "IP:\t");
				fprintf(fp, "%s\t", temp);
				fprintf(fp, "MAC:\t");
				for (int i = 0; i < 6; i++)
				{
					fprintf(fp, "%02x:", RecvPacket->SendMAC[i]);
				}
				fprintf(fp, "\n");
				fclose(fp);
				printf("Mac地址：\n");
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					RecvPacket->FrameHeader.SrcMAC[0],
					RecvPacket->FrameHeader.SrcMAC[1],
					RecvPacket->FrameHeader.SrcMAC[2],
					RecvPacket->FrameHeader.SrcMAC[3],
					RecvPacket->FrameHeader.SrcMAC[4],
					RecvPacket->FrameHeader.SrcMAC[5]
				);
				break;
			}
		}
	}
	
	RouterTable Routertable;
	hThread = CreateThread(NULL, NULL, Thread, LPVOID(&Routertable), 0, &dwThreadId);
	while (true)
	{
		int operation;
		printf("请输入你想要进行的操作：");
		printf("1：打印路由表；2：添加路由表项；3：删除路由表项；0：退出");
		scanf("%d", &operation);
		if (operation == 1)
		{
			Routertable.print();
		}
		else if (operation == 2)
		{
			RouterItem* NewItem = new RouterItem();
			char temp[30];
			printf("请输入目的网络：");
			scanf("%s", &temp);
			NewItem->Net = inet_addr(temp);
			printf("请输入掩码：");
			scanf("%s", &temp);
			NewItem->Mask = inet_addr(temp);
			printf("请输入下一跳地址：");
			scanf("%s", &temp);
			NewItem->NextIP = inet_addr(temp);
			NewItem->type = 1;
			Routertable.RouterAdd(NewItem);
		}
		else if (operation == 3)
		{
			printf("请输入删除表项编号：");
			int index;
			scanf("%d", &index);
			Routertable.RouterRemove(index);
		}
		else if (operation == 0)
		{
			break;
		}
		else
		{
			printf("无效操作，请重新选择\n");
		}
	}

	pcap_close(pcap_handle);
	return 0;
}