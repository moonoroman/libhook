//
// Created by Roman on 2018/3/28.
//
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <dlfcn.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>
#include "log.h"
#include "binder.h"
#include "sockets.h"


char *SERVICE[]={
        "android.location.ILocationManager",//定位
        "android.hardware.ICameraService",//相机
        "com.android.internal.telephony.ITelephony",//拨打电话
        "com.android.internal.telephony.ISms",//发送短信
//        "android.content.pm.IPackageManager",//程序包管理
        "com.android.internal.telephony.IPhoneSubInfo",//获取手机信息
        "com.android.internal.telephony.IIccPhoneBook",//sim卡获取联系人
        "android.content.IContentService"
};

char *content_uri[]={
        "call_log",  //通话记录
        "com.android.contacts",  //联系人
        "sms",   //短信
        "media/external/images",   //图片
        "media/internal/images",   //图片
        "media/external/audio",    //音频
        "media/external/video"    //视频
};
const int SERVICE_LEN = 7;

#if defined(__aarch64__)
const char *LIBIOC_PATH = "/system/lib64/libbinder.so";
#else
const char *LIBIOC_PATH = "/system/lib/libbinder.so";
#endif

//解析transaction data数据，获取服务名称
char* hexdump(binder_uintptr_t _data, binder_size_t len) {
    char *data = (char *)_data;
    char *dataAry = (char*)malloc(len*(sizeof(char)));
    char *dataTmp = dataAry;
    binder_size_t count;
    for (count = 0; count < len; count++) {
        if((*data >= 33) && (*data <= 122)) {
            *dataAry = *data; dataAry++;
        }
        data++;
    }
    *dataAry = '\0';
    return dataTmp;
}

int isStub(char *src,const char *stub)
{
    if(src == NULL)
        return -1;
    if(stub == NULL)
        return -1;
    size_t src_len = strlen(src);
    size_t stub_len = strlen(stub);
    if(src_len < stub_len)
        return -1;
    int i = 0,j = 0;
    for(i=0;i<src_len;i++)
    {
        int k = i;
        if(i > src_len - stub_len)
            return -1;
        for(j=0;j<stub_len;j++)
        {
            if(src[k] == stub[j])
                k++;
            else
                break;
        }
        if(j == stub_len)
            return 1;
    }
    return -1;
}

int send_remote_request(char *msg) {
    int client_socket = socket_local_client("com.safemonitor.localsocket",
                                            ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    if (client_socket < 0) {
        LOGE("Create socket failed!\n");
        return -1;
    }

//    LOGE("Create Success!\n");
    ssize_t write_bytes = write(client_socket, msg, strlen(msg));
    if (write_bytes < 0) {
        close(client_socket);
        return -1;
    }

    close(client_socket);
    return 0;
}

int (*old_ioctl)(int __fd, unsigned long int __request, void *arg) = 0;

int new_ioctl(int __fd, unsigned long int __request, void *arg) {
    if (__request == BINDER_WRITE_READ) {

        struct binder_write_read* tmp = (struct binder_write_read*)arg;
        binder_size_t read_size = tmp->read_size;

        if(read_size>0){
            binder_size_t already_got_size = tmp->read_consumed;
            void* pret = 0;
//            LOGE("[-] READ_BUFFER: %llx, consumed: %llx\n", tmp->read_buffer, tmp->read_consumed);

            while(already_got_size < read_size){//循环处理read_buffer中的每一个命令
                pret = (uint32_t *)(tmp->read_buffer + already_got_size);
                uint32_t cmd = *(uint32_t *)pret;//获得命令码
                pret += sizeof(uint32_t);
                binder_size_t size = _IOC_SIZE(cmd);  //从命令参数中解析出用户数据大小
                struct binder_transaction_data* pdata = (struct binder_transaction_data*)pret;

                switch (cmd)
                {
                    case BR_TRANSACTION:   //Binder通知Server进程收到一次请求
                        if(pdata->sender_euid>10000)   //过滤掉系统应用
                        {
                            char *pname = hexdump(pdata->data.ptr.buffer, pdata->data_size);  //提取请求的服务名称
//                            LOGE("[-] dump name: %s\n",pname);
                            int i,j;
                            for(i=0;i<SERVICE_LEN;i++){
                                if(isStub(pname, SERVICE[i])==1)
                                {
                                    char send_msg[100];
                                    if(SERVICE[i]=="android.content.IContentService"){//访问系统敏感数据库
                                        for(j=0;j<7;j++){
                                            if(isStub(pname, content_uri[j])==1){
                                                //封装数据
                                                sprintf(send_msg,"PID=%d, SERVICE=%s, uri=%s\n", pdata->sender_pid, SERVICE[i], content_uri[j]);
//                                                LOGE("[-] %s", send_msg);
                                                //发送数据到应用层
                                                if(send_remote_request(send_msg)<0)
                                                    LOGE("send msg to app failed!\n");
                                                break;
                                            }
                                        }
                                    } else{//调用敏感API
                                        //封装数据
                                        sprintf(send_msg,"PID=%d, SERVICE=%s, api=%d\n", pdata->sender_pid, SERVICE[i], pdata->code);
//                                        LOGE("[-] %s", send_msg);
                                        //发送数据到应用层
                                        if(send_remote_request(send_msg)<0)
                                            LOGE("send msg to app failed!\n");
                                        break;
                                    }
                                }
                            }
                            free(pname);
                        }
                        break;
                    default:
                        break;
                }
                already_got_size += size+4;//数据内容加上命令码
            }
        }
    }
    int res = (*old_ioctl)(__fd, __request, arg);
    return res;
}

//获取进程加载模块的基址
void *get_module_base(pid_t pid, const char *module_name) {
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0)
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid); /* self process */
    else
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);

    fp = fopen(filename, "r");

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok(line, "-");
                LOGE("[+] get_module_base: %s\n", pch);
                addr = strtoull(pch, NULL, 16);
                LOGE("[+] get_module_base: %llx\n", addr);
                if (addr == 0x8000)
                    addr = 0;

                break;
            }
        }
        fclose(fp);
    }

    return (void *) addr;
}

void* getSegmentBaseAddress(int fd, void *base_addr, int phnum, size_t phsize, unsigned long phdr_addr){
    if(phnum>0) {
        Elf64_Phdr phdr;
        lseek(fd, phdr_addr, SEEK_SET);//将指针移至程序头表偏移地址
        for (Elf64_Half i = 0; i < phnum; i++) {
            read(fd, &phdr, phsize);
            if(phdr.p_type == PT_LOAD)
                break;
        }
        return base_addr + phdr.p_offset - phdr.p_vaddr;
    }
    return 0;
}

int hook_ioctl() {

    old_ioctl = ioctl;
    LOGE("[-] old ioctl addr: %p\n", old_ioctl);

    void *base_addr = get_module_base(getpid(), LIBIOC_PATH);//获得libbinder模块的基址
    LOGE("[-] libbinder.so address = %p\n", base_addr);

    int fd;
    fd = open(LIBIOC_PATH, O_RDONLY);//以只读方式打开libbinder.so

    if (-1 == fd) {
        LOGD("error\n");
        return -1;
    }

    //读取ELF文件头
    Elf64_Ehdr ehdr;
    read(fd, &ehdr, sizeof(Elf64_Ehdr));

    unsigned long shdr_addr = ehdr.e_shoff;//段表在文件中的偏移量
    int shnum = ehdr.e_shnum;//段表描述符数量
    size_t shentsize = ehdr.e_shentsize;//段表描述符大小
    unsigned long strndex = ehdr.e_shstrndx;//段表字符串表索引

    unsigned long phdr_addr = ehdr.e_phoff;//程序头表在文件中的偏移量
    int phnum = ehdr.e_phnum;//程序头表表项数目
    size_t phsize = ehdr.e_phentsize;//程序头表项的大小
    void* bias = getSegmentBaseAddress(fd, base_addr, phnum, phsize, phdr_addr);//获得该段的内存基址
    LOGE("[-] SegmentBaseAddress: %p\n",bias);

    //shdr用于临时存储段表描述符
    Elf64_Shdr shdr;
    Elf64_Rela rel;
    Elf64_Sym sym;

    //从段表中读取段表字符串表的段表描述符
    lseek(fd, shdr_addr + strndex * shentsize, SEEK_SET);//将文件指针移到段表字符串表的段表描述符在文件中的偏移地址
    read(fd, &shdr, shentsize);

    //读取段表字符串表
    char *stringtab = (char *) malloc(shdr.sh_size);//开辟一块内存空间存储读取的段表字符串表
    lseek(fd, shdr.sh_offset, SEEK_SET);//将指针移到段表字符串表在文件中的偏移地址
    read(fd, stringtab, shdr.sh_size);

    lseek(fd, shdr_addr, SEEK_SET);//将指针移回段表偏移地址

    long i;
    unsigned long rel_addr = 0;//.rel.plt表地址
    unsigned long sym_addr = 0;//.dynsym表地址
    unsigned long str_addr = 0;//.dynstr表地址
    unsigned long rel_size = 0, sym_size = 0, str_size = 0, got_item = 0;
    char *strTable;
    int got_found = 0;

    for (i = 0; i < shnum; i++) {       //遍历段表,获取四个段在模块中的偏移量
        read(fd, &shdr, shentsize);
        if (strcmp(&stringtab[shdr.sh_name], ".rela.plt") == 0 ||
            strcmp(&stringtab[shdr.sh_name], ".rel.plt") == 0) {
            rel_addr = shdr.sh_offset;
            rel_size = shdr.sh_size;
            LOGE("[-] %s: addr = %lx, size=%lx\n", &stringtab[shdr.sh_name], rel_addr, rel_size);
            break;
        } else if (strcmp(&stringtab[shdr.sh_name], ".dynsym") == 0) {
            sym_addr = shdr.sh_offset;
            sym_size = shdr.sh_size;
            LOGE("[-] %s: addr = %lx, size=%lx\n", &stringtab[shdr.sh_name], sym_addr, sym_size);
        } else if (strcmp(&stringtab[shdr.sh_name], ".dynstr") == 0) {
            str_addr = shdr.sh_offset;
            str_size = shdr.sh_size;
            LOGE("[-] %s: addr = %lx, size=%lx\n", &stringtab[shdr.sh_name], str_addr, str_size);
        }
    }

    //读取字符串表
    strTable = (char *) malloc(str_size);
    lseek(fd, str_addr, SEEK_SET);
    read(fd, strTable, str_size);

    unsigned long relnum = rel_size / sizeof(rel);
    for (i = relnum - 1; i >= 0; i--) {
        lseek(fd, rel_addr + i * sizeof(rel), SEEK_SET);//将指针移至最后一个rel项偏移地址
        read(fd, &rel, sizeof(rel));//读取一条重定位条目

        unsigned relsym = ELF64_R_SYM(rel.r_info);
        lseek(fd, sym_addr + relsym* sizeof(sym), SEEK_SET);//将指针移至dynsym表对应的sym项偏移地址
        read(fd, &sym, sizeof(sym));

        if(strcmp(&strTable[sym.st_name], "ioctl")==0){
            got_item = rel.r_offset;
            LOGE("[-] got item: %lx\n",got_item);
            got_found = 1;

            uint64_t out_addr = (uint64_t)(bias+got_item);
            LOGE("[-] ioctl addr in .got before hook: %p\n", *(uint64_t *)out_addr);
            if(*(uint64_t *)out_addr==old_ioctl){
                uint64_t page_size = getpagesize();//获取内存分页大小
                uint64_t entry_page_start = out_addr & (~(page_size - 1));//获取页编号
                //设置该页内存为可读可写
                mprotect((uint64_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
                *(uint64_t *)out_addr = new_ioctl; //将新的函数地址写入全局偏移量表
                LOGE("[-] ioctl addr in .got after hook: %p\n", *(uint64_t *)out_addr);
            }
            break;
        }
    }

    LOGE("[-] got_found: %d\n", got_found);
    if (got_found==0)
        LOGE("[-] Can't find ioctl\n");

    free(stringtab);
    free(strTable);
    close(fd);

    return 0;
}


int hook_entry() {
    LOGE("Hook success\n");
    LOGE("Start hooking\n");
    hook_ioctl();
    return 0;
}




