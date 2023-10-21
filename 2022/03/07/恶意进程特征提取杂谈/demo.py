import re

# 获取进程信息代码简化为读取"/proc"文件里的内容

# 获取进程的起始地址等信息
def get_process_addr(pid):
    map_file = open("/proc/"+str(pid)+"/maps","rb")
    line = bytes.decode(map_file.readline())
    start_addr = int(line.split("-")[0],16)
    maps_list = []
    for line in map_file.readlines():
        line = bytes.decode(line)
        maps_list.append(line)
    for i in range(len(maps_list)):
        if maps_list[i].find("heap") != -1:
            tmp = maps_list[i-1].split("-")[1]
            end_addr = int(tmp.split(" ")[0],16)
    process_size = end_addr - start_addr
    return (start_addr,process_size)

# 读取进程的内存
def get_process_code(pid,addr,size):
    mem_file = open(f"/proc/{pid}/mem","rb")
    mem_file.seek(addr)
    data = mem_file.read(size)
    return data

# 对进程内存进行正则匹配
def reg_data(data,regex):
    if re.search(regex,data,flags=0) == None:
        return False
    else:
        return True

def main():
    test_pid = 1940556
    (start_addr,process_size) = get_process_addr(test_pid)
    data = get_process_code(test_pid,start_addr,process_size)
    if reg_data(str(data),"\x48(.){1}\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C"):
        print("匹配成功!")

if __name__ == "__main__":
    main()