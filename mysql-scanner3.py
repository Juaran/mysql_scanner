"""
@ mysql扫描器 V3.0  2019-06-23
"""

import pymysql
import IPy
import queue
import threading
import getopt
import sys
import warnings
warnings.filterwarnings("ignore")

from config import *


class LinkMysql(object):
    def __init__(self):
        self.link_mysql()

    def link_mysql(self):
        try:
            self.conn = pymysql.connect(host=HOST, port=PORT, user=USER, password=PASSWORD, database=DATABASE)
            self.cursor = self.conn.cursor()
        except Exception as e:
            print("\n数据库连接失败：%s\n请检查MYSQL配置！\n" % e)

    def save_host(self, ip, user, pwd):
        try:
            sql = "INSERT IGNORE INTO %s" % TABLE + "(host, username, password) VALUES('%s', '%s', '%s')" % \
                  (pymysql.escape_string(ip), user, pymysql.escape_string(pwd))
            # sql = "INSERT IGNORE INTO %s" % TABLE + "(host, username, password) VALUES('%s', '%s', '%s')" % (ip, user, pymysql.escape_string("sa%asa"))
            self.cursor.execute(sql)
            self.conn.commit()
        except Exception as e:
            print("保存失败：", e)


class MysqlScanner(object):
    def __init__(self):
        self.q = queue.Queue()
        self.lock = threading.Lock()

        self.port = port
        self.thread = THREAD
        self.timeout = TIMEOUT

    def getIpList(self, ipcmd):
        errMsg = '\n参数格式错误，请参照以下用法:\n' \
                 '-h 192.168.1.1   单个地址\n' \
                 '-h 192.168.1.1/16    掩码网段地址\n' \
                 '-h ip.txt    地址文件\n'
        ip_list = []
        if ".txt" in ipcmd:
            try:
                ip_file = open(ipcmd, "r", encoding="utf8")
                for ip in ip_file:
                    ip_list.append(ip.strip())
                ip_file.close()
            except FileNotFoundError:
                print("\nIP地址文件 %s 不存在！\n" % ipcmd)
                exit()
        elif '/' in ipcmd:
            ips = IPy.IP(ipcmd)
            for ip in ips:
                ip_list.append(ip)
        else:
            if "." in ipcmd:
                if len(ipcmd.split('.')) == 4:
                    ip_list.append(ipcmd)
                else:
                    print(errMsg)
                    exit()
            else:
                print(errMsg)
                exit()

        return ip_list

    def getUserList(self, usercmd):
        user_list = []
        if ".txt" in usercmd:
            try:
                user_file = open(usercmd, "r", encoding="utf8")
                for user in user_file:
                    user_list.append(user.strip())
                user_file.close()
            except FileNotFoundError:
                print("\n用户名文件 %s 不存在！\n" % usercmd)
                exit()
        else:
            user_list.append(usercmd)

        return user_list

    def getPassList(self, passcmd):
        pass_list = []
        if ".txt" in passcmd:
            try:
                pass_file = open(passcmd, "r", encoding="utf8")
                for pwd in pass_file:
                    if pwd.strip() == "空":
                        pass_list.append(' ')  # 添加空密码
                    else:
                        pass_list.append(pwd.strip())
                pass_file.close()
            except FileNotFoundError:
                print("\n密码文件 %s 不存在！\n" % passcmd)
                exit()
        else:
            pass_list.append(passcmd)

        return pass_list

    def prepareQueue(self, ips):
        for ip in ips:
            self.q.put(ip)

    def connect(self, user_pwd, ):
        (username, password) = user_pwd

        while not self.q.empty():
            ip = self.q.get()

            try:
                pymysql.connect(host=ip, user=username, passwd=password, port=self.port, connect_timeout=self.timeout)
                self.lock.acquire()
                print("----- Success connected. (IP: %s, User: %s, Pass: %s)" % (ip, username, password))
                # with open(self.outfile, 'a') as f:
                #     f.write(ip + ":" + str(port) + "\t" + username + "\t" + password + "\n")
                mq.save_host(ip, username, password)
                self.lock.release()
            except Exception as e:
                if PRINTALL:
                    self.lock.acquire()
                    print("Failed connected. (IP: %s, User: %s, Pass: %s)" % (ip, username, password))
                    self.lock.release()
                else:
                    pass

    def scanner(self, user_pwd, ):
        t_wait = []

        for i in range(THREAD):
            t = threading.Thread(target=ms.connect, args=(user_pwd, ))
            t.start()
            t_wait.append(t)

        for t in t_wait:
            t.join()


if __name__ == '__main__':

    opts, args = getopt.getopt(sys.argv[1:], "hH:u:p:P:T:t:s:a:")
    for opt, arg in opts:
        if opt == '-h':
            print("""
    __  ___                 _______                                 
   /  |/  /_  ___________ _/ / ___/_________ _____  ____  ___  _____
  / /|_/ / / / / ___/ __ `/ /\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / /  / / /_/ (__  ) /_/ / /___/ / /__/ /_/ / / / / / / /  __/ /    
/_/  /_/\__, /____/\__, /_//____/\___/\__,_/_/ /_/_/ /_/\___/_/     
       /____/        /_/    

\t -H\t 主机地址，有以下三种方式：
\t \t 192.168.1.1   单个地址
\t \t 192.168.1.1/16    掩码网段地址
\t \t ip.txt    地址文件
\t -u\t 用户文件或单个用户 [默认：dic_username_mysql.txt] 
\t -p\t 密码文件或单个密码 [默认：dic_password_mysql.txt] 
\t -P\t 端口号 [默认：3306] 
\t -T\t 线程数量 [默认：12] 
\t -t\t 连接超时 [默认：1.0s] 
\t -s\t 保存结果 [默认：result.txt] 
\t -a\t 打印模式 [默认：1 显示失败结果]
""")
            exit()
        elif opt == '-H':
            ipcmd = arg
        elif opt == '-u':
            usercmd = arg
        elif opt == '-p':
            passcmd = arg
        elif opt == '-P':
            port = int(arg)
        elif opt == '-T':
            thread = int(arg)
        elif opt == '-t':
            timeout = float(arg)
        elif opt == '-s':
            savefile = arg
        elif opt == '-a':
            printall = int(arg)

    mq = LinkMysql()

    ms = MysqlScanner()
    ips = ms.getIpList(ipcmd)
    users = ms.getUserList(usercmd)
    pwds = ms.getPassList(passcmd)

    user_pwds = []          # 列表存储自字典
    for user in users:
        for pwd in pwds:
            user_pwds.append((user, pwd))

    for user_pwd in user_pwds:
        ms.prepareQueue(ips)        # 每一个用户密码都需要重新填充队列
        ms.scanner(user_pwd)
