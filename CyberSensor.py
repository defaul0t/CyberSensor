import requests
import time
import re
import json
import urllib3
import xlrd
import xlwt
from xlutils.copy import copy

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {

    'Cookie': 'JSESSIONID=AB8AB409F1ECFB0C8BF802B3D8915052',
    'Content-Type': 'application/json;charset=utf-8'
}

# title = ''
# attackIp = ''
# AttackedIP = ''
# TimeStr = ''



def CY_Search():

    va_list = []
    for i in range(20, 0, -1):
        try:
            url = 'https://135.192.63.9/api/netidsEventlog/page'
            data = {"datasourceType": "latest",
                    "displayColumns": {"srcport": 1, "dstport": 1, "eventtypeid": 1, "eventlevel": 1, "eventtime": 1,
                                       "securityid": 1, "attackid": 1, "srcipStr": 1, "dstipStr": 1, "attackResult": 1},
                    "queryParam": {"eventlevels": [30, 40], "attackResult": ""}, "page": {"pageNo": i, "pageSize": 1},
                    "orderBy": {"field": "EVENTTIME", "order": -1}}
            r = requests.post(url=url, data=json.dumps(data), headers=headers, timeout=3, verify=False)
            r.encoding = 'UTF-8'
            str_text = r.text
            print(str_text)
            title = re.compile(r'(?<=eventName":")(.+?)(?=",")').search(str_text).group()
            attackIp = re.compile(r'(?<=srcipStr":")(.+?)(?=",")').search(str_text).group()
            AttackedIP = re.compile(r'(?<=dstipStr":")(.+?)(?=",")').search(str_text).group()
            TimeStr = re.compile(r'(?<=eventTimeStr":")(.+?)(?=",")').search(str_text).group()
            if attackIp in "已合并":
                continue
            flag = ip_search(attackIp)[0]
            print(flag)
            # 数据填充表格
            if flag == -1:
                address0 = ip_search(attackIp)[1]
                print(address0)
                output_ip(attackIp)
                va_list = [attackIp, 32, title, address0, AttackedIP, '杨济源', TimeStr]
                write_excel_xls_append('1.xls', va_list)
            else:
                print('青海本地ip')
                continue

        except:
            time.sleep(3)

    return va_list


def output_ip(ip):
    with open('攻击ip.txt', "a") as f:
        f.write(ip)


def write_excel_xls_append(name_xls, value):
    index = len(value)  # 获取需要写入数据的行数
    workbook = xlrd.open_workbook(name_xls)  # 打开工作簿
    sheets = workbook.sheet_names()  # 获取工作簿中的所有表格
    worksheet = workbook.sheet_by_name(sheets[0])  # 获取工作簿中所有表格中的的第一个表格
    rows_old = worksheet.nrows  # 获取表格中已存在的数据的行数
    new_workbook = copy(workbook)  # 将xlrd对象拷贝转化为xlwt对象
    new_worksheet = new_workbook.get_sheet(0)  # 获取转化后工作簿中的第一个表格
    for j in range(0, len(value)):
        new_worksheet.write(rows_old, j, value[j])  # 追加写入数据，注意是从i+rows_old行开始写入
    new_workbook.save(name_xls)  # 保存工作簿
    print("xls格式表格【追加】写入数据成功！")


FLAG = 1
address = ''
sk_ip_list = []


def ip_search(attackIp):
    global FLAG, address
    kv = {'user-agent': 'Mozilla/5.0'}
    url_ipsearch = 'http://ip-api.com/json/' + attackIp + '?lang=zh-CN'
    # print(url_ipsearch)
    r_add = requests.get(url=url_ipsearch, timeout=3, verify=False, headers=kv)
    r_add.encoding = 'utf-8'
    raa_str = r_add.text
    pd = bool(re.compile(r'(?<=regionName":")(.+?)(?=",)').search(raa_str))

    if pd:
        address = re.compile(r'(?<=regionName":")(.+?)(?=",)').search(raa_str).group()
        # print(address)
        # str_pd = '青海省'
        if address not in '青海省' and attackIp not in sk_ip_list:
            sk_ip_list.append(attackIp)
            FLAG = -1
        else:
            FLAG = 0

    return FLAG, address


if __name__ == '__main__':
    no = 1
    while no > 0:
        time.sleep(1)
        CY_Search()
