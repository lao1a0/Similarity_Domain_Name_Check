#!/user/bin/python
# -*- coding: UTF-8 -*-
import datetime
import os
import pandas as pd


def fatch_data_from_db(snum=0, lnum=1000):
    import pymongo
    client = pymongo.MongoClient("mongodb://ybkjadmin:Root123!@27.124.46.123:27017")
    collection = client['yuanbaotech_admin_v3']['similar_domain_info']
    task_url_list = []
    for i in collection.find({}, {'task_url': 1}).sort([("_id", -1)]).skip(snum).limit(lnum):
        task_url_list.append(i['task_url'])
    print(task_url_list)
    return task_url_list

def create_table_header():
    save_path = os.path.join(os.path.dirname(__file__), 'file')
    if not os.path.exists(save_path):
        os.makedirs(save_path)
    f_name = os.path.join(save_path, "{}-{}.csv".format(datetime.date.today().year, datetime.date.today().month))
    col_names = ["task_url", "fuzzer_num", 'similar_domain_num', "total_time","fuzzer_time"]
    df = pd.DataFrame([col_names])
    df.to_csv(f_name, mode='a', index=False, header=False, encoding='utf-8')
    print("<<文件：{}写入成功".format(f_name))


if __name__ == '__main__':
    test_list = ['onistudios.gg']
    create_table_header()
    for i in test_list:
        print("\n>>>[start]>>> ", i)
        os.system("python name_exist_request.py {}".format(i))  # 使用a接收返回值
