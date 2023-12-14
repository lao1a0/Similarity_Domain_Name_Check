#!/usr/bin/env python
# coding: utf-8

# # 单线程

# In[3]:


import pandas as pd
import pymongo
client = pymongo.MongoClient("mongodb://ybkjadmin:Root123!@27.124.46.123:27017")
collection = client['yuanbaotech_admin_v3']['similar_domain_info']

def fetch_from_db(task_url,collection=collection):
    task_url_list = []
    for i in collection.find({'task_url': task_url}):
        return i['similar_domain_list']
big_table=pd.read_csv("2023-6.csv")


# In[4]:


def _to_list(name):
    try:
        _=pd.read_csv(name)
        return _.loc[:, 'domain'].to_list()
    except Exception as e:
        if (isinstance(e, pd.errors.EmptyDataError)):
            return []


# In[5]:


same_rate=[]
for _ in big_table['task_url']:
    domain_in_db=fetch_from_db(_)
    print("{} 相似域名.csv".format(_))
    domain_in_csv =_to_list("{} 相似域名.csv".format(_))
    same_domain_list= [k for k in domain_in_db if k in domain_in_csv]
    extra_domain_list= [k for k in domain_in_csv if k not in domain_in_db]
    same_rate.append({
        "task_url":_,
        "rate":len(same_domain_list)/len(domain_in_db),
        "same":','.join(same_domain_list),
         "extra":','.join(extra_domain_list),
    })


# In[ ]:


pd_same_rate=pd.DataFrame(same_rate)


# In[83]:


pd_same_rate.rate=0


# In[53]:


pd_same_rate.to_csv("2023-06-09_compare_with_db.csv")


# # 多线程

# In[ ]:


import queue
import threading


def __job(data, q):
    for _ in data:
        domain_in_db = fetch_from_db(_)
    print("{} 相似域名.csv".format(_))
    domain_in_csv = _to_list("{} 相似域名.csv".format(_))
    same_domain_list = [k for k in domain_in_db if k in domain_in_csv]
    extra_domain_list = [k for k in domain_in_csv if k not in domain_in_db]
    q.put({
        "task_url": _,
        "rate": len(same_domain_list) / len(domain_in_db),
        "same": ','.join(same_domain_list),
        "extra": ','.join(extra_domain_list),
    })


def my_reshape(data_set, row):
    ''':cvar 行号对应线程数量，不动，动的是列号'''
    column = len(data_set) // row  # 最后一个list的数量
    _ = np.array(data_set[:column * row]).reshape(row, column).tolist()
    __ = 0
    for i in data_set[column * row:]:
        _[__].append(i)
        __ += 1
    return _


q = queue.Queue()
threads = []  # 线程列表
tnum = 30
data = my_reshape(big_table['task_url'], tnum)

for i in range(tnum):
    t = threading.Thread(target=__job, args=(data[i], q))
    t.start()
    threads.append(t)
for thread in threads:
    thread.join()
for _ in range(q.qsize()):
    same_rate.append(q.get())


# In[ ]:


pd_same_rate=pd.DataFrame(same_rate)
pd_same_rate


# # 信息熵
# 
# 查看一下数据库中的相似域名与源域名的信息熵之间的差异有多大

# In[78]:


import math

def _sae(data):
    # 用于删除低质量的域名
    valid_chars = set(data)
    entropy = 0
    for x in valid_chars:
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy
def _similar_alg_entropy(data):
    l=[]
    for _ in data:
        l.append(_sae(_))
    return sum(l)/len(l)


# In[79]:


import numpy as np
a=[]
b=[]
for _ in  big_table['task_url']:
    b.append(_similar_alg_entropy(fetch_from_db(_)))# 算一个相似域名的平均信息熵
    a.append(_sae(_))


# In[80]:


import matplotlib.pyplot as plt

x = np.arange(0, len(b))

plt.plot(x, a, c='red', label="a:Original domain name")
plt.plot(x, b, c='green', linestyle='-.', label="b:Similar domain name", alpha=0.75)
plt.scatter(x, b, c='yellow')
plt.legend(loc='best')
plt.ylabel("information entropy")
plt.grid(True, alpha=0.5)
plt.show()


# 可以发现，二者的信息熵重叠部分还是挺多的

# In[81]:


cc=[]
for _ in range(len(a)):
    cc.append(math.fabs(a[_]-b[_]))


# In[87]:


x = np.arange(0, len(cc))

plt.plot(x, cc, c='orange', label="|a-b|",alpha=0.75)
plt.plot(x, [sum(cc)/len(cc) for i in x], c='blue', linestyle='-.', label="avg(|a-b|)")
# plt.scatter(x, b, c='yellow')
plt.legend(loc='best')
plt.ylabel("information entropy")
plt.grid(True, alpha=0.5)
plt.show()


# In[89]:


print("信息熵之差：\n最大值：{}\n最小值：{}\n平均值：{}".format(max(cc),min(cc),sum(cc)/len(cc)))


# 想要全部包含的话，信息熵设置为0.73

# In[95]:


e=[]
for i in range(len(a)):
    e.append([big_table['task_url'][i],a[i],b[i],cc[i]])


# In[96]:


pd_e=pd.DataFrame(e,columns=["task_url","原始域名","相似域名","二者之差"])
pd_e


# In[97]:


def _fig(a,b,name):
    import matplotlib.pyplot as plt
    x = np.arange(0, len(b))
    plt.plot(x, a, c='red', label="a:Original domain name")
    plt.plot(x, b, c='green', linestyle='-.', label="b:{}".format(name), alpha=0.75)
    plt.scatter(x, b, c='yellow')
    plt.legend(loc='best')
    plt.ylabel("information entropy")
    plt.grid(True, alpha=0.5)
    plt.show()


# # difflib

# In[109]:


import difflib

import numpy as np
a=[]
b=[]
for __ in  big_table['task_url']:
    _=[]
    for i in fetch_from_db(__): # 从数据库中获取所有的相似域名
        _.append(difflib.SequenceMatcher(None, __, i).ratio())# 算一个相似域名的平均
    print(sum(_)/len(_))
    b.append(sum(_)/len(_)) # 算一个平均值


# In[115]:


x = np.arange(0, len(b))
plt.plot(x, b, c='green', linestyle='-.',label="difflib", alpha=0.75)
plt.plot(x, [sum(b)/len(b) for i in x], c='blue', linestyle='-.', label="avg")
plt.scatter(x, b, c='yellow')
plt.legend(loc='best')
plt.ylabel("difflib")
plt.grid(True, alpha=0.5)
plt.show()


# # simhash相似度

# In[ ]:


from simhash import Simhash


def simhash_similarity(text1, text2):
    """
    :param text1: 文本1
    :param text2: 文本2
    :return: 返回两篇文章的相似度
    """
    aa_simhash = Simhash(text1)
    bb_simhash = Simhash(text2)
    max_hashbit = max(len(bin(aa_simhash.value)), (len(bin(bb_simhash.value))))
    # 汉明距离
    distince = aa_simhash.distance(bb_simhash)
    similar = 1 - distince / max_hashbit
    return similar
simhash=[]
for __ in  big_table['task_url']:
    _=[]
    for i in fetch_from_db(__): # 从数据库中获取所有的相似域名
        _.append(simhash_similarity(_,i))# 算一个相似域名的平均
    simhash.append(sum(_)/len(_)) # 算一个平均值


# In[ ]:


import numpy as np
import matplotlib.pyplot as plt

x = np.arange(0, len(simhash))
plt.plot(x, simhash, c='green', linestyle='-.', label="simhash",alpha=0.75)
plt.plot(x, [sum(simhash)/len(simhash) for i in x], c='blue', linestyle='-.', label="avg")
plt.scatter(x, simhash, c='yellow')
plt.legend(loc='best')
plt.ylabel("simhash")
plt.grid(True, alpha=0.5)
plt.show()


# ![image.png](attachment:image.png)

# # Levenshtein
# 
# ## 编辑距离

# In[ ]:


import Levenshtein


# In[141]:


Levenshtein_distance=[]
for __ in  big_table['task_url']:
    _=[]
    for i in fetch_from_db(__): # 从数据库中获取所有的相似域名
        _.append(Levenshtein.distance(__,i))# 算一个相似域名的平均
    Levenshtein_distance.append(sum(_)/len(_)) # 算一个平均值


# In[143]:


import numpy as np
import matplotlib.pyplot as plt

x = np.arange(0, len(Levenshtein_distance))
plt.plot(x, Levenshtein_distance, c='green', linestyle='-.', label="Levenshtein_distance",alpha=0.75)
plt.plot(x, [sum(Levenshtein_distance)/len(Levenshtein_distance) for i in x], c='blue', linestyle='-.', label="avg")
plt.scatter(x, Levenshtein_distance, c='yellow')
plt.legend(loc='best')
plt.ylabel("Levenshtein_distance")
plt.grid(True, alpha=0.5)
plt.show()


# ## 莱文斯坦比

# In[139]:


Levenshtein_ratio=[]
for __ in  big_table['task_url']:
    _=[]
    for i in fetch_from_db(__): # 从数据库中获取所有的相似域名
        _.append(Levenshtein.ratio(__,i))# 算一个相似域名的平均
    Levenshtein_ratio.append(sum(_)/len(_)) # 算一个平均值


# In[ ]:


import numpy as np
import matplotlib.pyplot as plt

x = np.arange(0, len(Levenshtein_ratio))
plt.plot(x, Levenshtein_ratio, c='green', linestyle='-.', label="Levenshtein_ratio",alpha=0.75)
plt.plot(x, [sum(Levenshtein_ratio)/len(Levenshtein_ratio) for i in x], c='blue', linestyle='-.', label="avg")
plt.scatter(x, Levenshtein_ratio, c='yellow')
plt.legend(loc='best')
plt.ylabel("Levenshtein_ratio")
plt.grid(True, alpha=0.5)
plt.show()


# ![image.png](attachment:image.png)

# ## jaro距离

# In[135]:


Levenshtein_jaro=[]
for __ in  big_table['task_url']:
    _=[]
    for i in fetch_from_db(__): # 从数据库中获取所有的相似域名
        _.append(Levenshtein.jaro(__,i))# 算一个相似域名的平均
    Levenshtein_jaro.append(sum(_)/len(_)) # 算一个平均值


# In[ ]:


import numpy as np
import matplotlib.pyplot as plt

x = np.arange(0, len(Levenshtein_jaro))
plt.plot(x, Levenshtein_jaro, c='green', linestyle='-.', label="Levenshtein_jaro",alpha=0.75)
plt.plot(x, [sum(Levenshtein_jaro)/len(Levenshtein_jaro) for i in x], c='blue', linestyle='-.', label="avg")
plt.scatter(x, Levenshtein_jaro, c='yellow')
plt.legend(loc='best')
plt.ylabel("Levenshtein_jaro")
plt.grid(True, alpha=0.5)
plt.show()


# ![image.png](attachment:image.png)

# ## jaro–Winkler距离

# In[136]:


Levenshtein_jaro_winkler=[]
for __ in  big_table['task_url']:
    _=[]
    for i in fetch_from_db(__): # 从数据库中获取所有的相似域名
        _.append(Levenshtein.jaro_winkler(__,i))# 算一个相似域名的平均
    Levenshtein_jaro_winkler.append(sum(_)/len(_)) # 算一个平均值


# In[ ]:


import numpy as np
import matplotlib.pyplot as plt

x = np.arange(0, len(Levenshtein_jaro_winkler))
plt.plot(x, Levenshtein_jaro_winkler, c='green', linestyle='-.', label="Levenshtein_jaro_winkler",alpha=0.75)
plt.plot(x, [sum(Levenshtein_jaro_winkler)/len(Levenshtein_jaro_winkler) for i in x], c='blue', linestyle='-.', label="avg")
plt.scatter(x, simhash, c='yellow')
plt.legend(loc='best')
plt.ylabel("Levenshtein_jaro_winkler")
plt.grid(True, alpha=0.5)
plt.show()


# ![image.png](attachment:image.png)
