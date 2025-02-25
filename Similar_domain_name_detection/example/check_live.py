import asyncio, aiohttp, time, threading, argparse
from colorama import init,Fore
init(autoreset=True)

headers = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Mobile Safari/537.36'
}

def check_urls(file):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Mobile Safari/537.36'
    }
    try:
        urls = [url.strip() if url.startswith("http://") or url.startswith("https://") else "http://" + url.strip() for url in open(file, "r", encoding="utf-8")]
    except Exception as e:
        print("打开%s文件失败：%s" %(file, e))
        return
    print(Fore.YELLOW+"[INFO]共%s个网站" % len(urls))
    lock = threading.Lock()  # 创建互斥锁

    async def check_url(url, sem):
        async with sem:
            retry_count = 2  # 设置重试次数为2
            while retry_count > 0:
                retry_count -= 1
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, headers=headers, ssl=False, timeout=18, allow_redirects=False) as response:
                            code = response.status
                            if code in [200, 404, 403, 301, 302]:
                                print(Fore.GREEN+"[+]响应码：%s %s 存活" %(code, url))
                                with lock:
                                    with open('alive.txt', 'a', encoding='utf-8') as f:
                                        f.write(url + '\n')
                            else:
                                print(Fore.RED+"[-]响应码：%s %s die" %(code, url))
                                with lock:  
                                    with open('die.txt', 'a', encoding='utf-8') as f:
                                        f.write(url + '\n')
                            return
                except asyncio.TimeoutError as e:
                    if retry_count == 0:
                        print(Fore.RED+"[-]请求超时：%s %s" %(url,repr(e)))
                        with lock:  
                            with open('die.txt', 'a', encoding='utf-8') as f:
                                f.write(url + '\n')
                    else:
                        await asyncio.sleep(0.7)  # 重试之前等待1秒
                except Exception as e:
                    print(Fore.RED+"[-]请求异常：%s %s" %(url, repr(e)))
                    with lock:  
                        with open('die.txt', 'a', encoding='utf-8') as f:
                            f.write(url + '\n')
                    return

    async def main():
        sem = asyncio.Semaphore(100)  # 设置并发请求数量为100
        tasks = []
        for url in urls:
            tasks.append(check_url(url, sem))
        await asyncio.gather(*tasks)

    start_time = time.time()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    end_time = time.time()
    elapsed_time = end_time - start_time

    print(Fore.GREEN+"检测完成，耗时：%s 秒。存活url保存在alive.txt，不存活url保存在die.txt" % elapsed_time)
if __name__ == '__main__':
    import  time
    t1=time.time()
    file='example/url.txt'
    check_urls(file)
    t2=time.time()
    print("{:.2f}s".format(t2-t1))