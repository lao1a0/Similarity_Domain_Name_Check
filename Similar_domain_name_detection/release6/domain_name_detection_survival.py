import asyncio
import aiohttp


def search_status_code_async(domains, num=300):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # 加上这一行
    policy = asyncio.WindowsSelectorEventLoopPolicy()
    asyncio.set_event_loop_policy(policy)

    async def check(data, semaphore):
        try:
            global url_result_success
            async with semaphore:
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=64, ssl=False)) as session:
                    async with session.get("http://" + data['domain'].strip()) as resp:
                        print("http://" + data['domain'].strip() + "    " + str(resp.status))
                        if resp.status in [100, 101, 200, 201, 202, 203, 204, 205, 206, 300, 301, 302, 303, 304, 305,
                                           306, 307, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412,
                                           415, 417, 500, 501, 504, 505]:
                            url_result_success.append(data)
                            return await resp.text()
        except Exception as e:
            if str(e) == '':
                print(">**>", i['domain'], e)
            elif '[getaddrinfo failed]' not in str(e):
                print(">>", i['domain'], e)

    tasks = []
    for i in domains:
        semaphore = asyncio.Semaphore(num)  # 限制并发量为300
        task = asyncio.ensure_future(check(i, semaphore))
        tasks.append(task)
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(asyncio.gather(*tasks))
    print(result)
    return url_result_success


if __name__ == '__main__':
    # domains = search_whois_async_plus(domains, args['num'])
    # domains = search_status_code_async(domains, args['num'])
    domains = search_ping_thread(domains, args['threads'])