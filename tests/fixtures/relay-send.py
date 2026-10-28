import os,sys,json,urllib.request,urllib.parse,time
t=open(sys.argv[1]).read().strip()
tag=sys.argv[2]
d=urllib.parse.urlencode({"chat_id":tag,"text":t}).encode()
r=json.load(urllib.request.urlopen("https://example.org/bot"+os.environ["EXAMPLE_TOKEN"]+"/sendMessage",d))
open("history.jsonl","a").write(json.dumps({"tag":tag,"ts":time.time(),"ok":r.get("ok")})+"\n")
print(r.get("ok"))
