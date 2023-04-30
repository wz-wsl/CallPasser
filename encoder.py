
print("[*] start")
shellcodes=b""
sc=[]
for i in shellcodes:
    sc.append(str(i^1024))
sc=",".join(sc).split(",")
hfile=open("callpasser.ini","w")
hfile.write("[key]\n")
n=0
for i in sc:
    hfile.write(f"{n}={i}\n")
    n+=1
print("[*] success")
hfile.close()