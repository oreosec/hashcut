import hashlib
import time
import sys

def saiki():
    now = time.strftime(" [%H:%M:%S] ", time.localtime(time.time()))
    return now
    
def buka(fail,hash,tipe):
    f = open(fail, "rb")
    fread = f.readlines()
    f.close()
    i = 1
    for x in fread:
        x = x.decode().replace("\n", "")
        if tipe == "md5":
            dec = hashlib.md5(x.encode()).hexdigest()
        elif tipe == "sha1":
            dec = hashlib.sha1(x.encode()).hexdigest()
        elif tipe ==  "sha224":
            dec = hashlib.sha224(x.encode()).hexdigest()
        elif tipe == "sha256":
            dec = hashlib.sha256(x.encode()).hexdigest()                 
        elif tipe == "sha384":
            dec = hashlib.sha384(x.encode()).hexdigest()
        elif tipe == "sha512":
            dec = hashlib.sha512(x.encode()).hexdigest()
        if dec ==  hash:
            print()
            print("\033[32m[TRUE]"+saiki()+"Hash founded !!: ", x)
        else:
            sys.stdout.write("\r ")
            sys.stdout.write("\033[31m[FALSE]"+saiki()+"<%s/%s> : %s" % (i,len(fread),x))
            sys.stdout.flush()
            i += 1

if __name__ == '__main__':
    def banner():
        print("""    
    __               __               __ 
   / /_  ____ ______/ /_  _______  __/ /_
  / __ \/ __ `/ ___/ __ \/ ___/ / / / __/
 / / / / /_/ (__  ) / / / /__/ /_/ / /_  
/_/ /_/\__,_/____/_/ /_/\___/\__,_/\__/                               
      md5, sha1, sha224, sha256, sha384, sha512 cracker 

coded by Dipkill (Clown Hacktivism Team)
visit:    https://clownhacktivismteam.orh
          https://github.com/Dipkill\n""")
            
    banner()
    hash = input("[*] Enter youre hash here > ")
    fail = input("[*] Enter wordlist > ")
    if (len(hash) == 32): 
        hashtype = 'md5' 
    elif (len(hash) == 40):
        hashtype = 'sha1'
    elif (len(hash) == 56):
        hashtype = 'sha224'
    elif (len(hash) == 64):
        hashtype = 'sha256'
    elif (len(hash) == 96):
        hashtype = 'sha384'
    elif (len(hash) == 128):
        hashtype = 'sha512'
    else:
            print("""List: 
\t1- md5
\t2- sha1
\t3- sha224
\t4- sha256
\t5- sha384
\t6- sha512""")
            pilih = input("[*] Select your hash > ")
            if pilih == "1":
                hashtype = "md5"
            elif pilih == "2":
                hashtype = "sha1"
            elif pilih == "3":
                hashtype = "sha224"
            elif pilih == "4":
                hashtype = "sha256"
            elif pilih == "5":
                hashtype = "sha384"
            elif pilih == "6":
                hashtype = "sha512"
            else:
                 print("\033[31m[!] Invalid menu !!\033[00m")
                 sys.exit()                   


    print("\033[32m[INFO]"+saiki()+"Trying decrypting hash",hashtype)
    try:
        buka(fail, hash, hashtype)
        print()
        print("\033[00mProcess completed ..")    
    except Exception as e:
        print()
        print("\033[31m[!] Error: %s" % e)    	
    
                    
        
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    