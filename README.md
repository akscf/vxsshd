The inicial project was written about 5 years ago (maybe more) and it was a simple tcp rpc server with couple of cryptographic methods for protect communications. 
   There was a task to control several thousand devices under vxworks5 but the existing firmware didn't contain necessary services
   (of course, there were telnet and snmp there but it wasn't enough we needed to call special functions and did additional actions...no matter it's a long story). <br>
   And as result this application was appeared. But several years ago a decided to replace it to a simple ssh server (I wanted to get rid of special client and use standart ssh client for it). 
   Unfortunately all that I found requested too much memory or I wasn't able to build it... <br>
   So and as usual I had to do it by myself. <br>
   <br>
   It used curve25519-sha256 for KEX because I think it more suitable for embedded devices with limited memory and performance. <br>
   (recently I've added poly1305/ChaCha but I've not uesed it yet, lack of time...) <br>
   <br>
   <mark>And finally, I'd like to pay attention to the following: </mark> <br>
   If you are going to use it in your projects, please have a look at an rekening algorithm more thoroughly (seems to me it can be buggy ;). <br>
   And rewrite or use a hardware implementation of random number generator [vxssh_crypto_rnd.c] (by default it uses a libc rand function) <br>
  </p>


### Current version supports
 - ciphers: AES (128/192/256) CBC/CTR
 - keys algorithms: RSA
 - macs: MD5, SHA1, SHA256
 - kex: curve25519-sha256
