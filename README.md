This is a small and portable ssh server for VxWorks 5.x<br>
<br>
Features list:<br>
<b>Version 2.0.x</b> supports the following:<br> 
 - keys    : RSA<br>
 - ciphers : AES (128/192/256) CBC/CTR<br>
 - macs    : MD5, SHA1, SHA256<br>
 - kex     : curve25519-sha256<br>
<br>
------------------------------------------------------------------------<br>
History of changes:<br>
<b>10.01.2021</b><br>
    * fixed some bugs<br>
    + added tests<br>
    + added chaha, poly1305 algorithms (but not used yet) <br>

<b>14.10.2020</b><br>
    initial version<br>
<br>
------------------------------------------------------------------------<br>
A brief help about keys creation:<br>
<br>
$ openssl genpkey -algorithm RSA -out srv_key.pem -pkeyopt rsa_keygen_bits:1024 <br>
$ openssl rsa -in srv_key.pem -out srv_key_new.key <br>

