Small and portable SSH server for VxWorks 5.x <br>

NOTICE: <br>
 The server uses (by default) vxworks prnd functions. <br>
 And if you are planning to use this server in your project, would be a good idea to replace these functions on more safety (emssh_crypto_rnd.c). <br>


Generate the server key: <br>
# openssl genpkey -algorithm RSA -out srv_key.pem -pkeyopt rsa_keygen_bits:1024 <br>
# openssl rsa -in srv_key.pem -out srv_key_new.key <br>


<b>Version 2.0.1:</b> [emsshd2-arm7-be.elf 19/03/2020](builds/emsshd2-arm7-be.elf) <br> 
 - server / user key: RSA <br>
 - ciphers: AES (128/192/256) CBC/CTR <br>
 - macs   : MD5, SHA1, SHA256 <br>
 - kex    : curve25519-sha256 <br>


<b>Roadmap:</b> <br>
 - describe the API and write manuals <br>
 - add authorization by publickey <br>
 - add chach20-poly1305 <br>
 - add port forwarding <br>
 - add comepression (?) <br>
 - your ideas ? <br>


<b>Supports this project:</b> <br>
 If you want to support this project, you can do it via donates ;) <br>


--------------------------------------------------------------------------- <br>
Useful docs:<br>

RFC's <br>
https://tools.ietf.org/html/rfc4252 <br>
https://tools.ietf.org/html/rfc4253 <br>
https://tools.ietf.org/html/rfc4254 <br>

Diffie-Hellman Group Exchange <br>
https://tools.ietf.org/html/rfc4419 <br>
https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html <br>
https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml <br>

RSA <br>
https://tools.ietf.org/html/rfc3447 <br>

curve25519 <br>
https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman <br>
https://tools.ietf.org/id/draft-ietf-curdle-ssh-curves-07.html <br>
https://tools.ietf.org/html/rfc5656 <br>

asn1 <br>
https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem <br>
