<p>
 This is a small and portable ssh server for VxWorks 5.x
</p>
<p>Features list:</p>
<p>
 <b>Version 2.0.x</b> supports the following:
 <ul>
  <li>keys    : RSA</li>
  <li>ciphers : AES (128/192/256) CBC/CTR</li>
  <li>macs    : MD5, SHA1, SHA256</li>
  <li>kex     : curve25519-sha256</li>
  </ul>
</p>
<p>
 History of changes:
</p>
<p>
 <b>10.01.2021</b><br>
 <ul>
    <li>fixed some bugs</li>
    <li>added tests</li>
    <li>added chaha, poly1305 algorithms (but not used yet)</li>
 </ul>
</p>
<p>
 <b>14.10.2020</b>
 <ul>
  <li>initial version</li>
 </ul>
</p>
<p>
A brief help about keys creation:<br>
$ openssl genpkey -algorithm RSA -out srv_key.pem -pkeyopt rsa_keygen_bits:1024 <br>
$ openssl rsa -in srv_key.pem -out srv_key_new.key <br>
</p>
