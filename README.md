# ssh-ciphers
Query encryption settings from an SSH service

```
devel@wks1 ssh-ciphers $ ./ssh-ciphers host.somewhere.com 22
[+] Connecting
[+] Address resolved
[+] Trying to connect ...
[+] Connected
[+] SSH version 2.0
[+] Received package
[.] Package length : 700
[.] Padding length : 7
[>] Message number   20 (SSH_MSG_KEXINIT)
[>] Cookie           91 A6 31 93 70 9F D0 DE 22 FC C8 35 22 13 D7 55 
* kex_algorithms
    diffie-hellman-group-exchange-sha1
    diffie-hellman-group14-sha1
    diffie-hellman-group1-sha1

* server_host_key_algorithms
    ssh-rsa
    ssh-dss

* encryption_algorithms_client_to_server
    aes128-ctr
    aes192-ctr
    aes256-ctr
    arcfour256
    arcfour128
    aes128-cbc
    3des-cbc
    blowfish-cbc
    cast128-cbc
    aes192-cbc
    aes256-cbc
    arcfour
    rijndael-cbc@lysator.liu.se

* encryption_algorithms_server_to_client
    aes128-ctr
    aes192-ctr
    aes256-ctr
    arcfour256
    arcfour128
    aes128-cbc
    3des-cbc
    blowfish-cbc
    cast128-cbc
    aes192-cbc
    aes256-cbc
    arcfour
    rijndael-cbc@lysator.liu.se

* mac_algorithms_client_to_server
    hmac-md5
    hmac-sha1
    hmac-ripemd160
    hmac-ripemd160@openssh.com
    hmac-sha1-96
    hmac-md5-96

* mac_algorithms_server_to_client
    hmac-md5
    hmac-sha1
    hmac-ripemd160
    hmac-ripemd160@openssh.com
    hmac-sha1-96
    hmac-md5-96

* compression_algorithms_client_to_server
    none
    zlib@openssh.com

* compression_algorithms_server_to_client
    none
    zlib@openssh.com

* languages_client_to_server

* languages_server_to_client

[>] first_kex_packet_follows   FALSE
```
