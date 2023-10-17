# Time Based One Time Password C Implementation

## Running instructions
### Dependencies
To run the code, OpenSSL library and its sublibraries are a must. (EVP, HMac)<br/>
Must-have header files include:
* <stdio.h>
* <string.h>
* <time.h>
* <math.h>
* <openssl/evp.h>
* <openssl/hmac.h>
* <signal.h>
* <stdlib.h>
* <ctype.h> <br/><br/>
This code was written and tested in Kali Linux with openssl version OpenSSL 3.0.10<br/>

### To compile the code:
gcc -o totp totp.c -lm -lcrypto<br/>
Or simply; <br/>
run 'make' in the terminal<br/>
### To delete the binary file:
run 'make clean' in the terminal<br/>
### To see the possible commands on terminal
Run "./totp help"<br/>
### To generate a TOTP with the default key
./totp<br/><br/>
This will generate a TOTP with a default seeded key: "313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930"
### To generate a TOTP with a custom key
./totp key [your key] (e.g ./totp key 1234567890)<br/>
### To verify your TOTP with the default key
./totp verify [your TOTP] (e.g ./totp verify 612212)
### To verify your TOTP with your custom key
./totp verify [your key] [your TOTP] (e.g ./totp verify 1234567890 612212)<br/>

### To run the test cases from the paper
./totp test<br/>

## Implementation Details
This code is based on the rfc6238 paper.<br/>
See: https://datatracker.ietf.org/doc/html/rfc6238 for details<br/>
Time Step (X) is 30 seconds.<br/>
T0 initial time is 0.<br/>
Current unix time is based on seconds.<br/>
EVP's HMAC and sha3-512 algorithms are used for calculating the hash value.<br/>

## Verifying Process
This algorithm accepts one time-step backwards TOTPs in addition to the current TOTP.<br/>
For example if in time interval 0, the algorithm generates TOTP 123456, and in time interval 1, it generates 234567, both values are accepted at time interval 1. <br/>Normally the securest way is to accept only one time interval's output. However, I decided to allow this because opening a second terminal or restarting the terminal to verify the code may take some time. 