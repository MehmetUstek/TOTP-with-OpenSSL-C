# Time Based One Time Password C Implementation

## Running instructions
To run the code, OpenSSL library and its sublibraries are a must. (EVP, HMac)<br/>
This code was written and tested in Kali Linux with openssl version OpenSSL 3.0.10<br/>

### To compile the code:<br/>
gcc -o totp totp.c -lm -lcrypto<br/>
### To see the possible commands on terminal<br/>
Run "./totp help"<br/>
### To generate a TOTP with the default key<br/>
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

