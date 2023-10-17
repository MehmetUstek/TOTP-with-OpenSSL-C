all:
	gcc -o totp totp.c -lm -lcrypto
clean: 
	$(RM) totp