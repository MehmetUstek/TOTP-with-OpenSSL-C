#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <signal.h>
#include <stdlib.h>

static volatile sig_atomic_t keepRunning = 1;

static int DIGITS_POWER[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

static void sig_handler(int _)
{
    (void)_;
    keepRunning = 0;
}

unsigned char *mx_hmac_sha256(const void *key, int keylen,
                              const unsigned char *data, int datalen,
                              unsigned char *result, unsigned int *resultlen)
{
    return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}

// TODO: Error Handling
unsigned char *hmac_result(char *key, const unsigned char *msg)
{
    int keylen = strlen(key);
    int msglen = strlen((char *)msg);
    unsigned char *result = NULL;
    unsigned int resultlen = -1;

    result = mx_hmac_sha256((const void *)key, keylen, msg, msglen, result, &resultlen);
    return result;
}

// TODO: Test this function
char *strPaddingToBeginning(char *str)
{
    size_t len = strlen(str);
    memmove(str + 1, str, ++len);
    *str = "0";
}

char *generateTOTP(char *key,
                   char *time,
                   char *returnDigits)
{
    int codeDigits = atoi(returnDigits);
    char *result;

    // int codeDigits = Integer.decode(returnDigits).intValue();
    // String result = null;
    // Using the counter
    // First 8 bytes are for the movingFactor
    // Compliant with base RFC 4226 (HOTP)
    while (strlen(time) < 16)
    {
        // time = "0" + time;
        size_t len = strlen(time);
        memmove(time + 1, time, ++len);
        *time = "0";
    }
    // Get the HEX in a Byte[]
    // TODO: Probably will not work bc. of the []. Change it to *
    unsigned char msg[] = hexStr2Bytes(time);
    unsigned char k[] = hexStr2Bytes(key);
    unsigned char hash[] = hmac_result(k, msg);
    // put selected bytes into result int
    int offset = hash[strlen(hash) - 1] & 0xf;
    int binary =
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);
    int otp = binary % DIGITS_POWER[codeDigits];
    sprintf(result, "%d", otp);
    while (strlen(result) < codeDigits)
    {
        strPaddingToBeginning(result);
    }
    return result;
}

/// @brief Converts hex value to byte array in the same way the rfc6238 algorithm does.
/// This code was brought and modified from stackoverflow.
/// @param hex
/// @return byte array
unsigned char *hexStr2Bytes(char *hex)
{
    int i;
    unsigned int bytearray[12];
    uint8_t str_len = strlen(hex);

    for (i = 0; i < (str_len / 2); i++)
    {
        sscanf(hex + 2 * i, "%02x", &bytearray[i]);
        printf("bytearray %d: %02x\n", i, bytearray[i]);
    }
}

int main(int argc, char **argv)
{
    // Accept signal to stop terminal with SIGINT (ctrl +c) process.
    signal(SIGINT, sig_handler);
    // Seed for HMAC-SHA256 - 32 bytes
    char *seed32 = "3132333435363738393031323334353637383930313233343536373839303132";

    clock_t start;
    double time_required = 10.0;
    double time_spent;
    double last_time = 0.0;

    /* Mark beginning time */
    while (keepRunning)
    {
        start = clock();
        do
        {
            /* Get CPU time since loop started */
            time_spent = (double)(clock() - start) / CLOCKS_PER_SEC;
            if (time_spent - last_time >= 1.0)
            {
                // Clean the console and write the new remaining value.
                printf("\033[A\33[2K\r Remaining time: %d seconds\n", (int)round(time_required - time_spent));
                last_time = time_spent;
            }
        } while ((time_spent < time_required) && keepRunning);
    }
    puts("Stopped by signal `SIGINT'");
    return EXIT_SUCCESS;
}