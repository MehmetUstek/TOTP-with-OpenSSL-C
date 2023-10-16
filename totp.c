#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <signal.h>
#include <stdlib.h>

// Function declarations
void longToHex(time_t unix_time, int64_t T0, int64_t X, char *steps);
void hexToByteArray(const char *hex, unsigned char *val);
unsigned char *hmac_sha256(const void *key, size_t keylen, const unsigned char *data, size_t datalen,
                           unsigned char *result, unsigned int *resultlen);
unsigned char *hmac_result(unsigned char *key, const unsigned char *msg, size_t keylen, size_t msglen);
void generateTOTP(char *key, time_t time, int codeDigits, int64_t T0, int64_t X,
                  char result[7]);

static int DIGITS_POWER[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
long testTime[] = {59L, 1111111109L, 1111111111L,
                   1234567890L, 2000000000L, 20000000000L};

static volatile sig_atomic_t keepRunning = 1;

static void sig_handler(int _)
{
    (void)_;
    keepRunning = 0;
}

unsigned char *hmac_sha256(const void *key, size_t keylen,
                           const unsigned char *msg, size_t datalen,
                           unsigned char *result, unsigned int *resultlen)
{
    return HMAC(EVP_sha256(), key, keylen, msg, datalen, result, resultlen);
}

// TODO: Error Handling
unsigned char *hmac_result(unsigned char *key, const unsigned char *msg, size_t keylen, size_t msglen)
{
    // int length = sizeof(msg) / sizeof(msg[0]);
    // int lkength = sizeof(key) / sizeof(key[0]);
    // size_t keykklen = strlen(key);
    unsigned char *result = NULL;
    unsigned int resultlen = -1;

    result = hmac_sha256((const void *)key, keylen, msg, msglen, result, &resultlen);
    return result;
}

void longToHex(time_t unix_time, int64_t T0, int64_t X, char *steps)
{
    int64_t T = (unix_time - T0) / X;

    // zero-padding to fill 16 bytes, convert from long to hexadecimal.
    snprintf(steps, 17, "%016lX", T);

    // printf("Hexadecimal string: %s\n", steps);
}

/// @brief Converts hex value to byte array in the same way the rfc6238 algorithm does.
/// This code was brought and modified from stackoverflow.
/// @param hex
/// @return byte array
/// https://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c
void hexToByteArray(const char *hex, unsigned char *val)
{
    // char *inputHex = malloc(strlen(hex) + 3); // 2 for "0x", 1 for null terminator

    // strcpy(inputHex, "0x");
    // strcat(inputHex, hex);

    // const char *pos = inputHex + 2;
    // if (val == NULL)
    // {
    //     free(inputHex);
    // }
    const char *pos = hex;
    size_t length = strlen(hex) / 2;

    for (size_t count = 0; count < length; count++)
    {

        sscanf(pos, "%02hhx", &val[count]);
        pos += 2;
    }
    // if (length > 0)
    // {
    //     for (size_t i = 0; i < length; i++)
    //     {
    //         printf("%02x ", val[i]);
    //     }
    // }

    // free(inputHex);
}

void verifyTOTP()
{
    puts("Verify Code:");
}
void generateTOTP(char *key,
                  time_t time, // I choose not to implement time as a hex string as it is on the documentation, because I find it more confusing.
                  int codeDigits, int64_t T0, int64_t X,
                  char result[7])
{
    char steps[17]; // This steps replaces the 'time' variable in the documentation.
    longToHex(time, T0, X, steps);
    // Get the HEX in a Byte[]
    size_t msglen = ((strlen(steps) + 1) / 2); // Could be +1 not sure.
    unsigned char *msg = (unsigned char *)malloc(msglen);
    hexToByteArray(steps, msg);
    // for (size_t i = 0; i < (strlen(steps) + 3) / 2; i++)
    // {
    //     printf("msg: %02x ", msg[i]);
    // }

    size_t keylen = ((strlen(key) + 1) / 2);
    unsigned char *k = (unsigned char *)malloc(keylen);
    hexToByteArray(key, k);
    const unsigned char *hash = hmac_result(k, msg, keylen, msglen);
    // put selected bytes into result int
    int offset = hash[strlen(hash) - 1] & 0xf;
    int binary =
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);
    int otp = binary % DIGITS_POWER[codeDigits];
    snprintf(result, 7, "%06d", otp);
}

/// @brief Test with the values given in the last page of rfc6238 paper.
void test()
{
    // Seed for HMAC-SHA256 - 32 bytes
    char *secret = "12345678901234567890";
    long testTime[] = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
    int64_t T0 = 0;
    int64_t X = 30;
    for (int i = 0; i < 6; i++)
    {
        char result[7];
        generateTOTP(secret, testTime[i], 6, T0, X, result);
        printf("TOTP result:%s\n", result);
    }
}

/// @brief Accept signal to stop terminal with SIGINT (ctrl +c) process.
void catchSignal()
{
    signal(SIGINT, sig_handler);
}

int main(int argc, char **argv)
{
    catchSignal();
    if (argc > 1)
    {
        if (strcmp(argv[1], "test") == 0)
            test();
    }
    else
    {
        // Seed for HMAC-SHA256 - 32 bytes
        char *seed32 = "12345678901234567890";

        time_t start;
        double time_step = 30.0;
        double time_spent;
        double last_time = 0.0;
        time(&start);

        int64_t T0 = 0;
        int64_t X = 30;
        printf("Current Time as unix time:%ld\n", start);

        char result[7];
        // generateTOTP(seed32, unix_time, 6, T0, X, result);
        time_t currentTime;
        time(&currentTime);

        /* Mark beginning time */
        while (keepRunning)
        {
            time(&start);
            generateTOTP(seed32, 1111111109L, 6, T0, X, result);
            do
            {
                time(&currentTime);
                /* Get CPU time since loop started */
                time_spent = (double)difftime(currentTime, start);
                if (time_spent - last_time >= 1.0)
                {
                    // Clean the console and write the new remaining value.
                    printf("");
                    printf("\033[A\33[2K\r\033[A\33[2K\r Remaining time: %d seconds\t Your TOTP:%s\n", (int)round(time_step - time_spent), result);
                    //\033[A\33[2K\r\033[A\33[2K\r
                    last_time = time_spent;
                    verifyTOTP();
                }
            } while ((time_spent < time_step) && keepRunning);
            // Generate a new TOTP, and continue.
            strcpy(result, "");
            time(&currentTime);
            // printf("Current Time: %ld", currentTime);
            time_spent = 0.0;
            last_time = 0.0;
        }
        puts("\nStopped by signal `SIGINT'");
    }
    return EXIT_SUCCESS;
}