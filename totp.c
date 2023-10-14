#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <signal.h>
#include <stdlib.h>

// Function declarations
void hexToByteArray(const char *hex, unsigned char **byteArray, size_t *length);
unsigned char *mx_hmac_sha256(const void *key, int keylen, const unsigned char *data, int datalen,
                              unsigned char *result, unsigned int *resultlen);
unsigned char *hmac_result(unsigned char *key, const unsigned char *msg);
char *strPaddingToBeginning(char *str);
char *generateTOTP(char *key, char time[16], int codeDigits);

static int DIGITS_POWER[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
long testTime[] = {59L, 1111111109L, 1111111111L,
                   1234567890L, 2000000000L, 20000000000L};
char *steps = "0";

static volatile sig_atomic_t keepRunning = 1;

static void sig_handler(int _)
{
    (void)_;
    keepRunning = 0;
}

unsigned char *mx_hmac_sha256(const void *key, int keylen,
                              const unsigned char *msg, int datalen,
                              unsigned char *result, unsigned int *resultlen)
{
    return HMAC(EVP_sha256(), key, keylen, msg, datalen, result, resultlen);
}

// TODO: Error Handling
unsigned char *hmac_result(unsigned char *key, const unsigned char *msg)
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
    *str = '0';
    return str;
}

char *generateTOTP(char *key,
                   char time[8],
                   int codeDigits)
{
    char *result;
    // Using the counter
    // First 8 bytes are for the movingFactor
    // Compliant with base RFC 4226 (HOTP)
    // int targetStrLen = 16;
    // const char *padding = "0000000000000000";

    // int timeByteDifference = targetStrLen - strlen(time);
    // if (timeByteDifference < 0)
    //     timeByteDifference = 0;
    // sprintf(time, "[%*.*s%s]", timeByteDifference, timeByteDifference, padding, time);

    // while (strlen(time) < 16)
    // {
    //     // time = "0" + time;
    //     size_t len = strlen(time);
    //     memmove(time + 1, time, ++len);
    //     *time = '0';
    // }
    // Get the HEX in a Byte[]
    // TODO: Probably will not work bc. of the []. Change it to *
    size_t msglen;
    unsigned char *msg;
    hexToByteArray(time, msg, msglen);

    size_t klen;
    unsigned char *k;
    hexToByteArray(key, k, klen);
    const unsigned char *hash = hmac_result(k, msg);
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
    free(k);
    return result;
}

void longToHex(int64_t unix_time, int64_t T0, int64_t X, char *steps)
{
    int64_t T = (unix_time - T0) / X;

    // zero-padding to fill 16 bytes, convert from long to hexadecimal.
    snprintf(steps, 16, "%016lX", T);
    for (int i = 0; steps[i]; i++)
    {
        steps[i] = toupper(steps[i]);
    }

    printf("Hexadecimal string: %s\n", steps);
}

/// @brief Converts hex value to byte array in the same way the rfc6238 algorithm does.
/// This code was brought and modified from stackoverflow.
/// @param hex
/// @return byte array
void hexToByteArray(const char *hex, unsigned char **byteArray, size_t *length)
{
    // Concatenate "10" with the input hex string
    char *inputHex = malloc(strlen(hex) + 3); // 2 for "10", 1 for null terminator
    strcpy(inputHex, "10");
    strcat(inputHex, hex);

    // Convert hex string to unsigned long long integer
    unsigned long long num = strtoull(inputHex, NULL, 16);

    // Determine the length of the byte array
    *length = (size_t)((sizeof(unsigned long long) * 2 + 1) / 3); // Each byte represented by 2 hex characters, plus 1 for null terminator

    // Allocate memory for the byte array
    *byteArray = malloc(*length);

    // Copy the integer to the byte array
    for (size_t i = 0; i < *length; ++i)
    {
        (*byteArray)[i] = (unsigned char)(num >> (8 * ((*length - 1) - i))); // Extracting individual bytes
    }

    // Free dynamically allocated memory
    free(inputHex);
}

int main(int argc, char **argv)
{
    // Accept signal to stop terminal with SIGINT (ctrl +c) process.
    signal(SIGINT, sig_handler);

    // Seed for HMAC-SHA256 - 32 bytes
    char *seed32 = "3132333435363738393031323334353637383930313233343536373839303132";

    time_t start;
    double time_step = 10.0;
    double time_spent;
    double last_time = 0.0;
    time(&start);
    // printf("%ld", start);
    // printf("bytes: %d", sizeof(start));

    int64_t testTime[] = {59L};
    int64_t T0 = 0;
    int64_t X = 30;
    time_t unix_time = 1111111109L;
    char steps[16];
    longToHex(unix_time, T0, X, &steps);
    printf("Hexadecimal string: %s\n", steps);

    // printf("Generated OTP:%s", generateTOTP(seed32, start, 6));
    // const long *hex = 59; // Example input hex string
    // unsigned char *byteArray;
    // size_t length;
    // hexToByteArray(hex, &byteArray, &length);
    // // Print the resulting byte array
    // printf("Byte Array: ");
    // for (size_t i = 0; i < length; ++i)
    // {
    //     printf("%02X ", byteArray[i]); // Print in hexadecimal format
    // }
    // printf("\n");

    // start = clock();
    // printf("clock: %ld", start);

    /* Mark beginning time */
    // while (keepRunning)
    // {
    //     start = clock();
    //     do
    //     {
    //         /* Get CPU time since loop started */
    //         time_spent = (double)(clock() - start) / CLOCKS_PER_SEC;
    //         if (time_spent - last_time >= 1.0)
    //         {
    //             // Clean the console and write the new remaining value.
    //             printf("\033[A\33[2K\r Remaining time: %d seconds\n", (int)round(time_step - time_spent));
    //             last_time = time_spent;
    //         }
    //     } while ((time_spent < time_step) && keepRunning);
    // }
    // puts("\nStopped by signal `SIGINT'");
    return EXIT_SUCCESS;
}