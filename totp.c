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
void hexToByteArray(const char *hex, unsigned char *byteArray, size_t length);
unsigned char *mx_hmac_sha256(const void *key, int keylen, const unsigned char *data, int datalen,
                              unsigned char *result, unsigned int *resultlen);
unsigned char *hmac_result(unsigned char *key, const unsigned char *msg);
void generateTOTP(char *key, time_t time, int codeDigits, int64_t T0, int64_t X,
                  char result[7]);

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

void generateTOTP(char *key,
                  time_t time, // I choose not to implement time as a hex string as it is on the documentation, because I find it more confusing.
                  int codeDigits, int64_t T0, int64_t X,
                  char result[7])
{
    char steps[17]; // This steps replaces the 'time' variable in the documentation.
    longToHex(time, T0, X, steps);
    // Get the HEX in a Byte[]
    size_t msglen;
    unsigned char *msg;
    hexToByteArray(steps, msg, msglen);

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
    snprintf(result, 7, "%06d", otp);
}

void longToHex(time_t unix_time, int64_t T0, int64_t X, char *steps)
{
    int64_t T = (unix_time - T0) / X;

    // zero-padding to fill 16 bytes, convert from long to hexadecimal.
    snprintf(steps, 17, "%016lX", T);

    printf("Hexadecimal string: %s\n", steps);
}

/// @brief Converts hex value to byte array in the same way the rfc6238 algorithm does.
/// This code was brought and modified from stackoverflow.
/// @param hex
/// @return byte array
void hexToByteArray(const char *hex, unsigned char *byteArray, size_t length)
{
    length = (strlen(hex) + 1) / 2;

    // Concatenate "10" with the input hex string
    char *inputHex = malloc(strlen(hex) + 3); // 2 for "10", 1 for null terminator
    strcpy(inputHex, "10");
    strcat(inputHex, hex);

    // Convert hex string to unsigned long long integer
    unsigned long long num = strtoull(inputHex, NULL, 16);
    // Allocate memory for the byte array
    byteArray = (unsigned char *)malloc(length);

    for (size_t i = 0; i < length; ++i)
    {
        byteArray[i] = (unsigned char)(num >> (8 * ((length - 1) - i))); // Extracting individual bytes
    }

    // Check if the string has at least one character
    if (strlen(byteArray) > 1)
    {
        // Shift characters to remove the first character
        memmove(byteArray, byteArray + 1, strlen(byteArray));
        // Make sure the string is null-terminated
        byteArray[strlen(byteArray) - 1] = '\0';
    }
    // Free dynamically allocated memory
    free(inputHex);
}

int main(int argc, char **argv)
{
    // Accept signal to stop terminal with SIGINT (ctrl +c) process.
    signal(SIGINT, sig_handler);

    // Seed for HMAC-SHA256 - 32 bytes
    char *seed32 = "12345678901234567890";

    time_t start;
    double time_step = 5.0;
    double time_spent;
    double last_time = 0.0;
    time(&start);

    int64_t testTime[] = {59L};
    int64_t T0 = 0;
    int64_t X = 30;
    time_t unix_time = 1111111109L;
    char steps[17];

    char result[7];
    generateTOTP(seed32, unix_time, 6, T0, X, result);
    printf("TOTP: %s\n\n", result);

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
                printf("");
                printf("\033[A\33[2K\r Remaining time: %d seconds\n", (int)round(time_step - time_spent));
                last_time = time_spent;
            }
        } while ((time_spent < time_step) && keepRunning);
        // Generate a new TOTP, and continue.
        strcpy(steps, "");
        strcpy(result, "");
        generateTOTP(seed32, unix_time, 6, T0, X, result);
        time_spent = 0.0;
    }
    puts("\nStopped by signal `SIGINT'");
    return EXIT_SUCCESS;
}