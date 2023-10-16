#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <signal.h>
#include <stdlib.h>

#define ERROR_OTP_WRONG_LENGTH 1
#define ERROR_OTP_INPUT_WRONG_LENGTH 2
#define ERROR_WRONG_ARGUMENT 3

// Forward declarations
unsigned char *hmac_sha256(const void *key, size_t keylen, const unsigned char *data, size_t msglen,
                           unsigned char *result, unsigned int *resultlen);
unsigned char *hmac_result(unsigned char *key, const unsigned char *msg, size_t keylen, size_t msglen);
void longToHex(time_t unix_time, int64_t T0, int64_t X, char *steps);
void hexToByteArray(const char *hex, unsigned char *val);
void verifyTOTP(char *key, int64_t T0, int64_t X, char *totp);
void generateTOTP(char *key, time_t time, int codeDigits, int64_t T0, int64_t X,
                  char result[7]);
void test();
void catchSignal();
void argHandler(char **argv, char *secret);
void totpLoop(char *secret, double time_step);

/// Constant or predefined variable declarations
static int DIGITS_POWER[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
static volatile sig_atomic_t keepRunning = 1;
int64_t T0 = 0;
int64_t X = 30;

int killTheProgram(int exitCode)
{
    switch (exitCode)
    {
    case ERROR_OTP_WRONG_LENGTH:
        printf("The output otp is at wrong length");
        break;
    case ERROR_OTP_INPUT_WRONG_LENGTH:
        printf("The input otp is at wrong length");
        break;
    case ERROR_WRONG_ARGUMENT:
        printf("Wrong arguments are given to the terminal. To generate a totp, please run the code without arguments.\n");
        printf("To look at test cases use argument 'test'. To verify your totp code, please use 'verify [your totp code]' e.g verify 603303");
        break;

    default:
        break;
    }

    exit(EXIT_FAILURE);
}

/// @brief
/// @param _
static void sig_handler(int _)
{
    (void)_;
    keepRunning = 0;
}
/// @brief hmac_sha256 calculation using EVP api
/// @param key byte array version of the shared secret key
/// @param keylen
/// @param msg byte array version of the formatted T value.
/// @param msglen
/// @param result
/// @param resultlen
/// @return
unsigned char *hmac_sha256(const void *key, size_t keylen,
                           const unsigned char *msg, size_t msglen,
                           unsigned char *result, unsigned int *resultlen)
{
    return HMAC(EVP_sha256(), key, keylen, msg, msglen, result, resultlen);
}

// TODO: Error Handling

/// @brief
/// @param key byte array version of the shared secret key
/// @param msg byte array version of the formatted T value.
/// @param keylen
/// @param msglen
/// @return
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
/// @brief Converts long value T to hex string. Applies left zero-padding to fill 16 bytes.
/// T is an integer and represents the number of time steps between the initial counter
//  time T0 and the current Unix time.
/// @param unix_time standart unix time (in seconds) from 01-01-1970 00.00.00
/// @param T0 is the Unix time to start counting time steps
/// @param X represents the time step in seconds
/// @var T is an integer and represents the number of time steps between the initial counter
//  time T0 and the current Unix time.
/// @param steps is the address of the 16 digit-long zero-padded (if necessary) T value.
void longToHex(time_t unix_time, int64_t T0, int64_t X, char *steps)
{
    int64_t T = (unix_time - T0) / X;
    // zero-padding to fill 16 bytes, convert from long to hexadecimal.
    snprintf(steps, 17, "%016lX", T);
    // printf("Hexadecimal string: %s\n", steps);
}

/// @brief Converts hex value to byte array in the same way the rfc6238 algorithm does.
/// @param hex Hex value to be converted to byte array. This can be msg or key hex values.
/// @return byte array
/// I benefited from the below stackoverflow post, since I was not sure how to write hex to byte array code in c.
/// https://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c
void hexToByteArray(const char *hex, unsigned char *val)
{
    const char *pos = hex;
    size_t length = strlen(hex) / 2;

    for (size_t count = 0; count < length; count++)
    {
        sscanf(pos, "%02hhx", &val[count]);
        pos += 2;
    }
}

/// @brief Verify the given totp value with either current or previous value.
/// I decided to include one time-step backward with the following advice from the paper on mind.
/// "We recommend that the validator be set with a specific limit to the number of time steps a prover can be
/// "out of synch" before being rejected."
/// The reason I accept backward time-step is that the user have to open up new terminal or to verify.
/// @param key shared secret key
/// @param T0 is the Unix time to start counting time steps
/// @param X represents the time step in seconds
/// @param totp user input to verify time-based one time password.
void verifyTOTP(char *key, int64_t T0, int64_t X, char *totp)
{
    if (strlen(totp) != 6)
    {
        killTheProgram(ERROR_OTP_WRONG_LENGTH);
    }
    time_t currentTime;
    time(&currentTime);
    time_t previous_time_step = currentTime - X;
    char result[7];
    char previous_result[7];
    generateTOTP(key, previous_time_step, 6, T0, X, previous_result);
    generateTOTP(key, currentTime, 6, T0, X, result);
    if (strcmp(totp, result) == 0 || strcmp(totp, previous_result) == 0)
    {
        printf("TOTP Verified");
    }
    else
    {
        printf("Wrong TOTP");
    }
}

/// @brief
/// @param key shared secret key
/// @param time standart unix time (in seconds) from 01-01-1970 00.00.00
/// @param codeDigits indicates how many digits a TOTP value should have. This assignment requires this value
/// to be 6. Thus, everywhere else in this code accepts the codeDigits = 6.
/// @param T0 is the Unix time to start counting time steps
/// @param X represents the time step in seconds
/// @param result
void generateTOTP(char *key,
                  time_t time,
                  int codeDigits, int64_t T0, int64_t X,
                  char result[7])
{
    char steps[17];                                       // This steps replaces the 'time' variable from the paper
    longToHex(time, T0, X, steps);                        // T value to 16-digit long zero-padded hex string
    size_t msglen = ((strlen(steps) + 1) / 2);            // Could be +1 not sure.
    unsigned char *msg = (unsigned char *)malloc(msglen); // Byte array version of the formatted T value.
    hexToByteArray(steps, msg);
    // for (size_t i = 0; i < (strlen(steps) + 3) / 2; i++)
    // {
    //     printf("msg: %02x ", msg[i]);
    // }

    size_t keylen = ((strlen(key) + 1) / 2);
    unsigned char *k = (unsigned char *)malloc(keylen); // Byte array version of the key value.
    hexToByteArray(key, k);
    const unsigned char *hash = hmac_result(k, msg, keylen, msglen); // Calculated HMAC
    // if (hash < 0)
    // {
    //     killTheProgram();
    // }
    // put selected bytes into result int
    int offset = hash[strlen(hash) - 1] & 0xf; // Same variable calculations with RFC6238 algorithm
    int binary =
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);
    int otp = binary % DIGITS_POWER[codeDigits];
    snprintf(result, 7, "%06d", otp); // Zero-pad the otp if it is missing 6 digits.
    if (strlen(result) != 6)
    {
        killTheProgram(ERROR_OTP_WRONG_LENGTH); // Kill the process if totp result is not 6-digit.
    }
    free(msg); // Freeing the memory allocations to prevent data leakage.
    free(k);
}

/// @brief Test with the values given in the last page of rfc6238 paper.
void test()
{
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
/// @brief Console argument handler. Two arguments types: test or verify.
/// "test" is for testing the predefined values with constant secret and testTimes.
/// "verify" takes one more argument: the TOTP from the user to verify their one time password.
/// @param argv
/// @param secret shared key secret
void argHandler(char **argv, char *secret)
{
    if (strcmp(argv[1], "test") == 0)
    {
        test();
    }
    else if (strcmp(argv[1], "verify") == 0)
    {
        // argv[2] should be totp value.
        // TODO: Do error handling. If the totp is not 6-length etc.
        if (argv[2] == NULL)
        {
            killTheProgram(ERROR_WRONG_ARGUMENT);
        }
        verifyTOTP(secret, T0, X, argv[2]);
    }
    else
    {
        killTheProgram(ERROR_WRONG_ARGUMENT);
    }
}
/// @brief
/// @param secret shared secret key
/// @param time_step
void totpLoop(char *secret, double time_step)
{
    double time_spent;
    double last_time = 0.0;
    char result[7];

    time_t start;
    time_t currentTime;

    time(&start);
    time(&currentTime);

    while (keepRunning)
    {
        time(&start);
        generateTOTP(secret, currentTime, 6, T0, X, result);
        do
        {
            time(&currentTime);
            /* Get CPU time since loop started */
            time_spent = (double)difftime(currentTime, start);
            if (time_spent - last_time >= 1.0)
            {
                // Clean the console and write the new remaining value.
                // \033[A: Move the cursor up one line
                // \33[2K: Clear the current line.
                // \r: Move the cursor to the beginning of the line.
                printf("\033[A\33[2K\r Remaining time: %d seconds\t Your TOTP:%s\n", (int)round(time_step - time_spent), result);
                last_time = time_spent;
            }
        } while ((time_spent < time_step) && keepRunning);
        strcpy(result, "");
        time(&currentTime);
        // printf("Current Time: %ld", currentTime);
        time_spent = 0.0;
        last_time = 0.0;
    }
}

int main(int argc, char **argv)
{
    catchSignal();
    char *secret = "12345678901234567890";

    if (argc > 1)
    {
        argHandler(argv, secret);
    }
    else
    {
        double time_step = 30.0;
        totpLoop(secret, time_step);
        puts("\nStopped by signal `SIGINT'");
    }
    return EXIT_SUCCESS;
}