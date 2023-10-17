#include <stdio.h>        // Standard IO library header
#include <string.h>       // Provides functions to work with strings
#include <time.h>         // Provides functions to implement a unix timer.
#include <math.h>         // Provides mathematical functions (e.g round)
#include <openssl/evp.h>  // Header for the OpenSSL EVP library (used for generating sha3-512 hash)
#include <openssl/hmac.h> // Header for the OpenSSL HMAC library (used for generating HMAC value)
#include <signal.h>       // Header for handling input signals such as SIGINT.
#include <stdlib.h>       // Standard library header for memory allocation
#include <ctype.h>        // Standard library header for character type checking (e.g isdigit, isalpha)

// Error definitions
#define ERROR_OTP_WRONG_LENGTH 1        // Output OTP is at wrong length (should be 6)
#define ERROR_OTP_INPUT_WRONG_LENGTH 2  // Input TOTP to verify is provided with a wrong length (should be 6)
#define ERROR_WRONG_ARGUMENT 3          // The argument given to the terminal is undefined, unknown or typed incorrectly
#define ERROR_MEMORY_ALLOCATION 4       // Memory allocation error when malloc() is called
#define ERROR_BYTE_ARRAY_CONVERSION 5   // Error occurred at converting hex string to byte array
#define ERROR_HMAC_RESULT_NULL 6        // Result of the HMAC was null
#define ERROR_TIME_HEX_WRONG_FORMAT 7   // The unix time to hex string conversion did not output 16-digit long string.
#define ERROR_OTP_INPUT_NOT_ALL_DIGIT 8 // Input TOTP to verify is provided with a wrong format (should be all digits)

// Forward declarations
void killTheProgram(int exitCode);
unsigned char *getHMAC(const void *key, size_t keylen, const unsigned char *data, size_t msglen,
                       unsigned char *result, unsigned int *resultlen);
unsigned char *hmac_result(unsigned char *key, const unsigned char *msg, size_t keylen, size_t msglen);
void longToHex(time_t unix_time, int64_t T0, int64_t X, char *steps);
void hexToByteArray(const char *hex, unsigned char *val);
void verifyTOTP(char *key, int64_t T0, int64_t X, char *totp);
void generateTOTP(char *key, time_t time, int codeDigits, int64_t T0, int64_t X, char result[7]);
void test();
void catchSignal();
void argHandler(int argc, char **argv, char *secret);
void totpLoop(char *secret, double time_step);
void UIMessages();

/// Constant or predefined variable declarations
static int DIGITS_POWER[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
static volatile sig_atomic_t keepRunning = 1;
int64_t T0 = 0;
int64_t X = 30;

/// @brief Kills the process if encountered with an error.
/// @param exitCode
void killTheProgram(int exitCode)
{
    switch (exitCode)
    {
    case ERROR_OTP_WRONG_LENGTH:
        printf("\033[31mThe output otp is at wrong length\033[0m\n");
        break;
    case ERROR_OTP_INPUT_WRONG_LENGTH:
        printf("\033[31mThe input otp is at wrong length\033[0m\n");
        UIMessages();
        break;
    case ERROR_WRONG_ARGUMENT:
        printf("\033[31mWrong arguments are given to the terminal. To generate a totp, please run the code without arguments.\033[0m\n");
        UIMessages();
        break;
    case ERROR_MEMORY_ALLOCATION:
        printf("\033[31mMemory allocation failure.\033[0m\n");
        break;
    case ERROR_BYTE_ARRAY_CONVERSION:
        printf("\033[31mHex string to byte array failure.\033[0m\n");
        break;
    case ERROR_HMAC_RESULT_NULL:
        printf("\033[31mHMAC result is null\033[0m\n");
        break;
    case ERROR_TIME_HEX_WRONG_FORMAT:
        printf("\033[31mTime long to hex value output was at the wrong format.\033[0m\n");
        break;
    case ERROR_OTP_INPUT_NOT_ALL_DIGIT:
        printf("\033[31mThe input otp contains invalid (non-digit) values.\033[0m\n");
        UIMessages();
        break;

    default:
        break;
    }

    exit(EXIT_FAILURE);
}

/// @brief stops the program if encountered with a SIGINT signal.
/// @param _
static void sig_handler(int _)
{
    (void)_;
    keepRunning = 0;
}
/// @brief HMAC calculation using EVP api. I used sha3-512 since I found it more secure than standard sha2-256.
/// @param key byte array version of the shared secret key
/// @param keylen
/// @param msg byte array version of the formatted T value.
/// @param msglen
/// @param result HMAC result
/// @param resultlen HMAC result length
/// @return hash value of HMAC algorithm.
unsigned char *getHMAC(const void *key, size_t keylen,
                       const unsigned char *msg, size_t msglen,
                       unsigned char *result, unsigned int *resultlen)
{
    return HMAC(EVP_sha3_512(), key, keylen, msg, msglen, result, resultlen);
}

// TODO: Error Handling

/// @brief
/// @param key byte array version of the shared secret key
/// @param msg byte array version of the formatted T value.
/// @param keylen
/// @param msglen
/// @return hash value of HMAC algorithm. 64 bytes for HMAC-sha512, 32 bytes for HMAC-sha256
unsigned char *hmac_result(unsigned char *key, const unsigned char *msg, size_t keylen, size_t msglen)
{
    unsigned char *result = NULL;
    unsigned int resultlen = -1;

    result = getHMAC((const void *)key, keylen, msg, msglen, result, &resultlen);
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
    if (strlen(steps) != 16)
    {
        killTheProgram(ERROR_TIME_HEX_WRONG_FORMAT);
    }
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
/// The reason I accept backward time-step is that the user have to open up new terminal or restart the terminal
/// to verify their totp, which could be time consuming.
/// @param key shared secret key
/// @param T0 is the Unix time to start counting time steps
/// @param X represents the time step in seconds
/// @param totp user input to verify time-based one time password.
void verifyTOTP(char *key, int64_t T0, int64_t X, char *totp)
{
    if (strlen(totp) != 6)
    {
        killTheProgram(ERROR_OTP_INPUT_WRONG_LENGTH);
    }
    for (int i = 0; i < 6; ++i)
    {
        if (!isdigit(totp[i]))
        {
            killTheProgram(ERROR_OTP_INPUT_NOT_ALL_DIGIT);
        }
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

/// @brief Generates totp value by combining the byte arrays of key and time to generate a hash value using hmac algorithm.
/// This hash value is then
/// @param key shared secret key
/// @param time standart unix time (in seconds) from 01-01-1970 00.00.00
/// @param codeDigits indicates how many digits a TOTP value should have. This assignment requires this value
/// to be 6. Thus, everywhere else in this code accepts the codeDigits = 6.
/// @param T0 is the Unix time to start counting time steps
/// @param X represents the time step in seconds
/// @param result time based one time password (TOTP)
void generateTOTP(char *key,
                  time_t time,
                  int codeDigits, int64_t T0, int64_t X,
                  char result[7])
{
    char steps[17];                                       // This steps replaces the 'time' variable from the paper
    longToHex(time, T0, X, steps);                        // T value to 16-digit long zero-padded hex string
    size_t msglen = ((strlen(steps) + 1) / 2);            // Could be +1 not sure.
    unsigned char *msg = (unsigned char *)malloc(msglen); // Byte array version of the formatted T value.

    size_t keylen = ((strlen(key) + 1) / 2);
    unsigned char *k = (unsigned char *)malloc(keylen); // Byte array version of the key value.
    if (msg == NULL || k == NULL)
    {
        killTheProgram(ERROR_MEMORY_ALLOCATION);
    }

    hexToByteArray(steps, msg);
    hexToByteArray(key, k);
    if (k == NULL || msg == NULL)
    {
        killTheProgram(ERROR_BYTE_ARRAY_CONVERSION);
    }
    const unsigned char *hash = hmac_result(k, msg, keylen, msglen); // Calculated HMAC

    if (hash == NULL)
    {
        killTheProgram(ERROR_HMAC_RESULT_NULL);
    }

    // Same variable calculations with RFC6238 algorithm
    // 0xf is hex rep of 0000 1111. This calculation simply gets the last character (or the last byte)
    // of this hash value and further gets the 4 least significant bits.
    // The goal here is to provide pseudo-randomness.
    int offset = hash[strlen(hash) - 1] & 0xf;
    int binary =
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);
    int otp = binary % DIGITS_POWER[codeDigits];
    snprintf(result, 7, "%06d", otp); // Zero-pad the otp since the 'int' variable will discard the leading zero digits.
    if (strlen(result) != 6)
    {
        killTheProgram(ERROR_OTP_WRONG_LENGTH); // Kill the process if totp result is not 6-digit.
    }
    free(msg); // Freeing the memory allocations to prevent data leakage.
    free(k);
    msg = NULL;
    k = NULL;
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
void argHandler(int argc, char **argv, char *secret)
{
    if (strcmp(argv[1], "test") == 0)
    {
        test();
    }
    else if (strcmp(argv[1], "verify") == 0)
    {
        // argv[2] should be totp value.
        if (argv[2] == NULL)
        {
            killTheProgram(ERROR_WRONG_ARGUMENT);
        }
        if (argc > 3)
        {
            char *userProvidedKey = argv[2];
            verifyTOTP(userProvidedKey, T0, X, argv[3]);
        }
        else
            verifyTOTP(secret, T0, X, argv[2]);
    }
    else if (strcmp(argv[1], "key") == 0)
    {
        // argv[2] should be a key value.
        if (argv[2] == NULL)
        {
            killTheProgram(ERROR_WRONG_ARGUMENT);
        }
        char *userProvidedKey = argv[2];
        UIMessages();
        double time_step = (double)X;
        totpLoop(userProvidedKey, time_step);
    }
    else if (strcmp(argv[1], "help") == 0)
    {
        UIMessages();
    }
    else
    {
        killTheProgram(ERROR_WRONG_ARGUMENT);
    }
}

/// @brief While this loop keeps running, continue to display and generate totp values every 30 seconds.
/// @param secret shared secret key
/// @param time_step represents the time step in seconds, data type is double instead of long to keep track of the time.
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
            time_spent = (double)difftime(currentTime, start); // Get unix time difference.
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
        time(&currentTime); // Take the current time again and start over in the 30 seconds.
        time_spent = 0.0;
        last_time = 0.0;
    }
}
/// @brief Printing program capabilities to the terminal.
void UIMessages()
{
    printf("To stop the program use SIGINT signal in terminal (ctrl + c)\n");
    printf("To generate a TOTP using the default key, simply run: './totp'\n");
    printf("To use the test values provided in the paper run the code with argument 'test' (e.g ./totp test)\n");
    printf("To verify the totp value run the code with the argument 'verify' (e.g ./totp verify 635533)\n");
    printf("To generate a totp with a your custom key please run the code with argument 'key [your key]' (e.g ./totp key 12345677890)\n");
    printf("If you used a custom key, use 'verify [your key] [your totp]' (e.g ./totp verify 12345677890 612211)\n\n");
}
int main(int argc, char **argv)
{
    catchSignal(); // Stop the program with ctrl + c input.
    // Seed for HMAC-SHA512 - 64 bytes, gathered from the paper.
    char *secret = "313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930";

    if (argc > 1)
    {
        argHandler(argc, argv, secret);
    }
    else
    {
        UIMessages();
        double time_step = (double)X;
        totpLoop(secret, time_step);
        puts("\nStopped by signal `SIGINT'");
    }
    return EXIT_SUCCESS;
}