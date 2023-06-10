// File: pwcheck.c
// Subject: IZP
// Project: #1
// Author: Andrii Klymenko, FIT VUT
// Login: xklyme00
// Date: 10.6.2023

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_PASSWORD_LENGTH 100
#define MAX_PASSWORD_BUFFER_LENGTH MAX_PASSWORD_LENGTH + 2 // + '\n' + '\0' == +2

// suppress compiler warnings about unused function parameter
#define UNUSED(x) (void)(x)

// structure that represents arguments "-l LEVEL", "-p PARAM" and "--stats"
typedef struct {
    char *key; // name of the switch ("-l", "-p", "--stats")
    bool has_value; // has argument value or not
    int value; // argument value
    int min_value; // maximum argument value
    int max_value; // minimum argument value
    char *err_msg; // error message in case when argument is invalid
} Argument_t;

// structure that represents password statistics
typedef struct {
    int min_length; // length of the shortest password
    bool used_chars[128]; // array representing ascii table
    int total_length; // length of all passwords
    int password_cnt; // number of passwords
} Stats_t;

// returns false if value of string is not an integer, otherwise returns true and checks if this integer is greater
// than maximum password length. if so, it assigns to "*num" value of maximum password length, because there is
// no sense of keeping integer greater than it is
bool isNumber(char *str, int *num)
{
    char *end;
    long tmp = strtol(str, &end, 10);

    if(end == str || *end != '\0')
        return false;

    if(tmp > MAX_PASSWORD_LENGTH)
        tmp = MAX_PASSWORD_LENGTH;

    *num = (int) tmp;
    return true;
}

// compares two strings. returns 0 if strings are equal, positive number if first string is
// lexicographically greater than the second string and negative number if second string is
// lexicographically greater than the first string
int myStrcmp(char *str1, char *str2)
{
    int i;
    for(i = 0; str1[i] != '\0'; i++)
    {
        if(str1[i] != str2[i])
            break;
    }

    return (str1[i] - str2[i]);
}

// returns -1 if the password contains more than 100 characters, otherwise it returns its length
int isValidLength(char *password)
{
    int length = 0;
    for(int i = 0; i < MAX_PASSWORD_LENGTH + 1; i++)
    {
        if(password[i] == '\0')
            return length;

        // skip '\r' character
        if(password[i] == '\r')
        {
            length--;
            for(int j = i; password[j] != '\n'; j++)
                password[j] = password[j + 1];
        }

        // the end of the password is found (fgets puts '\n' at the end of the password)
        if(password[i] == '\n')
        {
            // '\n' is not part of the password, sot put '\0' instead of it (end the string)
            password[i] = '\0';
            return length;
        }

        length++;
    }

    return -1;
}

// check if character is uppercase
bool isUpperCase(char a)
{
    return (a >= 'A' && a <= 'Z');
}

// check if character is lowercase
bool isLowerCase(char a)
{
    return (a >= 'a' && a <= 'z');
}

// check if character is digit
bool isDigit(char a)
{
    return (a >= '0' && a <= '9');
}

// check if character is special (i.e. it is not uppercase, lowercase digit
// and its value is from interval <32, 126)
bool isSpecialChar(char a)
{
    return (!(isLowerCase(a) || isUpperCase(a) || isDigit(a)) && (a >= 32 && a <= 126));
}

// check if the password meets the first level of security
bool isFirstLevel(char *password, int x)
{
    // suppress compiler warnings about unused function parameter
    // it was needed to make an array of pointers to functions with parameters "char *" and "int"
    UNUSED(x);

    // were in the password uppercase and lowercase characters?
    bool isUpper = false;
    bool isLower = false;

    for(int i = 0; password[i] != '\0'; i++)
    {
        if(!isUpper && isUpperCase(password[i]))
            isUpper = true;
        else if(!isLower && isLowerCase(password[i]))
            isLower = true;

        if(isUpper && isLower)
            return true;
    }

    return false;
}

// update an array of characters that were used in passwords
void updateUsedChars(char *password, bool used_chars[])
{
    for(int i = 0; password[i] != '\0'; i++)
        if(!(used_chars[(int) password[i]]))
            used_chars[(int) password[i]] = true;
}

// update password statistic
void updateStats(char *password, Stats_t *stats)
{
    updateUsedChars(password, stats->used_chars);
    stats->total_length += isValidLength(password);
    if(isValidLength(password) < stats->min_length)
        stats->min_length = isValidLength(password);

    stats->password_cnt++;
}

// check if the password meets the second level of security
bool isSecondLevel(char *password, int param)
{
    if(param > 4)
        param = 4;

    // number of groups of characters that password has
    int group_cnt = 0;

    // array of groups (lowercase, uppercase, digit, special character)
    bool groups[4] = {false, };

    // "f" is a pointer to function with parameter "char" that returns a value of type "bool"
    typedef bool (*f)(char);

    // "checks" is an array of pointers to functions
    f checks[] = {isLowerCase, isUpperCase, isDigit, isSpecialChar};

    // loop through entire password
    for(int i = 0; password[i] != '\0'; i++)
    {
        // check if password character belongs to any group
        for(int j = 0; j < 4; j++)
        {
            if(!groups[j] && checks[j](password[i]))
            {
                groups[j] = true;
                group_cnt++;

                if(group_cnt >= param)
                    return true;

                break;
            }
        }
    }

    return false;
}

// returns number of different chars that were used in all passwords
int differentChars(bool *used_chars)
{
    int diff_cnt = 0;

    for(int i = 0; i < 128; i++)
        if(used_chars[i])
            diff_cnt++;

    return diff_cnt;
}

// check if the password meets the second level of security
bool isThirdLevel(char *password, int param)
{
    int sequence_len = 1;
    char current_char = '\0';

    for(int i = 0; password[i] != '\0'; i++)
    {
        if(password[i] == current_char)
            sequence_len++;
        else
        {
            current_char = password[i];
            sequence_len = 1;
        }

        if(sequence_len >= param)
            return false;
    }

    return true;
}

// check if the password meets the fourth level of security
bool isFourthLevel(char *password, int param)
{
    for(int i = 0; password[i] != '\0'; i++)
    {
        for(int j = i + 1; password[j] != '\0'; j++)
        {
            // are substrings equal?
            bool isSubstrEqual = true;

            // try to find equal substrings with length "param". if this happens return false
            for(int k = 0; k < param; k++)
            {
                if(password[i + k] == '\0' || password[j + k] == '\0' || password[i + k] != password[j + k])
                {
                    isSubstrEqual = false;
                    break;
                }
            }
            if(isSubstrEqual)
                return false;
        }
    }

    return true;
}

// parse programs arguments considering the situation when there are no switches "-l", "-p", "--stats",
// i.e. arguments are on fixed positions
bool parseFixedArguments(int argc, char *argv[], Argument_t arguments[])
{
    // program must have 2 arguments, and can have 4 arguments
    if(argc < 3 || argc > 4)
    {
        fprintf(stderr, "Error! Invalid number of arguments\n");
        return false;
    }

    // loop through all program arguments except program name
    for(int i = 1; i < argc; i++)
    {
        // check if switch can have any value (i.e. is not "--stats")
        if(arguments[i - 1].has_value)
        {
            // check if the switch has a value, if it is a positive integer,
            // and it is in the range of the minimum and maximum allowed value
            if(!isNumber(argv[i], &arguments[i - 1].value) ||
               arguments[i - 1].value < arguments[i - 1].min_value || arguments[i - 1].value > arguments[i - 1].max_value)
            {
                fprintf(stderr, "%s\n", arguments[i - 1].err_msg);
                return false;
            }
        }
        else
        {   // display that "--stats" switch was used
            if(myStrcmp(argv[i], arguments[i - 1].key) == 0)
                arguments[i - 1].value = 1;
            else
            {
                fprintf(stderr, "Error! Invalid program's argument: '%s'\n", argv[i]);
                return false;
            }
        }
    }

    return true;
}

// parse programs arguments considering the situation when there can be switches "-l", "-p", "--stats",
// i.e. arguments are not on fixed positions
bool parseArguments(int argc, char *argv[], Argument_t arguments[])
{
    // loop through all program arguments except program name
    for(int i = 1; i < argc; i++)
    {
        // did we meet switch "-p", "-l" or "--stats"
        bool key_found = false;

        // loop through arguments array ("-p", "-l" and "--stats" switches)
        for(int j = 0; j < 3; j++)
        {
            // found switch "-p", "-l" or "--stats"
            if(myStrcmp(argv[i], arguments[j].key) == 0)
            {
                key_found = true;

                // check if the switch is being used for the first time
                if(arguments[j].value == -1)
                {
                    // check if switch can have any value (i.e. is not "--stats")
                    if(arguments[j].has_value)
                    {

                        // check if the switch has a value, if it is a positive integer,
                        // and it is in the range of the minimum and maximum allowed value
                        if(i + 1 >= argc || !isNumber(argv[i + 1], &arguments[j].value) ||
                           arguments[j].value < arguments[j].min_value || arguments[j].value > arguments[j].max_value)
                        {
                            fprintf(stderr, "%s\n", arguments[j].err_msg);
                            return false;
                        }

                        // argument was successfully parsed => skip its value and move to the next one
                        i++;
                    }
                    else // display that "--stats" switch was used
                        arguments[j].value = 1;
                }
                else
                {
                    fprintf(stderr, "Error! Switch '%s' was entered twice\n", arguments[j].key);
                    return false;
                }
            }
        }

        // if argument is none of the following: "-p", "-l", "--stats"
        if(!key_found)
        {

            // if this is the first argument of the program, it can potentially be run correctly with fixed arguments
            if(i == 1)
                return parseFixedArguments(argc, argv, arguments);

            fprintf(stderr, "Error! Invalid program's argument: '%s'\n", argv[i]);
            return false;
        }
    }

    // if there weren't switches "-p" or "-l" as programs arguments, assign them a default value

    if(arguments[0].value == -1)
        arguments[0].value = 1;

    if(arguments[1].value == -1)
        arguments[1].value = 1;

    return true;
}

// print statistics of the passwords
void printStats(Stats_t stats)
{
    // can password cnt be 0?
    printf("Statistika:\n"
           "Ruznych znaku: %d\n"
           "Minimalni delka: %d\n"
           "Prumerna delka: %.1lf\n", differentChars(stats.used_chars), stats.min_length, (double) stats.total_length / stats.password_cnt);
}

// check if the password corresponds to the desired security level with the additional parameter
bool isPasswordSecure(char *password, int level, int param)
{
    // f is a pointer to a function with parameters "char *" and "int", which returns a value of the "bool" type
    typedef bool (*f)(char *, int);

    // array of functions that check security level
    f levels[] = {isFirstLevel, isSecondLevel, isThirdLevel, isFourthLevel};

    // loop through levels from first to the desired
    for(int i = 0; i < level; i++)
    {
        // levels[i](password, param) => in this way the function that has index "i" in the array "levels" is called
        // with arguments "password" and "param"
        if(!levels[i](password, param))
            return false;
    }

    return true;
}

// read all the passwords from stdin until EOF is reached or some password has invalid length
bool processPasswords(int level, int param, Stats_t *stats, int is_stats)
{
    char password[MAX_PASSWORD_BUFFER_LENGTH];

    while((fgets(password, MAX_PASSWORD_BUFFER_LENGTH, stdin)) != NULL)
    {
        if(isValidLength(password) == -1)
        {
            fprintf(stderr, "Error! Too long password: has more than 100 characters\n");
            return false;
        }

        if(isPasswordSecure(password, level, param))
            printf("%s\n", password);

        if(is_stats == 1)
            updateStats(password, stats);
    }

    return true;
}

int main(int argc, char *argv[])
{
    Argument_t arguments[3] = {

                // LEVEL
            {.key = "-l", .has_value = true, .value = -1, .min_value = 1, .max_value = 4,
                 .err_msg = "Error! 'LEVEL' argument must be a positive integer from interval <1, 4>\n"},

                 // PARAM
            {.key = "-p", .has_value = true, .value = -1, .min_value = 1, .max_value = MAX_PASSWORD_LENGTH,
                 .err_msg = "Error! 'PARAM' argument must be a positive integer\n"},

                 // STATS
            {.key = "--stats", .has_value = false, .value = -1, .min_value = 1, .max_value = 1, .err_msg = ""}
    };

    if(!parseArguments(argc, argv, arguments))
        return -1;

    // assigning switch values to variables after parsing
    int level = arguments[0].value;
    int param = arguments[1].value;

    Stats_t stats = {.min_length = 101, .used_chars = {false, }, .total_length = 0, .password_cnt = 0};

    if(!processPasswords(level, param, &stats, arguments[2].value))
        return -1;

    if(arguments[2].value == 1)
        printStats(stats);

    return 0;
}