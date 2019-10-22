#include <stdio.h>
#include <string.h>
#include <iostream>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <random>
#include <bitset>


// error codes
#define OK 0
#define ERR_ARGUMENTS 1
#define ERR_ARGUMENTS_MISSING_REQUIRED 2
#define ERR_ARGUMENTS_SERVER 3


struct IP46
{
    std::string ipv4;
    std::string ipv6;
    bool v6;            // true = ipv6 exists, false = only ipv4
};




void err(int err_code);
void sendQuery(std::string domain, IP46 server, std::string Port, bool FlagR, bool FlagX, bool Flag6);
std::string createHeader(std::string domain, IP46 server, std::string Port, bool FlagR, bool FlagX, bool Flag6);

IP46 lookup_host (const char *host);