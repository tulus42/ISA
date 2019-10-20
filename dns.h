#include <stdio.h>
#include <string.h>
#include <iostream>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>


// error codes
#define OK 0
#define ERR_ARGUMENTS 1


struct IP46
{
    std::string ipv4;
    std::string ipv6;
};




void err(int err_code);

IP46 lookup_host (const char *host);