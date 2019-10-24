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
#include <regex>
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <sys/types.h> 


// error codes
#define OK 0
#define ERR_ARGUMENTS 1
#define ERR_ARGUMENTS_MISSING_REQUIRED 2
#define ERR_ARGUMENTS_SERVER 3
#define ERR_SOCKET 4


struct IP46
{
    std::string ipv4;
    std::string ipv6;
    bool v4;
    bool v6;            
    
};


class bufferClass;
class Arguments;
class Header;
class Question;

void err(int err_code);
void sendQuery(bufferClass* buffer, std::string domain, IP46 server, short Port, bool FlagR, bool FlagX, bool Flag6);
std::string createHeader(bool FlagR);
std::string createQuestion(std::string Domain, bool Flag6);

IP46 lookup_host (const char *host);