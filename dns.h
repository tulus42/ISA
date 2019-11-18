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
#include <poll.h>


// error codes
#define OK 0
#define ERR_ARGUMENTS 1                     // Invalid argumetns
#define ERR_ARGUMENTS_MISSING_REQUIRED 2    // Missing required argument - Server or Address
#define ERR_ARGUMENTS_SERVER 3              // Invalid input Server name/ip address
#define ERR_SOCKET 4                        // Error in socket
#define ERR_RCVD_SOCKET 5                   // Error in received socket
#define ERR_INPUT_DOMAIN 6                  // Error in insertet domain
#define ERR_TIMEOUT 7
#define ERR_RCODE_1 11                      // format error - The name server was unable to interpret query
#define ERR_RCODE_2 12                      // server failure - The name server was unable to process this query due to a problem with the name server
#define ERR_RCODE_3 13                      // name error - Domain name referenced in the query does not exist
#define ERR_RCODE_4 14                      // not implemented - The name server does not support the requested kind of query
#define ERR_RCODE_5 15                      // refused - The name server refused to perform the specified operation for policy reasons


//
#define MAXLINE 512

enum DNSType {
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULLdns,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    AAAA,
    unknown
};

struct IP46 {
    std::string ipv4;
    std::string ipv6;
    bool v4;
    bool v6;            
    
};

struct DNSheaderParams {
    unsigned short QDCount;
    unsigned short ANCount;
    unsigned short NSCount;
    unsigned short ARCount;
};


class bufferClass;
class Arguments;
class Header;
class Question;

void err(int err_code);
void sendQuery(bufferClass* buffer, bufferClass* rcvBuffer, Arguments inputArgvs);
void parseAnswer(bufferClass* buffer, bufferClass* rcvBuffer, Arguments inputArgvs);
DNSheaderParams checkRcvdHeader(bufferClass* buffer, bufferClass* rcvBuffer, Arguments inputArgvs);
std::string createHeader(bool FlagR);
std::string createQuestion(std::string Domain, bool Flag6);

IP46 lookup_host (const char *host);