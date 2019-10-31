#include "dns.h"

class bufferClass {
public:
    unsigned char buffer[512];
    unsigned char* endOfBuffer = &buffer[0];
    
    bufferClass() {
        for (int i = 0; i < 256; i++) {
            buffer[i] = 0;
        }
    }

    void addCh(char val) {
        *endOfBuffer++ = val;
    }

    void addS(char* val) {
        for (unsigned int i = 0; i < strlen(val); i++) {
            *endOfBuffer++ = val[i];
        }
    }

    void addShort(short val) {
        short * ptrBuffer = (short*)endOfBuffer;
        *ptrBuffer = htons(val);
        endOfBuffer += 2;
    }

    unsigned short readID() {
        unsigned short* res = (unsigned short*)buffer;
        return *res;
    }

    unsigned short readShort(unsigned char** ptr) {
        unsigned short* res = (unsigned short*)*ptr;
        *ptr += 2;
        return ntohs(*res);
    }

    std::string readAddress(unsigned char** BuffPtr) {
        std::string res = "";
                
        while (**BuffPtr != 0) {
            // if compression by ptr
            if ((0xc0 & (int)**BuffPtr) == 0xc0) {
                **BuffPtr = 0x3f & (int)**BuffPtr;
                unsigned short* compressionOffset = (unsigned short*)*BuffPtr;
                *compressionOffset = ntohs(*compressionOffset);

                unsigned char* tmpPtr = &(this->buffer[*compressionOffset]);
                res += this->readAddress(&tmpPtr);

                *BuffPtr += 2;
                return(res);
                
            // if no compression
            } else {
                int subdomainCnt = (int)**BuffPtr;
                *BuffPtr += 1;
                for (int i = 0; i < subdomainCnt; i++) {
                    res += **BuffPtr;
                    *BuffPtr += 1;
                }
                res += '.';
            }     
        }
        *BuffPtr += 1;  
        return(res);
    }

    std::string readIP(unsigned char** BuffPtr, int ipV) {
        if (ipV == 4) {
            
            for (int i = 0; i < 4; i++) {
                
            }
            return("");


            
        } else
        
        if (ipV == 6) {
            return("");

        } else {
            err(ERR_RCVD_SOCKET);
            return("");
        }
    }
};



class Arguments {
public:
    bool optR = false;
    bool optX = false;
    bool opt6 = false;
    bool optP = false;
    short optPortValue = 53;
    bool optS = false;
    IP46 optServerIP;
    bool optA = false;
    std::string optAddressValue;


    void handle_arguments(int argc, char** argv) {
        if (argc > 9)
            err(ERR_ARGUMENTS);

        // main cycle for checking if arguments are valid
        for (int i = 1; i < argc; i++) {
            // -r
            if (std::string(argv[i]) == "-r") {
                if (optR == false)
                    optR = true;
                else
                    err(ERR_ARGUMENTS);
                
                std::cout << "Recurion desired \n";
            }        

            // -x
            else if (std::string(argv[i]) == "-x") {
                if (optX == false)
                    optX = true;
                else
                    err(ERR_ARGUMENTS);

                std::cout << "Reverse ON\n";
            } 

            // -6
            else if (std::string(argv[i]) == "-6") {
                if (opt6 == false)
                    opt6 = true;
                else
                    err(ERR_ARGUMENTS);

                std::cout << "IPv6 - AAAA \n";
            } 

            // -p   PORT
            else if (std::string(argv[i]) == "-p") {
                if (optP == false)
                    optP = true;
                else
                    err(ERR_ARGUMENTS);

                i++;
                int iPort = std::stoi(argv[i]);

                // check validity of port
                if (std::to_string(iPort) != argv[i])
                    err(ERR_ARGUMENTS);
                if (iPort > 65535)
                    err(ERR_ARGUMENTS);

                std::cout << "Port: " << argv[i] << std::endl;

                optPortValue = (short)(std::stoi(argv[i]));
            } 

            // -s   SERVER
            else if (std::string(argv[i]) == "-s") {
                if (optS == false)
                    optS = true;
                else
                    err(ERR_ARGUMENTS_SERVER);

                i++;
                // check validity of server
                optServerIP = lookup_host(argv[i]);

                if (optServerIP.ipv4 == "" && optServerIP.ipv6 == "")
                    err(ERR_ARGUMENTS_SERVER);

                if (optServerIP.ipv6 != "")
                    optServerIP.v6 = true;
                else
                    optServerIP.v6 = false;
                

                std::cout << "IPv4: " << optServerIP.ipv4 << "\n";
                std::cout << "IPv6: " << optServerIP.ipv6 << "\n";                        
            } 

            // address
            else if (optA == false) {
                optA = true;
                optAddressValue = argv[i];
            }

            else {
                err(ERR_ARGUMENTS);
            }

        }

        if (optS == false || optA == false)
            err(ERR_ARGUMENTS_MISSING_REQUIRED);
    }
};


class Header {
public:
    unsigned short *dnsHeader;
    unsigned short headerID;

    Header(bufferClass* buffer) {
        // map header to buffer
        dnsHeader = (unsigned short*)&buffer[0];

        // generate ID
        srand((unsigned int)time(NULL));

        headerID = rand() % 65536;

        dnsHeader[0] = headerID;
        dnsHeader[1] = 0;
        dnsHeader[2] = htons(1);
        dnsHeader[3] = 0;
        dnsHeader[4] = 0;
        dnsHeader[5] = 0;

        buffer->endOfBuffer += 12;
    }

    void RFlag(bool flagR) {
        if (flagR)
            dnsHeader[1] = htons(0x0100);
    }
};


class Question {
public:
    Question(bufferClass* buffer, std::string domain) {
        std::regex re("([.])");
        std::sregex_iterator next(domain.begin(), domain.end(), re);
        std::sregex_iterator end;
        std::smatch match;

        char lengthOfSubdomain;
        std::string subdomainString;

        while (next != end) {
            match = *next;
            
            // 8 bit length of subdomain
            lengthOfSubdomain = match.prefix().length();
            buffer->addCh(lengthOfSubdomain);

            // subdomain to binary
            subdomainString = match.prefix();
            
            for (std::size_t i = 0; i < subdomainString.size(); ++i) {
                buffer->addCh(subdomainString[i]);

                std::cout << subdomainString[i] << ": " << std::bitset<8>(subdomainString[i]).to_string() << std::endl;
            }
            next++;
        } 

        // if domain not ends with "." 
        // -> handle last subdomain
        if (match.suffix() != "") {
            // 8 bit length of last subdomain
            lengthOfSubdomain = match.suffix().length();
            buffer->addCh(lengthOfSubdomain); 

            // last subdomain to binary
            subdomainString = match.suffix();

            for (std::size_t i = 0; i < subdomainString.size(); ++i) {
                buffer->addCh(subdomainString[i]);

                std::cout << subdomainString[i] << ": " << std::bitset<8>(subdomainString[i]).to_string() << std::endl;
            }
        }

        // add "." at the end of domain
        buffer->addCh(0);
    }

    void Qtype_QClass(bufferClass* buffer, bool IPv6) {
        // QTYPE
        if (IPv6) {
            buffer->addShort(28);
        } else {
            buffer->addShort(1);
        }

        // QCLASS
        buffer->addShort(1);
    }
};


/**
 * @brief function gets server domain and returns server IP
 * 
 * 
 * @source: https://gist.github.com/jirihnidek/bf7a2363e480491da72301b228b35d5d
 * @author jirihnidek, xtulus00
 * */
IP46 lookup_host (const char *host) {
  struct addrinfo hints, *res;
  int errcode;
  char addrstr[100];
  void *ptr;
  IP46 myIp;

  myIp.ipv4 = "";
  myIp.ipv6 = "";
  myIp.v4 = false;
  myIp.v6 = false;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_CANONNAME;

  errcode = getaddrinfo (host, NULL, &hints, &res);
  if (errcode != 0)
    {
      perror ("getaddrinfo");
      return myIp;
    }

  printf ("Host: %s\n", host);
  while (res) {
      inet_ntop (res->ai_family, res->ai_addr->sa_data, addrstr, 100);

      switch (res->ai_family) {
        case AF_INET:
          ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
          break;
        case AF_INET6:
          ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
          break;
        }
      inet_ntop (res->ai_family, ptr, addrstr, 100);
      //printf ("IPv%d address: %s (%s)\n", res->ai_family == PF_INET6 ? 6 : 4, addrstr, res->ai_canonname);
      if (res->ai_family == PF_INET6) {
          myIp.ipv6 = addrstr;
          myIp.v6 = true;
      } else {
          myIp.ipv4 = addrstr;
          myIp.v4 = true;
      }
      res = res->ai_next;
    }

  return myIp;
}


int getIPVersion(unsigned short ipVersion) {
    if (ipVersion == 0x01) {
        return(4);
    } else if (ipVersion == 0x1c) {
        return(6);
    } else {
        err(ERR_RCVD_SOCKET);
    }

    return(0);

}

/**
 * @brief function for write error message to stderr and exit with exit code from parameter
 * 
 * @param err_code
 * */
void err(int err_code) {
    switch(err_code) {
        case ERR_ARGUMENTS:
            std::cerr << "Invalid argumetns." << std::endl;
            break;

        case ERR_ARGUMENTS_MISSING_REQUIRED:
            std::cerr << "Missing required argument - Server or Address." << std::endl;
            break;

        case ERR_ARGUMENTS_SERVER:
            std::cerr << "Invalid input Server name/ip address." << std::endl;
            break;

        case ERR_SOCKET:
            std::cerr << "Error in socket" << std::endl;
            break;

        case ERR_RCVD_SOCKET:
            std::cerr << "Error in received socket" << std::endl;
            break;
            
    }

    exit(err_code);
}


/**
 * @brief
 * 
 * 
 * @source: https://www.geeksforgeeks.org/udp-server-client-implementation-c/
 * @author amitds, xtulus00
 * */
void sendQuery(bufferClass* bufferPtr, bufferClass* rcvBuffer, Arguments inputArgvs) {
    Header dnsHeader(bufferPtr);
    dnsHeader.RFlag(inputArgvs.optR);

    Question dnsQuestion(bufferPtr, inputArgvs.optAddressValue);
    dnsQuestion.Qtype_QClass(bufferPtr, inputArgvs.opt6);

    // sendig UDP query
    int sockQuery;
    int n;
    int len = bufferPtr->endOfBuffer - bufferPtr->buffer;

    if (!inputArgvs.optServerIP.v4) {
        // IPv6 socket

        struct sockaddr_in6 servaddr6;
    
        if ( (sockQuery = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) { 
            perror("socket creation failed"); 
            err(ERR_SOCKET); 
        } 

        memset(&servaddr6, 0, sizeof(servaddr6)); 
        
        // Filling server information 
        servaddr6.sin6_family = AF_INET6; 
        servaddr6.sin6_port = htons(inputArgvs.optPortValue); 
        // store this IP address in serveraddr:
        inet_pton(AF_INET6, inputArgvs.optServerIP.ipv6.c_str(), &servaddr6.sin6_addr);
     
        

        // send socket
        
        sendto(sockQuery, /*dnsMessage.c_str(), dnsMessage.length()*/"ahoj",4, 
            MSG_CONFIRM, (const struct sockaddr *) &servaddr6,  
                sizeof(servaddr6)); 

        n = recvfrom(sockQuery, (char *)rcvBuffer->buffer, MAXLINE,  
                MSG_WAITALL, (struct sockaddr *) &servaddr6, 
                (socklen_t*)&len); 
        


    } else {
        // IPv4 socket

        struct sockaddr_in servaddr; 
        // Source: https://www.geeksforgeeks.org/udp-server-client-implementation-c/
        // Creating socket file descriptor 
        if ( (sockQuery = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) { 
            perror("socket creation failed"); 
            err(ERR_SOCKET); 
        } 

        memset(&servaddr, 0, sizeof(servaddr)); 
        
        // Filling server information 
        servaddr.sin_family = AF_INET; 
        servaddr.sin_port = htons(inputArgvs.optPortValue); 
        // store this IP address in serveraddr:
        inet_pton(AF_INET, inputArgvs.optServerIP.ipv4.c_str(), &(servaddr.sin_addr));
        

        // send socket
        
        
        sendto(sockQuery, bufferPtr->buffer, len, 
            MSG_CONFIRM, (const struct sockaddr *) &servaddr,  
                sizeof(servaddr)); 

        n = recvfrom(sockQuery, (char *)rcvBuffer->buffer, MAXLINE,  
                MSG_WAITALL, (struct sockaddr *) &servaddr, 
                (socklen_t*)&len); 
    }


    
    rcvBuffer->buffer[n] = '\0';
    rcvBuffer->endOfBuffer = &(rcvBuffer->buffer[n]);
    printf("Server : %s\n", rcvBuffer->buffer); 
  
    close(sockQuery); 
}


DNSheaderParams checkRcvdHeader(bufferClass* buffer, bufferClass* rcvBuffer, Arguments inputArgs) {
    DNSheaderParams hdrParams;

    unsigned char* bufferPtr = &(rcvBuffer->buffer[0]);

    // check ID
    if (buffer->readID() != rcvBuffer->readID()) {
        err(ERR_RCVD_SOCKET);
    } else {
        bufferPtr += 2;
    }

    // check flags
    //                                 1  1  1  1  1  1
    //   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // | 1|   000x    | x| x| x| x|  000   |   0xxx    |

    // check for 0
    constexpr unsigned char mapTest1{ 0x70 };   // must be x000 xxxx 
    constexpr unsigned char mapTest2{ 0x78 };   //         x000 0xxx 
    if ((mapTest1 & *bufferPtr) != 0x00) {
        err(ERR_RCVD_SOCKET);
    }

    if ((mapTest2 & *(bufferPtr + 1)) != 0x00) {
        err(ERR_RCVD_SOCKET);
    }


    // check for 1
    // QR must be set to 1
    constexpr unsigned char QRflag{ 0x80 };     // 1xxx xxxx
    if ((QRflag & *bufferPtr) != QRflag) {
        err(ERR_RCVD_SOCKET);
    }

    // OPCODE
    // if inverse
    constexpr unsigned char REVERSEflag{ 0x10 };
    if (inputArgs.optX) {
        if ((REVERSEflag & *bufferPtr) != REVERSEflag) {    // xxxx 1xxx
            err(ERR_RCVD_SOCKET);
        }
    } else {
        if ((REVERSEflag & *bufferPtr) != 0x00) {           // xxxx 0xxx
            err(ERR_RCVD_SOCKET);
        }
    }

    // authoritative
    constexpr unsigned char AAflag{ 0x04 };
    if ((AAflag & *bufferPtr) == AAflag) {
        std::cout << "Authoritative: Yes\n"; 
    } else {
        std::cout << "Authoritative: No\n";
    }

    // truncated
    constexpr unsigned char TCflag{ 0x02 };
    if ((TCflag & *bufferPtr) == TCflag) {
        std::cout << "Truncated: Yes\n"; 
    } else {
        std::cout << "Truncated: No\n";
    }

    // recursion
    constexpr unsigned char RDflag{ 0x01 };
    if ((RDflag & *bufferPtr++) == RDflag) {

        constexpr unsigned char RAflag{ 0x80 };
        if ((RAflag & *bufferPtr++) == RAflag) {
            std::cout << "Recursive: Yes\n";
        } else {
            std::cout << "Recursive: No\n";
        }
        
    } else {
        std::cout << "Recursive: No\n";
        bufferPtr++;
    }

    // QDCount
    hdrParams.QDCount = rcvBuffer->readShort(&bufferPtr);

    // ANCount
    hdrParams.ANCount = rcvBuffer->readShort(&bufferPtr);

    // NSCount
    hdrParams.NSCount = rcvBuffer->readShort(&bufferPtr);

    // ARCount
    hdrParams.ARCount = rcvBuffer->readShort(&bufferPtr);
    
    return hdrParams;
}



void parseAnswer(bufferClass* buffer, bufferClass* rcvBuffer, Arguments inputArgs) {
    unsigned char* bufferPtr = &(rcvBuffer->buffer[0]);
    unsigned char* offsetBufferPtr = &(rcvBuffer->buffer[0]);
    DNSheaderParams ansDnsHdr;

    ansDnsHdr = checkRcvdHeader(buffer, rcvBuffer, inputArgs);

    // move ptr after header
    bufferPtr += 12;
    
    // Question section
    std::cout << "Questions: " << ansDnsHdr.QDCount << std::endl;
    
    std::cout << rcvBuffer->readAddress(&bufferPtr) << ", ";
    std::cout << ((rcvBuffer->readShort(&bufferPtr) == 0x01) ? "A" : "AAAA") << ", ";
    std::cout << ((rcvBuffer->readShort(&bufferPtr) == 0x01) ? "IN" : "unknown") << std::endl;

    // std::cout << "New Offset: " << bufferPtr - rcvBuffer->buffer << std::endl;

    // Answer section
    std::cout << "Answers: " << ansDnsHdr.ANCount << std::endl;
    for (int i = 0; i < ansDnsHdr.ANCount; i++) {
        std::cout << rcvBuffer->readAddress(&bufferPtr) << ", ";

        int ipV = getIPVersion(rcvBuffer->readShort(&bufferPtr));
        std::cout << ((ipV == 4) ? "A" : "AAAA") << ", ";

        std::cout << ((rcvBuffer->readShort(&bufferPtr) == 0x01) ? "IN" : "unknown") << ", ";
        std::cout << rcvBuffer->readIP(&bufferPtr, ipV) << std::endl;
    }
    

    std::cout << "Authority: " << ansDnsHdr.NSCount << std::endl;
    std::cout << "Additional: " << ansDnsHdr.ARCount << std::endl;


}



// int helpfulX = bufferPtr - rcvBuffer->buffer;
// std::cout << "actual offset" << helpfulX << std::endl;

int main(int argc, char **argv) {
    Arguments inputArgs;
    inputArgs.handle_arguments(argc, argv);

    bufferClass buffer;
    bufferClass rcvBuffer;

    sendQuery(&buffer, &rcvBuffer, inputArgs);
    parseAnswer(&buffer, &rcvBuffer, inputArgs);

    return(0);
}