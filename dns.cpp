#include "dns.h"

class bufferClass {
public:
    unsigned char buffer[512];
    unsigned char* endOfBuffer = &buffer[0];
    
    void addCh(char val) {
        *endOfBuffer++ = val;
    }

    void addS(char* val) {
        for (unsigned int i = 0; i < strlen(val); i++) {
            *endOfBuffer++ = val[i];
        }
    }

    void addShort(short val) {
        *endOfBuffer = htons(val);
        endOfBuffer += 2;
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
 * @author: jirihnidek, xtulus00
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
            
    }

    exit(err_code);
}


/**
 * @brief
 * 
 * */
void sendQuery(bufferClass* bufferPtr,std::string Domain, IP46 Server, short Port, bool FlagR, bool FlagX, bool Flag6) {
    Header dnsHeader(bufferPtr);
    dnsHeader.RFlag(FlagR);

    Question dnsQuestion(bufferPtr, Domain);
    dnsQuestion.Qtype_QClass(bufferPtr, Flag6);

    // sendig UDP query
    int sockQuery;

    if (!Server.v4) {
        // IPv6 socket

        struct sockaddr_in6 servaddr6;
    
        if ( (sockQuery = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) { 
            perror("socket creation failed"); 
            err(ERR_SOCKET); 
        } 

        memset(&servaddr6, 0, sizeof(servaddr6)); 
        
        // Filling server information 
        servaddr6.sin6_family = AF_INET6; 
        servaddr6.sin6_port = htons(Port); 
        // store this IP address in serveraddr:
        inet_pton(AF_INET6, Server.ipv6.c_str(), &servaddr6.sin6_addr);
     
        

        // send socket
        int n, len; 
        
        sendto(sockQuery, /*dnsMessage.c_str(), dnsMessage.length()*/"ahoj",4, 
            MSG_CONFIRM, (const struct sockaddr *) &servaddr6,  
                sizeof(servaddr6)); 
        


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
        servaddr.sin_port = htons(Port); 
        // store this IP address in serveraddr:
        inet_pton(AF_INET, Server.ipv4.c_str(), &(servaddr.sin_addr));
        

        // send socket
        int n, len; 
        
        sendto(sockQuery, /*dnsMessage.c_str(), dnsMessage.length()*/"ahoj",4, 
            MSG_CONFIRM, (const struct sockaddr *) &servaddr,  
                sizeof(servaddr)); 
    }
}


int main(int argc, char **argv) {
    Arguments inputArgs;
    inputArgs.handle_arguments(argc, argv);

    bufferClass buffer;

    sendQuery(&buffer, inputArgs.optAddressValue, inputArgs.optServerIP, inputArgs.optPortValue, inputArgs.optR, inputArgs.optX, inputArgs.opt6);
    

    return(0);
}