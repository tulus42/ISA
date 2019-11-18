/**
 * DNS resolver - ISA 2019, FIT VUT Brno
 * Adrián Tulušák, xtulus00
 * 
 * */



#include "dns.h"


/**
 * @class contains buffer long 512 bytes - max length of DNS message
 *        and pointer to the end of this buffer
 * */
class bufferClass {
public:
    unsigned char buffer[512];
    unsigned char* endOfBuffer = &buffer[0];
    
    /**
     * @brief Constructor - set 0 to every index of buffer
     * */
    bufferClass() {
        for (int i = 0; i < 256; i++) {
            buffer[i] = 0;
        }
    }

    /**
     * @brief function adds 1 char value to the buffer and shifts end of buffer pointer by 1
     * @param val value that will be added to the buffer
     * */
    void addCh(char val) {
        *endOfBuffer++ = val;
    }

    /**
     * @brief function adds string to the buffer and shifts end of buffer pointer by length of that string
     *        function parse string in cycle and every char adds to the buffer
     * @param val value that will be added to the buffer
     * */
    void addS(char* val) {
        for (unsigned int i = 0; i < strlen(val); i++) {
            *endOfBuffer++ = val[i];
        }
    }

    /**
     * @brief function adds 1 shor value to the buffer and shifts end of buffer pointer by 2
     *        function converts value to the network format
     * @param val value that will be added to the buffer
     * */
    void addShort(short val) {
        short * ptrBuffer = (short*)endOfBuffer;
        *ptrBuffer = htons(val);
        endOfBuffer += 2;
    }

    /**
     * @brief reads first short from the buffer - ID of DNS header
     * @return returns short - ID of DNS header
     * */
    unsigned short readID() {
        unsigned short* res = (unsigned short*)buffer;
        return *res;
    }

    /**
     * @brief reads 1 short from the buffer and shifts actual position pointer by 2
     *        function converts short from network format to the client format
     * @param ptr pointer to the actual position in buffer
     * @return returns readed short
     * */
    unsigned short readShort(unsigned char** ptr) {
        unsigned short* res = (unsigned short*)*ptr;
        *ptr += 2;
        return ntohs(*res);
    }

    /**
     * @brief reads 1 char from the buffer and shifts actual position pointer by 1
     * @param ptr pointer to the actual position in buffer
     * @return returns readed char
     * */
    unsigned char readChar(unsigned char** ptr) {
        unsigned char res = **ptr;
        *ptr += 1;
        return(res);
    }

    /**
     * @brief Function read address (domain) from buffer. Function reads length of subdomain that will
     *        be readed and than reads that subdomain. After that this subdomain will be added to the
     *        buffer. Function can handle pointer in domain and read it anyway.
     * @param BuffPtr pointer to the actual position in buffer
     * @return returns string - domain
     * */
    std::string readAddress(unsigned char** BuffPtr) {
        std::string res = "";
                
        // reads chars - at first number that means how many chars will read in subdomain and than
        // reads this subdomain
        // cycle ends when reads "0" at position with number of loength of following subdomain
        while (**BuffPtr != 0) {
            // if compression by ptr
            // recursively call function readAddress and read part or full domain from readed pointer
            if ((0xc0 & (int)**BuffPtr) == 0xc0) {
                unsigned short compressionOffset = *((unsigned short*)*BuffPtr);

                // remove offset sign (0xC0) from frist 2 bits of offset
                compressionOffset = 0x3f00 & compressionOffset;
                compressionOffset = ntohs(compressionOffset);

                unsigned char* tmpPtr = &(this->buffer[compressionOffset]);
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


    /**
     * @brief reads RData from answer and moves actual position pointer by length of RData 
     * @param BuffPtr pointer to the actual position in buffer
     * @param typeOfAnswer type of DNS resource record
     * @param length length of RData
     * @return returns readed and converted RData from network format 
     * */
    std::string readRData(unsigned char** BuffPtr, DNSType typeOfAnswer, unsigned short length) {
        std::string res = "";

        // switch reading RData by type of resorce record
        switch (typeOfAnswer)
        {
        case A:
            // A record must be 4 bytes long
            if (length != 4) 
                err(ERR_RCVD_SOCKET);
        
            // reads byte, makes string from it and adds "." after it
            for (int i = 0; i < 4; i++) {
                unsigned int tmpRes = this->readChar(BuffPtr);
                res += std::to_string(tmpRes);
                if (i != 3) {
                    res += ".";
                }
            }
            break;

        case AAAA:
            // AAAA record must be 16 bytes long
            if (length != 16)
                err(ERR_RCVD_SOCKET);

            // reads short and converts it to hex, adds ":" between it
            for (int i = 0; i < 8; i++) {
                unsigned short tmpRes = this->readShort(BuffPtr);
                std::stringstream tmpStream;
                tmpStream << std::hex << tmpRes;
                res += tmpStream.str();

                if (i < 7)
                    res += ":";
            }
            break;

        case CNAME:
            // CNAME record has same structure like address
            res = this->readAddress(BuffPtr);
            break;
            
        case PTR:
            // PTR record need to read address
            res = this->readAddress(BuffPtr);
            break;

        // other records just write "unknown" and move pointer to the actual position in buffer - do not read other records
        default:
            res = "unknown";
            *BuffPtr += length;
            break;
        }
        
        return(res);
    }
};


/**
 * @class contains all arguments of programs, information if are used and their value
 *        and functions to manipulate with them
 * */
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

    /**
     * @brief reads all arguments and if valid argument, sets its bool to true
     *        if not valid, call err() function
     * @param argc number of arguments
     * @param argv array of arguments
     * */
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
            }        

            // -x
            else if (std::string(argv[i]) == "-x") {
                if (optX == false)
                    optX = true;
                else
                    err(ERR_ARGUMENTS);
            } 

            // -6
            else if (std::string(argv[i]) == "-6") {
                if (opt6 == false)
                    opt6 = true;
                else
                    err(ERR_ARGUMENTS);
            } 

            // -p   PORT
            else if (std::string(argv[i]) == "-p") {
                if (optP == false)
                    optP = true;
                else
                    err(ERR_ARGUMENTS);

                // port is made of 2 arguments
                i++;
                int iPort = std::stoi(argv[i]);

                // check validity of port
                if (std::to_string(iPort) != argv[i])
                    err(ERR_ARGUMENTS);
                if (iPort > 65535)
                    err(ERR_ARGUMENTS);

                optPortValue = (short)(std::stoi(argv[i]));
            } 

            // -s   SERVER
            else if (std::string(argv[i]) == "-s") {
                if (optS == false)
                    optS = true;
                else
                    err(ERR_ARGUMENTS_SERVER);

                // server is made of 2 arguments
                i++;
                // check validity of server
                optServerIP = lookup_host(argv[i]);

                // if ipv4 niether ipv6 is not valid, call err()
                if (optServerIP.ipv4 == "" && optServerIP.ipv6 == "")
                    err(ERR_ARGUMENTS_SERVER);

                if (optServerIP.ipv6 != "")
                    optServerIP.v6 = true;
                else
                    optServerIP.v6 = false;                      
            } 

            // address
            else if (optA == false) {
                optA = true;
                optAddressValue = argv[i];
            }

            // everything else is invalid
            else {
                err(ERR_ARGUMENTS);
            }

        }

        // check if required arguments are used
        if (optS == false || optA == false)
            err(ERR_ARGUMENTS_MISSING_REQUIRED);
    }
};


/**
 * @class contains header of DNS query and all needed to ceate it
 * */
class Header {
public:
    unsigned short* dnsHeader;
    unsigned short headerID;

    /**
     * @brief Constructor - creates header of DNS query
     * @param buffer pointer to the buffer
     * */
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

    /**
     * @brief sets value of recusrive flag in header
     * @param flagR value of "recursive" argument
     * */ 
    void RFlag(bool flagR) {
        if (flagR)
            dnsHeader[1] = htons(0x0100);
    }
};


/**
 * @class contains informations about question specification and all necessary to create question
 * */
class Question {
public:
    bool ipv6;
    bool reverse;
    std::string domain;
    bufferClass* buffer;

    /**
     * @brief Constructor - assigns values to the variables from arguments
     *        and choose between reverse and standard query
     * @param bufferPtr pointer to bufferClass
     * @param argvs arguments of program
     * */
    Question(bufferClass* bufferPtr, Arguments argvs) {
        reverse = argvs.optX;
        domain = argvs.optAddressValue;
        buffer = bufferPtr;
        ipv6 = argvs.opt6;
        
        if (!reverse) {
            // standard query
            this->addAddressToBuffer();
        } else {
            // reverse query
            this->reverseQuery(buffer);
        }

        // add "." at the end of domain
        buffer->addCh(0);
    }

    /**
     * @brief parse domain name (or ip address) divided by "." and writes it to the buffer
     *        in query format
     * */
    void addAddressToBuffer () {
        std::regex re("([.])");
        std::sregex_iterator next(domain.begin(), domain.end(), re);
        std::sregex_iterator end;
        std::smatch match;
        std::string lastPart;
        bool onePartDomain = true;

        char lengthOfSubdomain;
        std::string subdomainString;

        if (domain == ".") {
            return;
        }

        // reads every subdomain in cycle 
        while (next != end) {
            onePartDomain = false;

            match = *next;
            
            // 8 bit length of subdomain
            lengthOfSubdomain = match.prefix().length();
            // adds length of subdomain to the buffer
            buffer->addCh(lengthOfSubdomain);

            subdomainString = match.prefix();
            
            // adds subdomain to the buffer
            for (std::size_t i = 0; i < subdomainString.size(); ++i) {
                buffer->addCh(subdomainString[i]);
            }
            next++;
        } 


        if (onePartDomain) {
            lastPart = domain;
        } else {
            lastPart = match.suffix();
        }
        // if domain do not ends with "." 
        // -> handle last subdomain
        if (lastPart != "") {
            // 8 bit length of last subdomain
            lengthOfSubdomain = lastPart.length();
            // adds length of subdomain to the buffer
            buffer->addCh(lengthOfSubdomain); 

            subdomainString = lastPart;

            // adds last subdomain to the buffer
            for (std::size_t i = 0; i < subdomainString.size(); ++i) {
                buffer->addCh(subdomainString[i]);
            }
        }
    }

    /**
     * @brief function gets ipv6 address that may be in shorten format and make it full format
     *        empty spaces fulfill with 0
     *        function works with 32-part address format - every part is 4-bit long hexa number
     * @param begin string vector - contains parts before shortening (before "::") 
     * @param end string vector - contains parts after shortening (after "::")
     * @return functions returns vector of strings - returns full form of ipv6 addres
     *         in 32-part format including zeroes
     * */
    std::vector<std::string> fillIPv6WithZeroes(std::vector<std::string> begin, std::vector<std::string> end) {
        int emptyCnt = 32 - (begin.size() + end.size());

        // cycle for adding "0" to the empty spaces in vector
        for (int i = 0; i < emptyCnt; i++) {
            begin.push_back("0");
        }

        // creating fill addres by concatenating all created vectors
        // -> vector before shortening + vector with zeroes + vector ater shortening
        begin.insert(begin.end(), end.begin(), end.end());

        return(begin);
    }

    /**
     * @brief functions checks version of ip address by regex
     *        then parse each version and in the end it wrtites the address to the buffer
     * @param buffer pointer to the buffer class to write address to the buffer
     * */
    void reverseQuery(bufferClass* buffer) {
        int tmpInt;
        std::stringstream tmpStream;
        std::string tmpString = "";
        bool reverseV6;

        // Check validity of IP int reverse query and choose IP version
        // IPv4
        // source : http://ipregex.com/
        if(std::regex_match(domain, std::regex("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])[.]){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"))){
            reverseV6 = false;
        } // IPv6
        // source : https://www.phpliveregex.com/learn/system-administration/how-to-match-ip-addresses/
        else if(std::regex_match(domain, std::regex("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])[.]){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])[.]){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"))){
            reverseV6 = true;
        } else {
            err(ERR_INPUT_DOMAIN);
        }


        // reverse IPv6 query - 0000:: -> some.domain.name
        if (reverseV6) {
            std::vector<std::string> v6begin;
            std::vector<std::string> v6end;
            bool afterShortenFlag = false;

            // loop for every char in domain from input
            for (std::string::iterator i=domain.begin(); i != domain.end(); i++) {
                if (*i == ':') {
                    // "::"
                    if (*(i+1) == ':') {
                        afterShortenFlag = true;
                        i++;

                        // ::...
                        if (i == domain.begin())
                            continue;
                    } 

                // reading part of address (not ":" or "::")
                } else {
                    tmpStream << std::dec << (*i);

                    // ::..xx:xx
                    if (afterShortenFlag) {
                        v6end.push_back(tmpStream.str());
                    // xx:xx..::
                    } else {
                        v6begin.push_back(tmpStream.str());
                    }
                    tmpStream.str("");
                }
            }

            // if ipv6 address was in shorten format -> fulfill it with 0
            std::vector<std::string> fullV6Vector = this->fillIPv6WithZeroes(v6begin,v6end);

            // address must be reversed (1.2.3.4.5... -> ...5.4.3.2.1)
            std::reverse(fullV6Vector.begin(),fullV6Vector.end()); 

            // creates string from vector and adds "." between parts of address
            domain = "";
            for (int i = 0; i < 32; i++) {
                domain += (fullV6Vector[i]);
                domain += '.';
            }

            // creates full address for DNS server by adding "ip6.arpa" at the end
            domain += "ip6.arpa.";


        // reverse IPv4 query - 123.456.789.1 -> some.domain.name
        } else {
            std::vector<int> ipv4Vector;

            // loop for every char in domain from input
            for ( std::string::iterator i=domain.begin(); i!=domain.end(); ++i) {
                if (*i == '.') {
                    // check if values are valid numbers 
                    tmpInt = std::stoi(tmpString);
                    if (std::to_string(tmpInt) != tmpString || tmpInt > 255 || tmpInt < 0)
                        err(ERR_INPUT_DOMAIN);

                    ipv4Vector.push_back(tmpInt);
                    tmpString = "";
                } else {
                    tmpString += *i;
                }
            }

            // check if values are valid numbers 
            tmpInt = std::stoi(tmpString);
            if (std::to_string(tmpInt) != tmpString || tmpInt > 255)
                err(ERR_INPUT_DOMAIN);

            ipv4Vector.push_back(tmpInt);

            // check if address has valid length
            if (ipv4Vector.size() != 4)
                err(ERR_INPUT_DOMAIN);

            // make reverse ipv4 address
            std::reverse(ipv4Vector.begin(),ipv4Vector.end()); 

            // create full address xx4.xx3.xx2.xx1.in-addr.arpa.
            domain = "";
            for (int i = 0; i < 4; i++) {
                domain += std::to_string(ipv4Vector[i]);
                domain += '.';
            }

            domain += "in-addr.arpa.";   
        }

        // adds ipv6/ipv4 address to the buffer
        this->addAddressToBuffer();
    }


    /**
     * @brief functions sets QType and QClass in the query
     * @param buffer pointer to the bufferClass to add information to the buffer
     * */
    void Qtype_QClass(bufferClass* buffer) {
        // QTYPE
        if (reverse) {
            // PTR
            buffer->addShort(12);
        } else {
            // AAAA
            if (ipv6) {
                buffer->addShort(28);
            // A    
            } else {
                buffer->addShort(1);
            }
        }

        // QCLASS
        buffer->addShort(1);
    }
};


/**
 * @brief function gets server domain and returns server IP
 * @param host char pointer - domain that will be translated to the ip address
 * @return returns structure that contains information about ipv4 and ipv6 address
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

  while (res) {
      inet_ntop (res->ai_family, res->ai_addr->sa_data, addrstr, 100);

      switch (res->ai_family) {
        // IPv4
        case AF_INET:
          ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
          break;
        // IPv6
        case AF_INET6:
          ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
          break;
        }
      inet_ntop (res->ai_family, ptr, addrstr, 100);

      // IPv6
      if (res->ai_family == PF_INET6) {
          myIp.ipv6 = addrstr;
          myIp.v6 = true;
      // IPv4
      } else {
          myIp.ipv4 = addrstr;
          myIp.v4 = true;
      }
      res = res->ai_next;
    }

  return myIp;
}

/**
 * @brief funstion checks value of answer Type, returns name of that Type and writes that type to the stdou
 * @param tmpType unsigned short - value of Type in answer
 * @return returns translated Type of answer
 * */
DNSType getType(unsigned short tmpType) {
    switch (tmpType)
    {
    case 0x01:
        std::cout << "A, ";
        return(A);
    
    case 0x02:
        std::cout << "NS, ";
        return(NS);

    case 0x03:
        std::cout << "MD, ";
        return(MD);

    case 0x04:
        std::cout << "MF, ";
        return(MF);

    case 0x05:
        std::cout << "CNAME, ";
        return(CNAME);

    case 0x06:
        std::cout << "SOA, ";
        return(SOA);

    case 0x07:
        std::cout << "MB, ";
        return(MB);

    case 0x08:
        std::cout << "MG, ";
        return(MG);

    case 0x09:
        std::cout << "MR, ";
        return(MR);

    case 0x0a:
        std::cout << "NULLdns, ";
        return(NULLdns);

    case 0x0b:
        std::cout << "WKS, ";
        return(WKS);

    case 0x0c:
        std::cout << "PTR, ";
        return(PTR);

    case 0x0d:
        std::cout << "HINFO, ";
        return(HINFO);

    case 0x0e:
        std::cout << "MINFO, ";
        return(MINFO);

    case 0x0f:
        std::cout << "MX, ";
        return(MX);

    case 0x10:
        std::cout << "TXT, ";
        return(TXT);

    case 0x1c:
        std::cout << "AAAA, ";
        return(AAAA);


    default:
        std::cout << "unknown Type";
        return(unknown);
    }
}

/**
 * @brief function for write error message to stderr and exit with exit code from parameter
 * @param err_code value of error code
 * */
void err(int err_code) {
    switch(err_code) {
        case ERR_ARGUMENTS:
            fprintf( stderr, "Error: Invalid argumetns.\n");
            break;

        case ERR_ARGUMENTS_MISSING_REQUIRED:
            fprintf( stderr, "Error: Missing required argument - Server or Address.\n");
            break;

        case ERR_ARGUMENTS_SERVER:
            fprintf( stderr, "Error: Invalid input Server name/ip address.\n");
            break;

        case ERR_SOCKET:
            fprintf( stderr, "Error: Error in socket\n");
            break;

        case ERR_RCVD_SOCKET:
            fprintf( stderr, "Error: Error in received socket\n");
            break;

        case ERR_INPUT_DOMAIN:
            fprintf( stderr, "Error: Error in insertet domain\n");
            break;

        case ERR_TIMEOUT:
            fprintf( stderr, "Error: socket time out\n");
            break;

        case ERR_RCODE_1:
            fprintf( stderr, "Error: format error - The name server was unable to interpret query.\n");
            break;

        case ERR_RCODE_2:
            fprintf( stderr, "Error: server failure - The name server was unable to process this query due to a problem with the name server.\n");
            break;

        case ERR_RCODE_3:
            fprintf( stderr, "Error: name error - Domain name referenced in the query does not exist.\n");
            break;

        case ERR_RCODE_4:
            fprintf( stderr, "Error: not implemented - The name server does not support the requested kind of query.\n");
            break;    

        case ERR_RCODE_5:
            fprintf( stderr, "Error: refused - The name server refused to perform the specified operation for policy reasons.\n");
            break;    
    }

    exit(err_code);
}


/**
 * @brief function creates whole question and sends it
 *        after that it receives answer and saves it to the rcvBuffer
 *        for next parsing
 * @param bufferPtr pointer to the bufferClass for writting header and 
 *        question to the buffer. This buffer will be send in socket
 * @param rcvBuffer pointer to the bufferClass for writing received
 *        answer to the buffer
 * @param inputArgvs class with program input arguments for setting
 *        flags in query
 * 
 * @source: https://www.geeksforgeeks.org/udp-server-client-implementation-c/
 * @author amitds, xtulus00
 * */
void sendQuery(bufferClass* bufferPtr, bufferClass* rcvBuffer, Arguments inputArgvs) {
    // creating header
    Header dnsHeader(bufferPtr);
    dnsHeader.RFlag(inputArgvs.optR);

    // creating question
    Question dnsQuestion(bufferPtr, inputArgvs);
    dnsQuestion.Qtype_QClass(bufferPtr);

    // sendig UDP query /////////////////////
    int sockQuery;
    int n;
    int len = bufferPtr->endOfBuffer - bufferPtr->buffer;

    if (!inputArgvs.optServerIP.v4) {
        // IPv6 socket ////
        // edited IPv4 sendig from listed source
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
        
        sendto(sockQuery, bufferPtr->buffer, len, 
            MSG_CONFIRM, (const struct sockaddr *) &servaddr6,  
                sizeof(servaddr6)); 

        // time out
        struct pollfd pfd = {.fd = sockQuery, .events = POLLIN, {0}};

        if (poll(&pfd, 1, 3000) == 0) {
            err(ERR_TIMEOUT);
        }

        n = recvfrom(sockQuery, (char *)rcvBuffer->buffer, MAXLINE,  
                MSG_WAITALL, (struct sockaddr *) &servaddr6, 
                (socklen_t*)&len); 
        


    } else {
        // IPv4 socket ////

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

        // time out
        struct pollfd pfd = {.fd = sockQuery, .events = POLLIN, {0}};

        if (poll(&pfd, 1, 3000) == 0) {
            err(ERR_TIMEOUT);
        }

        n = recvfrom(sockQuery, (char *)rcvBuffer->buffer, MAXLINE,  
                MSG_WAITALL, (struct sockaddr *) &servaddr, 
                (socklen_t*)&len); 
    }


    // write end of buffer symbol and assign pointer to the end of buffer
    rcvBuffer->buffer[n] = '\0';
    rcvBuffer->endOfBuffer = &(rcvBuffer->buffer[n]);
  
    close(sockQuery); 
}

/**
 * @brief function reads header of received message and compares it to arguments of program
 *        and checks it validity
 * @param buffer pointer to the bufferClass with sending buffer to compare ID to the received ID 
 * @param rcvBuffer pointer to the bufferClass with received buffer for reading header from the buffer
 * @param inputArgs class with arguments of program
 * @return returns structure that contains count of every part of answer (QDCount, ANCount, NSCount, ARCount)
 * */
DNSheaderParams checkRcvdHeader(bufferClass* buffer, bufferClass* rcvBuffer, Arguments inputArgs) {
    DNSheaderParams hdrParams;

    unsigned char* bufferPtr = &(rcvBuffer->buffer[0]);

    // check ID
    if (buffer->readID() != rcvBuffer->readID()) {
        err(ERR_RCVD_SOCKET);
    } else {
        bufferPtr += 2;
    }

    // check flags - meaning of values:
    //  1 - must be set to 1 - if not -> err
    //  0 - must be set to 0 - if not -> err
    //  x - can be set to both values
    //                                 1  1  1  1  1  1
    //   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // | 1|   000x    | x| x| x| x|  000   |   0xxx    |
    

    // checking values by bit mask ///////////

    // check for 0
    constexpr unsigned char mapTest1{ 0x70 };   // must be x000 xxxx ____ ____ 
    constexpr unsigned char mapTest2{ 0x78 };   //         ____ ____ x000 0xxx 
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
    constexpr unsigned char OPCFlag{ 0x00 };
    // if inverse
    if (inputArgs.optX) {
        if ((OPCFlag & *bufferPtr) != OPCFlag) {        // xxxx 1xxx
            err(ERR_RCVD_SOCKET);
        }
    // if standard query
    } else {
        if ((OPCFlag & *bufferPtr) != OPCFlag) {           // xxxx 0xxx
            err(ERR_RCVD_SOCKET);
        }
    }

    // authoritative
    constexpr unsigned char AAflag{ 0x04 };
    if ((AAflag & *bufferPtr) == AAflag) {
        std::cout << "Authoritative: Yes, "; 
    } else {
        std::cout << "Authoritative: No, ";
    }

    // truncated
    constexpr unsigned char TCflag{ 0x02 };
    if ((TCflag & *bufferPtr) == TCflag) {
        std::cout << "Truncated: Yes, "; 
    } else {
        std::cout << "Truncated: No, ";
    }

    // recursion
    constexpr unsigned char RDflag{ 0x01 };
    if ((RDflag & *bufferPtr++) == RDflag) {

        constexpr unsigned char RAflag{ 0x80 };
        if ((RAflag & *bufferPtr) == RAflag) {
            std::cout << "Recursive: Yes";
        } else {
            std::cout << "Recursive: No";
        }
        
    } else {
        std::cout << "Recursive: No";
        bufferPtr;
    }

    // return code
    if ((0x05 & *bufferPtr) == 0x05) {
        err(ERR_RCODE_2);
    }

    if ((0x04 & *bufferPtr) == 0x04) {
        err(ERR_RCODE_4);
    }

    if ((0x03 & *bufferPtr) == 0x03) {
        err(ERR_RCODE_3);
    }

    if ((0x02 & *bufferPtr) == 0x02) {
        err(ERR_RCODE_2);
    }

    if ((0x01 & *bufferPtr++) == 0x01) {
        err(ERR_RCODE_1);
    }

    // write information about answer to the stdout
    std::cout << std::endl;


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


/**
 * @brief reads one answer from answer/authority/additional section and writes it to the stdout
 *        after read always move pointer to the actual position by length of readed part
 * @param rcvBuffer pointer to the buffer class with buffer with received message
 * @param bufferPtr pointer to the actual position in buffer
 * */
void readAnswer(bufferClass* rcvBuffer, unsigned char** bufferPtr) {
    unsigned short rLength;
    std::cout << "  " << rcvBuffer->readAddress(bufferPtr) << ", ";

    // read TYPE
    DNSType typeOfAnswer = getType(rcvBuffer->readShort(bufferPtr));

    // read CLASS
    std::cout << ((rcvBuffer->readShort(bufferPtr) == 0x01) ? "IN" : "unknown") << ", ";

    // read TTL
    unsigned short ttl = rcvBuffer->readShort(bufferPtr) * 65536;
    ttl += rcvBuffer->readShort(bufferPtr);
    std::cout << ttl << ", ";

    // read RLength
    rLength = rcvBuffer->readShort(bufferPtr);

    // read RData
    std::cout << rcvBuffer->readRData(bufferPtr, typeOfAnswer, rLength) << std::endl;
}


/**
 * @brief functions handles all validations and parsing of received message
 *        at first calls funstions to check validity of header and then for
 *        every section os message
 * @param buffer pointer to the bufferClass with question buffer to compare ID
 * @param rcvBuffer pointer to the bufferClass with answer buffer
 * @param inputArgs class with arguments of program
 * */
void parseAnswer(bufferClass* buffer, bufferClass* rcvBuffer, Arguments inputArgs) {
    unsigned char* bufferPtr = &(rcvBuffer->buffer[0]);
    unsigned char* offsetBufferPtr = &(rcvBuffer->buffer[0]);
    DNSheaderParams ansDnsHdr;

    ansDnsHdr = checkRcvdHeader(buffer, rcvBuffer, inputArgs);

    // move ptr after header
    bufferPtr += 12;
    
    // Question section
    std::cout << "Questions: " << ansDnsHdr.QDCount << std::endl;
    
    std::cout << "  " << rcvBuffer->readAddress(&bufferPtr) << ", ";        // address
    getType(rcvBuffer->readShort(&bufferPtr));                              // type
    std::cout << ((rcvBuffer->readShort(&bufferPtr) == 0x01) ? "IN" : "unknown") << std::endl;      // class

    // Answer section
    std::cout << "Answers: " << ansDnsHdr.ANCount << std::endl;
    for (int i = 0; i < ansDnsHdr.ANCount; i++) {
        readAnswer(rcvBuffer, &bufferPtr);
    }
    
    // Authority section
    std::cout << "Authority: " << ansDnsHdr.NSCount << std::endl;
    for (int i = 0; i < ansDnsHdr.NSCount; i++) {
        readAnswer(rcvBuffer, &bufferPtr);
    }

    // Additional section
    std::cout << "Additional: " << ansDnsHdr.ARCount << std::endl;
    for (int i = 0; i < ansDnsHdr.ARCount; i++) {
        readAnswer(rcvBuffer, &bufferPtr);
    }

}



int main(int argc, char **argv) {
    Arguments inputArgs;
    inputArgs.handle_arguments(argc, argv);

    bufferClass buffer;
    bufferClass rcvBuffer;

    sendQuery(&buffer, &rcvBuffer, inputArgs);
    parseAnswer(&buffer, &rcvBuffer, inputArgs);

    return(0);
}