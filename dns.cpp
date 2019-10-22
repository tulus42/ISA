#include "dns.h"


class Arguments {
public:
    bool optR = false;
    bool optX = false;
    bool opt6 = false;
    bool optP = false;
    std::string optPortValue = "53";
    bool optServer = false;
    IP46 optServerIP;
    bool optAddress = false;
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
                optPortValue = argv[i];
            } 

            // -s   SERVER
            else if (std::string(argv[i]) == "-s") {
                if (optServer == false)
                    optServer = true;
                else
                    err(ERR_ARGUMENTS_SERVER);

                i++;
                // TODO
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
            else if (optAddress == false) {
                optAddress = true;
                optAddressValue = argv[i];
            }

            else {
                err(ERR_ARGUMENTS);
            }

        }

        if (optServer == false || optAddress == false)
            err(ERR_ARGUMENTS_MISSING_REQUIRED);
    }
};



/**
 *  * The header contains the following fields:
 *
 *                                   1  1  1  1  1  1
 *     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                      ID                       |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    QDCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    ANCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    NSCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    ARCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * */
class DNSHeader {
public:
    std::string ID;
    std::string QR;
    std::string Opcode = "0000";        // use only standard query
    std::string AA;
    std::string TC;
    std::string RD;
    std::string RA;
    std::string Z = "000";
    std::string Rcode;
    std::string QDCOUNT;
    std::string ANCOUNT;
    std::string NSCOUNT;
    std::string ARCOUNT;

    void genDNSHeader() {
        // generate ID
        srand((unsigned int)time(NULL));

        std::string newID;
        for (int i = 0; i < 16; i++) {
            newID.append(std::to_string(rand() % 2));
        }

        ID = newID;
        
        std::cout<< "ID: " << ID << std::endl;
    }

    // 1 bit
    void setQR(std::string value) {
        // 0 = query, 1 = answer
        QR = value;
    }

    // 1 bit
    void setAA(std::string value) {
        AA = value;
    }

    // 1 bit
    void setTC(std::string value) {
        TC = value;
    }
    
    // 1 bit
    void setRD(std::string value) {
        RD = value;
    }

    // 1 bit
    void setRA(std::string value) {
        RA = value;
    }

    // 4 bits
    void setRcode(std::string value) {
        Rcode = value;
    }

    // 16 bits
    void setQDCOUNT(int value) {
        QDCOUNT = std::bitset<16>(value).to_string(); //to binary
    }

    // 16 bits
    void setANCOUNT(int value) {
        ANCOUNT = std::bitset<16>(value).to_string(); //to binary
    }

    // 16 bits
    void setNSCOUNT(int value) {
        NSCOUNT = std::bitset<16>(value).to_string(); //to binary
    }

    // 16 bits
    void setARCOUNT(int value) {
        ARCOUNT = std::bitset<16>(value).to_string(); //to binary
    }
    
    // returns full header
    std::string getFullHeader() {
        return(ID + QR + Opcode + AA + TC + RD + RA + Z + Rcode + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT);
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
      if (res->ai_family == PF_INET6)
          myIp.ipv6 = addrstr;
      else 
          myIp.ipv4 = addrstr;
      res = res->ai_next;
    }

  return myIp;
}


/**
 * @brief
 * 
 * */
void sendQuery(std::string Domain, IP46 Server, std::string Port, bool FlagR, bool FlagX, bool Flag6) {
    std::string dnsHeader = createHeader(Domain, Server, Port, FlagR, FlagX, Flag6);

    std::cout << dnsHeader.substr(0, 16) << std::endl << dnsHeader.substr(16, 16) << std::endl << dnsHeader.substr(32, 16) << std::endl << dnsHeader.substr(48, 16) << std::endl << dnsHeader.substr(64, 16) << std::endl << dnsHeader.substr(80, 16) << std::endl;

}


/**
 * @brief
 *
 * */
std::string createHeader(std::string domain, IP46 server, std::string Port, bool FlagR, bool FlagX, bool Flag6) {
    DNSHeader queryHeader;
    queryHeader.genDNSHeader();
    queryHeader.setQR("0");
    queryHeader.setAA("0");
    queryHeader.setTC("0");
    queryHeader.setRD(FlagR ? "1" : "0");
    queryHeader.setRA("0");
    queryHeader.setRcode("0000");
    queryHeader.setQDCOUNT(1);
    queryHeader.setANCOUNT(0);
    queryHeader.setNSCOUNT(0);
    queryHeader.setARCOUNT(0);

    return(queryHeader.getFullHeader());
}



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
            
    }

    exit(err_code);
}



int main(int argc, char **argv){
    Arguments inputArgs;
    inputArgs.handle_arguments(argc, argv);

    sendQuery(inputArgs.optAddressValue, inputArgs.optServerIP, inputArgs.optPortValue, inputArgs.optR, inputArgs.optX, inputArgs.opt6);



    return(0);
}