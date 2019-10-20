#include "dns.h"


class Arguments {
    public:
        bool optR = false;
        bool optX = false;
        bool opt6 = false;
        bool optP = false;
        std::string optPortValue = "53";
        bool optServer = false;

        std::string optServerValue;
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
                        err(ERR_ARGUMENTS);

                    i++;
                    // TODO
                    // check validity of server
                    optServerIP = lookup_host(argv[i]);

                    if (optServerIP.ipv4 == "" && optServerIP.ipv6 == "")
                        err(ERR_ARGUMENTS);

                    if (optServerIP.ipv6 != "")
                        optServerValue = optServerIP.ipv6;

                    std::cout << "IPv4: " << optServerIP.ipv4 << "\n";
                    std::cout << "IPv6: " << optServerIP.ipv6 << "\n";
                    // optServerValue = arg[i]
                        
                } 

                // address
                else if (optAddress == false) {
                    optAddress = true;
                }

                else {
                    err(ERR_ARGUMENTS);
                }

            }
        }
};


void err(int err_code) {
    switch(err_code) {
        case ERR_ARGUMENTS:
            std::cerr << "Invalid argumetns" << std::endl;
            
    }

    exit(err_code);
}

/**
 * @brief
 * 
 * 
 * @source: https://gist.github.com/jirihnidek/bf7a2363e480491da72301b228b35d5d
 * @author: jirihnidek, xtulus00
 * */
IP46 lookup_host (const char *host)
{
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



int main(int argc, char **argv){
    Arguments inputArgs;
    inputArgs.handle_arguments(argc, argv);



    return(0);
}