#include "dns.h"


class Arguments {
    public:
        bool optR = false;
        bool optX = false;
        bool opt6 = false;
        bool optP = false;
        int optPValue;
        bool optS = false;
        Server optSType;
        std::string optSValue;
        bool optA = false;
        std::string optAddress;


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

                // -p
                else if (std::string(argv[i]) == "-p") {
                    if (optP == false)
                        optP = true;
                    else
                        err(ERR_ARGUMENTS);

                    i++;
                    // TODO 
                    // port toInt()
                    // optPValue = argv[i]
                        
                } 

                // -s
                else if (std::string(argv[i]) == "-s") {
                    if (optS == false)
                        optS = true;
                    else
                        err(ERR_ARGUMENTS);

                    i++;
                    // TODO
                    // check validity of server
                    // check if IP or Domain
                    // optSValue = arg[i]
                        
                } 

                // address
                else if (optA == false) {

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




using namespace std;
int main(int argc, char **argv){

    handle_arguments(argc, argv);



    return(0);
}