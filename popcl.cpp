/**
 * File:        popcl.cpp
 * Author:      Marek Jankech
 * Date:        20.11.2017
 * Project:     Client POP3 with TLS support
 * Description: The program allows reading mails through POP3 protocol
                with pop3s and POP3 STARTTLS extensions. Program supports
                authentication with USER/PASS commands only.
 */

#include <cstdlib>
#include <cstdio>
#include <cstdbool>
#include <cstring>
#include <iostream>
#include <sstream>
#include <unistd.h>
#include <getopt.h>

using namespace std;

/**
 *Global constants
 */
string helpMsg =
  "usage: popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]]\n"
  "             [-d] [-n] -a <auth_file> -o <out_dir>\n";

/**
 *Prototypes of functions
 */
void errTerminate(string msg);

/**
 *Main
 */
int main(int argc, char **argv)
{
    int c, currOptind;
    bool pFlag, TFlag, SFlag, cFlag, CFlag, dFlag, nFlag, aFlag, oFlag;
    string server, port, certFile, certAddr, authFile, outDir;
    struct option long_ops[] = {
       {"help", no_argument, NULL, 'h'},
       {0, 0, 0, 0}
    };

    do {
      currOptind = optind;
      c = getopt_long(argc, argv, ":p:TSc:C:dna:o:", long_ops, NULL);
      switch (c) {
        case 'p':
          pFlag = true;
          port = optarg;
          break;
        case 'T':
          TFlag = true;
          break;
        case 'S':
          SFlag = true;
          break;
        case 'c':
          cFlag = true;
          certFile = optarg;
          break;
        case 'C':
          CFlag = true;
          certAddr = optarg;
          break;
        case 'd':
          dFlag = true;
          break;
        case 'n':
          nFlag = true;
          break;
        case 'a':
          aFlag = true;
          authFile = optarg;
          break;
        case 'o':
          oFlag = true;
          outDir = optarg;
          break;
        case 'h':
          if (argc == 2) {
            cout << helpMsg;
            exit(EXIT_SUCCESS);
          }
          else {
            errTerminate("--help or -h has to be entered as the only argument");
          }
          break;
        case ':':
          errTerminate(string("option ") + string(1, optopt) + " requires an argument");
          break;
        case '?':
          if (optopt) {
            errTerminate(string("bad option -") + string(1, optopt));
          }
          else {
            errTerminate(string("bad option ") + argv[currOptind]);
          }
          break;
        case -1:
          break;
        default:
          errTerminate("bad input");
      }
    } while (c != -1);

    return 0;
}

/**
 * Function for terminating the program with an error message
 */
void errTerminate(string msg) {
  cerr << "Error: " << msg << endl;
  cout << helpMsg;
  exit(EXIT_FAILURE);
}
