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
#include <iostream>
#include <sstream>
#include <unistd.h>

using namespace std;

/**
 *Global constants
 */
string helpMsg = "\n"
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
    int c;
    bool pFlag, TFlag, SFlag, cFlag, CFlag, dFlag, nFlag, aFlag, oFlag;
    string server, port, certFile, certAddr, authFile, outDir;

    cout << "Hello world!" << endl;
    while ((c = getopt(argc, argv, ":p:TSc:C:dna:o:")) != -1) {
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
        case ':':
          break;
      }
    }
    return 0;
}

/**
 * Function for terminating the program with an error message
 */
void errTerminate(string msg) {
  cerr << "Error: " << msg << "\n";
  exit(EXIT_FAILURE);
}
