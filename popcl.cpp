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
#include <string>
#include <iostream>
#include <sstream>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

using namespace std;

/**
 *Global constants
 */
const string helpMsg =
  "usage: popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]]\n"
  "             [-d] [-n] -a <auth_file> -o <out_dir>\n";
const string mandatArgsMsg = "at least, <server>, -a <auth_file>, -o <out_dir>"
  "must be specified";
const string pop3_port = "110";
const string pop3s_port = "995";

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
  bool pFlag = false, TFlag = false, SFlag = false, cFlag = false,
  CFlag = false, dFlag = false, nFlag = false, aFlag = false, oFlag = false;
  string server, port = pop3_port, certFile, certAddr, authFile, outDir;
  struct option long_ops[] = {
     {"help", no_argument, NULL, 'h'},
     {0, 0, 0, 0}
  };

  if (argc < 2) {
    errTerminate(mandatArgsMsg);
  }
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

  struct stat outDirStat;

  if (oFlag) {
    if (stat(outDir.c_str(), &outDirStat) != 0 ) {
      errTerminate(string("Can't access output directory ") + outDir);
    }
    if (!(outDirStat.st_mode & S_IFDIR)) {
      errTerminate(outDir + " is not a directory");
    }
  }
  else {
    errTerminate(mandatArgsMsg);
  }
  if (TFlag) {
    if (!pFlag) {
      port = pop3s_port;
    }
  }

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
