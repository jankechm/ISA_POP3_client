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
#include <fstream>
#include <regex>
#include <map>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>

#define BUFSIZE 1024

using namespace std;

/**
 *Global variables
 */
const string usageMsg =
  "usage: popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]]\n"
  "             [-d] [-n] -a <auth_file> -o <out_dir>\n";
const string mandatArgsMsg = "at least, <server>, -a <auth_file>, -o <out_dir>"
  " must be specified";
const string badAnswer = "negative or no answer from the server";
const string recvProblem = "problem with receiving message from the server";
const string sendProblem = "problem with sending message to the server";
const string pop3_port = "110";
const string pop3s_port = "995";
string user = "", pass = "";

/**
 *Prototypes of functions
 */
void parseArgs(int argc, char **argv, map<string, bool> &oFlags, map<string, string> &oArgs);
void checkOps (map<string, bool> &oFlags);
void errTerminate(string msg);
void handleAuth(string authPath, string &user, string &pass);

/**
 *Main
 */
int main(int argc, char **argv)
{
  int clientSocket, ecode, bytesrx, msgNum, msgCnt, storedCnt = 0;
  map<string, bool> optFlags = {
    {"p", false}, {"T", false}, {"S", false}, {"c", false}, {"C", false},
    {"d", false}, {"n", false}, {"a", false}, {"o", false}
  };
  map<string, string> optArgs = {
    {"server", ""}, {"port", pop3_port},  {"certFile", ""}, {"certAddr", ""},
    {"authFile", ""}, {"outDir", "./"}
  };
  char buffer[BUFSIZE];
  struct addrinfo hints, *result;
  struct stat outDirStat;
  string msg = "", status = "", msgPart = "", msgContent = "", response = "";
  stringstream ss;
  vector<int> msgNums;
  regex ok_rgx("^\\+OK.*?\r\n$");
  regex list_rgx("\\+OK (\\d*) \\d*\r\n(\\d* \\d*\r\n)*");
  regex ending_rgx("\r\n\\.\r\n$");
  smatch matches;

  //Handle input arguments
  parseArgs(argc, argv, optFlags, optArgs);
  //Check for illegal combinations and mandatory options
  checkOps(optFlags);
  //Reset data structures
  memset(&hints, 0, sizeof(struct addrinfo));
  memset(buffer, 0, sizeof(buffer));
  //Specify criteria: TCP, IPv4/IPv6
  hints.ai_flags = 0;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  //Try to access output directory
  if (stat(optArgs["outDir"].c_str(), &outDirStat) != 0 ) {
    errTerminate(string("can't access output directory ") + optArgs["outDir"]);
  }
  if (!(outDirStat.st_mode & S_IFDIR)) {
    errTerminate(optArgs["outDir"] + " is not a directory");
  }
  //Get user name and password from the authentication file
  handleAuth(optArgs["authFile"], user, pass);
  //Determine appropriate port
  if (optFlags["T"]) {
    if (!optFlags["p"]) {
      optArgs["port"] = pop3s_port;
    }
    //TODO
  }
  else if (optFlags["S"]) {
    //TODO
  }
  else {
    //Address translation for socket
    if ((ecode = (getaddrinfo(optArgs["server"].c_str(), optArgs["port"].c_str(), &hints, &result))) != 0) {
      //cerr << optArgs["server"] << " " << optArgs["port"] << endl;
      errTerminate(gai_strerror(ecode));
    }
    //Create socket
    if ((clientSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) == -1) {
      errTerminate("can't create socket");
    }
    //Establish a connection to the server
    if (connect(clientSocket, result->ai_addr, result->ai_addrlen) == -1) {
      errTerminate("can't connect to the server");
    }
    //Free addrinfo structure result
    freeaddrinfo(result);
    //Communicate with the server
    if ((bytesrx = recv(clientSocket, buffer, sizeof(buffer)-1, 0)) == -1) {
      errTerminate(recvProblem);
    }
    //Terminate string with '\0'
    buffer[bytesrx] = '\0';
    cout << buffer << endl;
    if (regex_match(buffer, ok_rgx)) {
      //cout << "Match!" << endl;
    }
    else {
      //cout << "No match!" << endl;
      errTerminate(badAnswer);
    }
    if (optFlags["d"]) {
      if (optFlags["n"]) {
        //TODO
      }
      else {
        //TODO
      }
    }
    //Regular message downloading
    else {
      //Send USER username command
      msg = "USER " + user + "\r\n";
      cout << "C: " << msg;
      if ((send(clientSocket, msg.c_str(), msg.size(), 0)) == -1) {
        close(clientSocket);
        errTerminate(sendProblem);
      }
      //Receive response to USER
      if ((bytesrx = recv(clientSocket, buffer, sizeof(buffer)-1, 0)) == -1) {
        errTerminate(recvProblem);
      }
      buffer[bytesrx] = '\0';
      cout << "S: " << buffer;
      if (strncmp(buffer, "+OK", 3) == 0) {
        cout << "Match!" << endl;
      }
      else {
        cout << "No match!" << endl;
        msg = "QUIT\r\n";
        send(clientSocket, msg.c_str(), msg.size(), 0);
        errTerminate(badAnswer);
      }

      //Send PASS password command
      msg = "PASS " + pass + "\r\n";
      cout << "C: " << msg;
      if ((send(clientSocket, msg.c_str(), msg.size(), 0)) == -1) {
        close(clientSocket);
        errTerminate(sendProblem);
      }
      //Receive response to PASS
      if ((bytesrx = recv(clientSocket, buffer, sizeof(buffer)-1, 0)) == -1) {
        errTerminate(recvProblem);
      }
      buffer[bytesrx] = '\0';
      cout << "S: " << buffer;
      if (strncmp(buffer, "+OK", 3) == 0) {
        cout << "Match!" << endl;
        memset(buffer, 0, sizeof(buffer));
      }
      else {
        cout << "No match!" << endl;
        msg = "QUIT\r\n";
        send(clientSocket, msg.c_str(), msg.size(), 0);
        errTerminate(badAnswer);
      }

      //Send LIST command
      msg = "LIST \r\n";
      cout << "C: " << msg;
      if ((send(clientSocket, msg.c_str(), msg.size(), 0)) == -1) {
        close(clientSocket);
        errTerminate(sendProblem);
      }
      //Receive response to LIST
      //First line
      msgContent = "";
      int j1,j2,j3;
      j1 = j2 = j3 = 0;
      while (1) {
        cout << "j1 je " << j1 << endl;
        bytesrx = recv(clientSocket, buffer, sizeof(buffer)-1, 0);
        if (bytesrx == -1) {
          errTerminate(recvProblem);
        }
        cout << "j2 je " << j2 << endl;

        cout << "j3 je " << j3 << endl;
        buffer[bytesrx] = '\0';
        //cout << "S: '" << buffer << "'" << endl;

        response = string(buffer);

        msgContent += response;
        if (regex_search(msgContent, ending_rgx)) {
          break;
        }
        /*ss << response;
        ss >> status;
        memset(buffer, 0, sizeof(buffer));*/
        j1++;j2++;j3++;
      }
      if (strncmp(msgContent.c_str(), "+OK", 3) == 0) {
        cout << "Match +OK" << endl;
      }
      /*ss >> msgCnt;
      cout << "Msg counter: " << msgCnt << endl;*/
      if (regex_search(msgContent, matches, list_rgx)) {
        for (int i = 0; i < matches.size(); ++i) {
          cout << i << " '" << matches[i].str() << "'" << endl;
        }
      }
      msgCnt = 0;
      //Next lines
      if (msgCnt > 0) {
        while (1) {
          if ((bytesrx = recv(clientSocket, buffer, sizeof(buffer)-1, 0)) == -1) {
            errTerminate(recvProblem);
          }
          buffer[bytesrx] = '\0';
          cout << "S: '" << buffer << "'" << endl;
          if (strncmp(buffer, ".\r\n", 3) == 0) {
            cout << "Hotovo!" << endl;
            memset(buffer, 0, sizeof(buffer));
            break;
          }
          ss.str("");
          ss.clear();
          response = string(buffer);
          ss << response;
          ss >> msgNum;
          msgNums.push_back(msgNum);
          memset(buffer, 0, sizeof(buffer));
        }
        for (unsigned int i = 0; i < msgNums.size(); i++) {
          cout << msgNums[i] << " ";
        }
        cout << endl;

        //Send RETR command in a cycle for every message
        //and download messages
        for (unsigned int i = 0; i < msgNums.size(); i++) {
          msg = "RETR " + to_string(msgNums[i]) + "\r\n";
          cout << "C: " << msg;
          if ((send(clientSocket, msg.c_str(), msg.size(), 0)) == -1) {
            close(clientSocket);
            errTerminate(sendProblem);
          }
          //Receive response to RETR
          //First line
          msgContent = "";
          if ((bytesrx = recv(clientSocket, buffer, sizeof(buffer)-1, 0)) == -1) {
            errTerminate(recvProblem);
          }
          buffer[bytesrx] = '\0';
          cout << "S: " << buffer;
          response = string(buffer);
          ss.str("");
          ss.clear();
          ss << response;
          ss >> status;
          memset(buffer, 0, sizeof(buffer));
          if (!(strncmp(status.c_str(), "+OK", 3) == 0)) {
            continue;
          }
          //Next lines - whole message
          while (1) {
            if ((bytesrx = recv(clientSocket, buffer, sizeof(buffer)-1, 0)) == -1) {
              errTerminate(recvProblem);
            }
            buffer[bytesrx] = '\0';
            msgPart = string(buffer);
            if (regex_search(msgPart, ending_rgx)) {
              cout << "Sprava " << msgNums[i] << " kompletne stiahnuta!" << endl;
              memset(buffer, 0, sizeof(buffer));
              msgContent += msgPart.substr(0, msgPart.size()-3);
              storedCnt++;
              break;
            }
            msgContent += msgPart;
            memset(buffer, 0, sizeof(buffer));
          }
          string filePath = optArgs["outDir"] + to_string(msgNums[i]) + ".txt";
          ofstream ofsfile(filePath, ios::out);
          if(!ofsfile.is_open()) {
            errTerminate("can not open output file to store message");
          }
          ofsfile << msgContent;
        }
        if (storedCnt == 0 || storedCnt >= 5) {
          cout << "Staženo " << storedCnt << " zpráv." << endl;
        }
        else if (storedCnt == 1) {
          cout << "Stažena 1 zpráva." << endl;
        }
        else {
          cout << "Staženy " << storedCnt << " zprávy." << endl;
        }
      }
      //Nothing to download
      else {
        cout << "Staženo 0 zpráv." << endl;
      }
      msg = "QUIT\r\n";
      send(clientSocket, msg.c_str(), msg.size(), 0);
    }
  }
  return 0;
}

/**
 * Function for parsing input arguments
 */
void parseArgs(int argc, char **argv, map<string, bool> &oFlags, map<string, string> &oArgs) {
  struct option long_ops[] = {
     {"help", no_argument, NULL, 'h'},
     {0, 0, 0, 0}
  };
  int currOptind, c;

  //if there is no arg, print usage msg
  if (argc < 2) {
    cout << usageMsg;
    exit(EXIT_SUCCESS);
  }
  //get hostname or IP address of the server
  oArgs["server"] = argv[1];
  /*for (int i = 0; i < argc; i++) {
    cerr << i << ": " << argv[i] << endl;
  }*/
  //Get options in cycle
  do {
    currOptind = optind;
    c = getopt_long(argc, argv, ":p:TSc:C:dna:o:", long_ops, NULL);
    switch (c) {
      case 'p':
        oFlags["p"] = true;
        oArgs["port"] = optarg;
        break;
      case 'T':
        oFlags["T"] = true;
        break;
      case 'S':
        oFlags["S"] = true;
        break;
      case 'c':
        oFlags["c"] = true;
        oArgs["certFile"] = optarg;
        break;
      case 'C':
        oFlags["C"] = true;
        oArgs["certAddr"] = optarg;
        break;
      case 'd':
        oFlags["d"] = true;
        break;
      case 'n':
        oFlags["n"] = true;
        break;
      case 'a':
        oFlags["a"] = true;
        oArgs["authFile"] = optarg;
        break;
      case 'o':
        oFlags["o"] = true;
        oArgs["outDir"] = optarg;
        break;
      //handle help
      case 'h':
        if (argc == 2) {
          cout << usageMsg;
          exit(EXIT_SUCCESS);
        }
        else {
          errTerminate("--help or -h has to be entered as the only argument");
        }
        break;
      //handle option without required argument
      case ':':
        errTerminate(string("option ") + string(1, optopt) + " requires an argument");
        break;
      //handle unrecognized option; have to distinguish between long and short option
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
  /*for (int i = 0; i < argc; i++) {
    cerr << i << ": " << argv[i] << endl;
  }*/
}

/**
 * Function checks for illegal options combinations and mandatory options
 */
void checkOps (map<string, bool> &oFlags) {
  //Check for illegal combinations
  if (oFlags["T"] && oFlags["S"]) {
    errTerminate("only one of the options -T or -S can be specified");
  }
  if ((oFlags["c"] || oFlags["C"]) && (!oFlags["T"] && !oFlags["S"])) {
    errTerminate("-c or -C option must be entered along with -T or -S");
  }
  //Check for mandatory options
  if (!oFlags["o"] || !oFlags["a"]) {
    errTerminate(mandatArgsMsg);
  }
}

/**
 * Function for terminating the program with an error message
 */
void errTerminate(string msg) {
  cerr << "Error: " << msg << endl;
  cout << usageMsg;
  exit(EXIT_FAILURE);
}

/**
 * Function for getting information from authentication file
 */
void handleAuth(string authPath, string &user, string &pass) {
  string s, content;
  regex rgx("^\\s*(username)\\s*=\\s*?(\\S*)\\s*(password)\\s*=\\s*?(\\S*)\\s*$");
  smatch matches;

  //opening file with fstream
  fstream fs(authPath);
  if (!fs.is_open()) {
    errTerminate("can not open authentication file");
  }
  else {
    //store whole content in single string
    while (fs >> s) {
      content += s + " ";
    }
  }
  //try match witch regular expression
  if (regex_match(content, matches, rgx)) {
    /*cout << "Match!" << endl;
    for (int i = 0; i < matches.size(); ++i) {
      cout << i << " '" << matches[i].str() << "'" << endl;
    }
    cout << matches[2].str() << endl;
    cout << matches[4].str() << endl;*/
    //parse user name and password
    user = matches[2].str();
    pass = matches[4].str();
  }
  else {
    errTerminate("the content of the authentication file is in bad format");
  }
}
