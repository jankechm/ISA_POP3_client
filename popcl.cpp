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
const string fileOpenProblem = "can not open output file to store message";
const string pop3_port = "110";
const string pop3s_port = "995";
const regex ok_rgx("^\\+OK.*?\r\n$");
const regex list_rgx(R"~(\+OK (\d*) \d*\r\n((\d* \d*\r\n)*))~");
const regex list_msgs_rgx(R"~(\d* \d*\r\n)~");
const regex ending_rgx("\r\n\\.\r\n$");
const regex split_msg_ids_rgx(R"~( \d*\r\n)~");
string user = "", pass = "";

/**
 *Prototypes of functions
 */
void parseArgs(int argc, char **argv, map<string, bool> &oFlags, map<string, string> &oArgs);
void checkOps (map<string, bool> &oFlags);
void errTerminate(string msg);
void handleAuth(string authPath, string &user, string &pass);
void establishCom(int &clientSocket, int &bytesrx, char buffer[], map<string, string> &oArgs);
void authentize(int &clientSocket, int &bytesrx, char *buffer);
void listMsgNums(int &clientSocket, int &bytesrx, char *buffer, int &msgCnt, vector<int> &msgNums);
void parseMsgNums(int &clientSocket, int &msgCnt, string &msgContent, vector<int> &msgNums);
void storeIMF(string outDir, string msgNum, string msgContent);
bool retrieveMsg(int &clientSocket, int &bytesrx, char *buffer, string msgNum, string outDir);

/**
 *Main
 */
int main(int argc, char **argv)
{
  int clientSocket, bytesrx, msgCnt, storedCnt = 0;
  map<string, bool> optFlags = {
    {"p", false}, {"T", false}, {"S", false}, {"c", false}, {"C", false},
    {"d", false}, {"n", false}, {"a", false}, {"o", false}
  };
  map<string, string> optArgs = {
    {"server", ""}, {"port", pop3_port},  {"certFile", ""}, {"certAddr", ""},
    {"authFile", ""}, {"outDir", "./"}
  };
  char buffer[BUFSIZE];
  struct stat outDirStat;
  string msg = "";
  vector<int> msgNums;

  //Handle input arguments
  parseArgs(argc, argv, optFlags, optArgs);
  //Check for illegal combinations and mandatory options
  checkOps(optFlags);
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
    //Regular communication
    establishCom(clientSocket, bytesrx, buffer, optArgs);
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
      //Send USER and PASS cmd
      authentize(clientSocket, bytesrx, buffer);
      //Send LIST command
      listMsgNums(clientSocket, bytesrx, buffer, msgCnt, msgNums);
      //If there are some messages, get their numbers
      if (msgCnt > 0) {
        //Send RETR command in a cycle for every message
        //and download messages
        storedCnt = 0;
        for (unsigned int i = 0; i < msgNums.size(); i++) {
          if (retrieveMsg(clientSocket, bytesrx, buffer, to_string(msgNums[i]), optArgs["outDir"])) {
            storedCnt++;
          }
        }
        // Write to stdout
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
      //Send QUIT command
      msg = "QUIT\r\n";
      send(clientSocket, msg.c_str(), msg.size(), 0);
    } //End regular msg dowload
  } //End without encyption
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

  //If there is no arg, print usage msg
  if (argc < 2) {
    cout << usageMsg;
    exit(EXIT_SUCCESS);
  }
  //Get hostname or IP address of the server
  oArgs["server"] = argv[1];
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
      //Handle help
      case 'h':
        if (argc == 2) {
          cout << usageMsg;
          exit(EXIT_SUCCESS);
        }
        else {
          errTerminate("--help or -h has to be entered as the only argument");
        }
        break;
      //Handle option without required argument
      case ':':
        errTerminate(string("option ") + string(1, optopt) + " requires an argument");
        break;
      //Handle unrecognized option; have to distinguish between long and short option
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

  //Opening file with fstream
  fstream fs(authPath);
  if (!fs.is_open()) {
    errTerminate("can not open authentication file");
  }
  else {
    //Store whole content in single string
    while (fs >> s) {
      content += s + " ";
    }
  }
  //Try match witch regular expression
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

/**
 * Function for establishing communication with the server
 */
void establishCom(int &clientSocket, int &bytesrx, char *buffer, map<string, string> &oArgs) {
  struct addrinfo hints, *result;
  int ecode;

  //Reset data structures
  memset(&hints, 0, sizeof(struct addrinfo));
  memset(buffer, 0, BUFSIZE);
  //Specify criteria: TCP, IPv4/IPv6
  hints.ai_flags = 0;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;

  //Address translation for socket
  if ((ecode = (getaddrinfo(oArgs["server"].c_str(), oArgs["port"].c_str(), &hints, &result))) != 0) {
    //cerr << oArgs["server"] << " " << oArgs["port"] << endl;
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
  if ((bytesrx = recv(clientSocket, buffer, BUFSIZE-1, 0)) == -1) {
    errTerminate(recvProblem);
  }
  //Check for response
  buffer[bytesrx] = '\0';
  cout << buffer << endl;
  if (!regex_match(buffer, ok_rgx)) {
    errTerminate(badAnswer);
  }
}

/**
 * Function for authentication to the server
 */
void authentize(int &clientSocket, int &bytesrx, char *buffer) {
  string msgSend = "";

  //Send USER username command
  msgSend = "USER " + user + "\r\n";
  cout << "C: " << msgSend;
  if ((send(clientSocket, msgSend.c_str(), msgSend.size(), 0)) == -1) {
    close(clientSocket);
    errTerminate(sendProblem);
  }
  //Receive response to USER
  if ((bytesrx = recv(clientSocket, buffer, BUFSIZE-1, 0)) == -1) {
    errTerminate(recvProblem);
  }
  buffer[bytesrx] = '\0';
  cout << "S: " << buffer;
  if (strncmp(buffer, "+OK", 3) != 0) {
    cout << "No match!" << endl;
    msgSend = "QUIT\r\n";
    send(clientSocket, msgSend.c_str(), msgSend.size(), 0);
    errTerminate(badAnswer);
  }

  //Send PASS password command
  msgSend = "PASS " + pass + "\r\n";
  cout << "C: " << msgSend;
  if ((send(clientSocket, msgSend.c_str(), msgSend.size(), 0)) == -1) {
    close(clientSocket);
    errTerminate(sendProblem);
  }
  //Receive response to PASS
  if ((bytesrx = recv(clientSocket, buffer, BUFSIZE-1, 0)) == -1) {
    errTerminate(recvProblem);
  }
  buffer[bytesrx] = '\0';
  cout << "S: " << buffer;
  if (strncmp(buffer, "+OK", 3) != 0) {
    cout << "No match!" << endl;
    msgSend = "QUIT\r\n";
    send(clientSocket, msgSend.c_str(), msgSend.size(), 0);
    errTerminate(badAnswer);
  }
}

/**
 * Function for listing messages numbers from the server
 */
void listMsgNums(int &clientSocket, int &bytesrx, char *buffer, int &msgCnt, vector<int> &msgNums) {
  string msgSend = "", msgContent = "", response = "";

  //Send LIST command
  msgSend = "LIST \r\n";
  cout << "C: " << msgSend;
  if ((send(clientSocket, msgSend.c_str(), msgSend.size(), 0)) == -1) {
    close(clientSocket);
    errTerminate(sendProblem);
  }
  //Receive response to LIST
  while (1) {
    bytesrx = recv(clientSocket, buffer, BUFSIZE-1, 0);
    if (bytesrx == -1) {
      errTerminate(recvProblem);
    }
    buffer[bytesrx] = '\0';
    response = string(buffer);
    msgContent += response;
    if (regex_search(msgContent, ending_rgx)) {
      break;
    }
  }
  cout << "S: " << msgContent;
  //Parse answer
  parseMsgNums(clientSocket, msgCnt, msgContent, msgNums);
}

/**
 * Function for parsing messages numbers
 */
void parseMsgNums(int &clientSocket, int &msgCnt, string &msgContent, vector<int> &msgNums) {
  int msgNum;
  smatch matches;
  string msgLines = "", msgLine = "", msgSend = "";
  stringstream ss;

  //Check if postive response
  if (regex_search(msgContent, matches, list_rgx)) {
    /*for (unsigned int i = 0; i < matches.size(); i++) {
      cout << i << " '" << matches[i].str() << "'" << endl;
    }*/
    msgCnt = stoi(matches[1].str());
    cout << "msgCnt: " << msgCnt << endl;
    if (msgCnt > 0) {
      msgLines = matches[2].str();
      cout << "msgLines: " << endl << msgLines << endl;
      ss << msgLines;
      for (int i = 0; i < msgCnt; i++) {
        ss >> msgNum;
        msgNums.push_back(msgNum);
        ss >> msgNum;
      }
      cout << "msgNums: '";
      for (unsigned int i = 0; i < msgNums.size(); i++) {
        cout << msgNums[i] << " ";
      }
      cout << "'" << endl;
    }
  }
  //If no postive answer, QUIT communication
  else {
    cout << "No match!" << endl;
    msgSend = "QUIT\r\n";
    send(clientSocket, msgSend.c_str(), msgSend.size(), 0);
    errTerminate(badAnswer);
  }
}

/**
 * Function for downloading a message from the server
 */
bool retrieveMsg(int &clientSocket, int &bytesrx, char *buffer, string msgNum, string outDir) {
  string msgSend = "", msgContent = "", msgPart = "", response = "", status = "";
  stringstream ss;

  msgSend = "RETR " + msgNum + "\r\n";
  cout << "C: " << msgSend;
  if ((send(clientSocket, msgSend.c_str(), msgSend.size(), 0)) == -1) {
    close(clientSocket);
    errTerminate(sendProblem);
  }
  //Receive response to RETR
  //First line
  if ((bytesrx = recv(clientSocket, buffer, BUFSIZE-1, 0)) == -1) {
    errTerminate(recvProblem);
  }
  buffer[bytesrx] = '\0';
  cout << "S: " << buffer;
  response = string(buffer);
  ss << response;
  ss >> status;
  if (!(strncmp(status.c_str(), "+OK", 3) == 0)) {
    return false;
  }
  //Next lines - whole message
  while (1) {
    if ((bytesrx = recv(clientSocket, buffer, BUFSIZE-1, 0)) == -1) {
      errTerminate(recvProblem);
    }
    buffer[bytesrx] = '\0';
    msgPart = string(buffer);
    if (regex_search(msgPart, ending_rgx)) {
      cout << "Sprava " << msgNum << " kompletne stiahnuta!" << endl;
      msgContent += msgPart.substr(0, msgPart.size()-3);
      break;
    }
    msgContent += msgPart;
  }
  //Store IMF message in output file
  storeIMF(outDir, msgNum, msgContent);
  return true;
}

/**
 * Function for storing IMF message in output file
 */
void storeIMF(string outDir, string msgNum, string msgContent) {
  string filePath;

  if (outDir.back() == '/') {
    filePath = outDir + msgNum + ".txt";
  }
  else {
    filePath = outDir + "/" + msgNum + ".txt";
  }
  ofstream ofsfile(filePath, ios::out);
  if(!ofsfile.is_open()) {
    errTerminate(fileOpenProblem);
  }
  ofsfile << msgContent;
}
