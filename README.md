# POP3 client

Program allows downloading and deleting mail messages from a server using POP3 protocol.
The authentication is required using POP3 commands USER and PASS.

## Usage

### Compile:

```bash
$ ./make
```

### Run:

```bash
$ ./popcl <server> [-p <port>] [-d] -a <auth_file> -o <out_dir>
```

### Mandatory arguments:
Argument | Description
------------ | -------------
&lt;server> | IPv4 or IPv6 address or domain name of POP3 server.
-a &lt;auth_file> | Path to the file with login credentials.
-o &lt;outd_dir> | Directory where the messages to be downloaded are being stored.

### Optional arguments:
Argument | Description
------------ | -------------
-p &lt;port> | Server port number. Default is 110.
-d | Delete all messages from the server after downloading them.

## Example


```bash
$ ./popcl pop3.seznam.cz -o ~/Documents/popcl_mails/ -a ~/Documents/auth.txt
$ ./popcl 2a02:598:2::46 -o /tmp -a auth.txt -d
```
