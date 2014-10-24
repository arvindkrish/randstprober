#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include "socket.h"

static char *AddrToHost(struct in_addr *addr, char *hname, int maxhostlen);
static void NetSetErrno(NetErrnoType e);

static NetErrnoType net_errno = E_NET_OK;
static int saved_errno = 0;

/* Translations between ``net_errno'' values and human readable strings.
*/
static const char *net_syserrlist[] = {
	"All was chill"
};



#ifdef STRERROR_NOT_DEFINED
const char *strerror(int errno) { return sys_errlist[errno]; }
#endif



/* NetErrStr()
 *--------------------------------------------------------------------
 * Returns a diagnostic message for the last failure.
 */
const char *NetErrStr()
{
  return (net_errno==E_NET_ERRNO) ? strerror(saved_errno) :
    net_syserrlist[net_errno];
}

/* NetErrNo()
 *--------------------------------------------------------------------
 * Returns a diagnostic number for the last failure.
 */
NetErrnoType NetErrNo()
{
  return net_errno;
}



/* NetMakeWelcome()
 *--------------------------------------------------------------------
 * Creates a socket that listens for incoming connections.
 *--------------------------------------------------------------------
 * Creates a socket on the local machine at on given ``port''.
 * Call @NewConnection() and pass the socket returned by this function to
 * it.
 *
 * Returns a socket on success or -1 on error.
 */
SOCKET
NetMakeWelcome(int port)
{
  int fd;
  struct sockaddr_in addr;
  int v;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd == -1)
    {
      NetSetErrno(E_NET_ERRNO);
      return -1;
    }

  v = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)))
    {
      NetSetErrno(E_NET_ERRNO);
      return -1;
    }
  if(listen(fd, 5))
    {
      NetSetErrno(E_NET_ERRNO);
      return -1;
    }

  NetSetErrno(E_NET_OK);
  return fd;
}



/* NetNewConnection()
 *--------------------------------------------------------------------
 * Waits for a new connection.
 *--------------------------------------------------------------------
 * Waits for a new connection on the welcome socket. Once a connection
 * is attempted from a remote host, initializes the client ``newc''
 * and creates a new socket for it to create.
 *
 * Returns -1 on error and 0 on success.
 */
int
NetNewConnection(w, newc)
     SOCKET w;
     ClientPtr newc;
{
  int newfd;
  struct sockaddr_in addr;
  int addrlen = sizeof(addr);

  do
      {
	  errno = 0;
	  if(((newfd = accept(w, (struct sockaddr *)&addr, (socklen_t *)&addrlen)) == -1)
	     && errno != EINTR)
	      {
		NetSetErrno(E_NET_ERRNO);
		return -1;
	      }
      } while(errno == EINTR);

  ResetClient(newc);
  InitClient(newc);
  SetClientFd(newc, newfd);

  if(GetClientMaxHlen(newc))
      AddrToHost(&addr.sin_addr,
		 GetClientHname(newc), GetClientMaxHlen(newc));

  NetSetErrno(E_NET_OK);
  return 0;
}


/* NetCloseConnection()
 *--------------------------------------------------------------------
 * Closes a client's connection.
 */
void
NetCloseConnection(c)
     ClientPtr c;
{
    close(GetClientFd(c));
    CloseClient(c);
    NetSetErrno(E_NET_OK);
}



/* NetClientDataAvail()
 *--------------------------------------------------------------------
 * Returns the number of bytes available on the connection to a client.
 */
int
NetClientDataAvail(c)
     ClientPtr c;
{
  long len;
  int fd = GetClientFd(c);

  if(ioctl(fd, FIONREAD, &len))
    {
      
      return -1;
    }

  NetSetErrno(E_NET_OK);
  return len;
}



/* NetGetClientHostname()
 *--------------------------------------------------------------------
 * Gets the hostname of a remote client.
 *--------------------------------------------------------------------
 * Given a buffer ``hanme'' and the size of that buffer, ``maxhostlen'',
 * puts the hostname of the remote client into the buffer.
 *
 * Usually, the client's hostname will will be available through
 * @GetClientHname() if @GetClientMaxHlen() returns non-zero on the
 * client. If however, you have defined @GetClientMaxHlen() to return
 * zero, @GetClientHostname() is the function to call, since the
 * data will not be available through @GetClientHname().
 *
 * Returns a pointer to the buffer on success, or NULL on error.
 */
char *
NetGetClientHostname(c, hname, maxhostlen)
     ClientPtr c;
     char *hname;
     int maxhostlen;
{
  struct sockaddr_in name;
  int nlen = sizeof(name);

  if(getpeername(GetClientFd(c), (struct sockaddr *)&name, (socklen_t *)&nlen))
    {
      NetSetErrno(E_NET_ERRNO);
      return NULL;
    }

  NetSetErrno(E_NET_OK);
  return AddrToHost(&name.sin_addr, hname, maxhostlen);
}


/* This is not for you. */
static char *
AddrToHost(struct in_addr *addr, char *hname, int maxhostlen)
{
    struct hostent *hent;

    hent = gethostbyaddr(addr, sizeof(*addr), AF_INET);
    if(hent == NULL)
	    /* Use the ip address as the hostname */
	    strncpy(hname, inet_ntoa(*addr), maxhostlen);
    else
	strncpy(hname, hent->h_name, maxhostlen);

    return hname;
}


static void NetSetErrno(NetErrnoType e)
{
  if(e == E_NET_ERRNO)saved_errno = errno;
  net_errno = e;
  if(net_errno != E_NET_OK) HandleNetError();
}


void InitClient(ClientPtr cl) { cl->fd = -1; }
void ResetClient(ClientPtr cl) { cl->fd = -1; }
void SetClientFd(ClientPtr cl, SOCKET fd) { cl->fd = fd; }
SOCKET GetClientFd(ClientPtr cl) { return cl->fd; }
void CloseClient(ClientPtr cl) { ResetClient(cl); }
char *GetClientHname(ClientPtr cl) { return cl->hostname; }
int GetClientMaxHlen(ClientPtr cl) { return sizeof(cl->hostname); }
void HandleNetError() {
  fprintf(stderr, "Network error: %s\n", NetErrStr());
}



void child_signal()
{
    int res;
    wait(&res);
}

/* NetMakeContact()
 *--------------------------------------------------------------------
 * Makes a tcp connection to a host:port pair.
 *--------------------------------------------------------------------
 * ``Hostname'' can either be in the form of a hostname or an IP address
 * represented as a string. If the hostname is not found as it is,
 * ``hostname'' is assumed to be an IP address, and it is treated as such.
 *
 * If the lookup succeeds, a TCP connection is established with the
 * specified ``port'' number on the remote host and a stream socket is
 * returned.
 *
 * On any sort of error, an error code can be obtained with @NetErrNo()
 * and a message with @NetErrStr().
 */
SOCKET
NetMakeContact(const char *hname, int port)
{
  int fd;
  struct sockaddr_in addr;
  struct hostent *hent;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd == -1)
    {
      NetSetErrno(E_NET_ERRNO);
      return -1;
    }


  hent = gethostbyname(hname);
  if(hent == NULL)
    addr.sin_addr.s_addr = inet_addr(hname);
  else
    memcpy(&addr.sin_addr, hent->h_addr, hent->h_length);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)))
    {
      NetSetErrno(E_NET_ERRNO);
      return -1;
    }

  NetSetErrno(E_NET_OK);
  return fd;
}

int
NetGetAddr(char *hname)
{
    struct sockaddr_in addr;
    struct hostent *hent;
    
    hent = gethostbyname(hname);
    if (hent == NULL)
	addr.sin_addr.s_addr = inet_addr(hname);
    else
	memcpy(&addr.sin_addr, hent->h_addr, hent->h_length);
    return addr.sin_addr.s_addr;
}

int write_buf(int fd, char *buf, size_t len)
{
    size_t total = 0;
    int ret;
    while (total < len) {
	ret = write(fd, buf + total, len-total);
	if (ret < 0)
	    return -1;
	total += ret;
    }
    return total;
}

int write_int(int f,int32 x)
{
    char b[4];
    SIVAL(b,0,x);
    return write_buf(f,b,4);
}

int read_buf(int fd, char *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
	int ret = read(fd, buf + total, len-total);
	if (ret < 0)
	    return -1;
	total += ret;
    }
    return total;
}

int read_int(int f, int32 *val)
{
	char b[4];
	int ret;

	ret = read_buf(f,b,4);
	if (ret < 0)
	    return -1;
	*val = IVAL(b,0);
	if (*val == (int32)0xffffffff) *val = -1;
	return sizeof(int32);
}
