#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include <mysql/mysql.h>

#define SIZE 60

MYSQL *con;
MYSQL_RES *res;
MYSQL_ROW row;

char d[100], e[100], f[100];
char x[100], y[100], z[100];

char query[1024];

void finish_with_error(MYSQL *con)
{
  fprintf(stderr, "%s\n", mysql_error(con));
  mysql_close(con);
  exit(1);        
}

void my_packet_handler(   //own callback function
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{

    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) 
    {
        printf("Not an IP packet.\n\n");
        return;
    }

    printf("\nTotal packet available: %d bytes\n", header->caplen);  //caplen is the actual available length
    printf("Expected packet size: %d bytes\n", header->len); //len is the total packet length 
    //pointers to start of various headers
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    int ethernet_header_length = 14; //fixed length of ethernet header in bytes.
    int ip_header_length;
    int tcp_header_length;
    int payload_length;
    int a,b,c,g,h,i,j,l,m,n,o,p,q,r,s,t,u,v,w;
    int k = 0;   
 

    ip_header = packet + ethernet_header_length;

    ip_header_length = ((*ip_header) & 0x0F); // second half

    ip_header_length = ip_header_length * 4; //32 bit segment so 4 bytes
    printf("IP header length in bytes: %d\n", ip_header_length);

    u_char protocol = *(ip_header + 9);

    if (protocol != IPPROTO_TCP) 
    {
        printf("Not a TCP packet.\n\n");
	    printf("*****************************************************************************\n");
        return;
    }

    tcp_header = packet + ethernet_header_length + ip_header_length;

    tcp_header_length = (*(tcp_header + 12) & 0xF0) >> 4; //first half

    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen - (ethernet_header_length + ip_header_length +  tcp_header_length);
    
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);
    printf("*****************************************************************************\n\n");
    printf("Printing Payload:\n");

	printf("Destination Mac Address: ");
	for(i = 0; i<5; i++)
	{    	
		printf("%X", packet[i]);
		printf(":");
	}
	printf("%X", packet[5]);

	printf("\nSource Mac Address: ");
	for(i = 6; i<11; i++)
   	 {    	
		printf("%X", packet[i]);
		printf(":");
   	 }
	printf("%X", packet[11]);

	printf("\nSource IP Address: ");
	for(i = 26; i<=28; i++)
   	 {    	
		printf("%d", packet[i]);
		printf(".");
   	 }
	printf("%d", packet[29]);

	printf("\nDestination IP Address: ");
	for(i = 30; i<=32; i++)
   	 {    	
		printf("%d", packet[i]);
		printf(".");
   	 }
	printf("%d", packet[33]);

	printf("\nSource Port Number: ");
	a = packet[34];
	b = packet[35];
	unsigned long num3;
	num3 = (a<<8) | b;
 	 printf("%ld", num3);
	
	printf("\nDestination Port Number: ");
   	
		r = packet[36];
		o = packet[37];
		unsigned long num4;
		num4 = (r<<8) | o;
   		 printf("%ld", num4);

if(num3 == 25 || num3 == 52030)
{	
	printf("\nSMTP: ");
	
	printf("\nResponse Code:- ");
	for(i = 54; i<=56; i++)
    	{    	
		d[i-54] = packet[i];  //Copy the individual char
    		printf("%c", packet[i]);
 	}
 		d[i-54] = '\0';  //null terminate the array
	printf("\nCommand:- ");
	for(i = 54; i<=57; i++)
    	{    	
		e[i-54] = packet[i];
    		printf("%c", packet[i]);
	}
		e[i-54] = '\0';
	printf("\nResponse Parameter:- ");
	for(i = 58; i<=104; i++)
    	{    	
		f[i-58] = packet[i];
    		printf("%c", packet[i]);
 	}
 		f[i-58] = '\0';
//printf("\nTime to live: %X\n", packet[22]);
	
 
	/*printf("\nWindow Size ValueWindow: ");
   	
	c = packet[48];
	h = packet[49];
	unsigned long num5;
	num5 = (c<<8) | h;
 	 g = num5;
	printf("%c", g);*/

if (mysql_query(con, "DROP TABLE IF EXISTS SMTP")) {
      finish_with_error(con);
  }


  if (mysql_query(con, "CREATE TABLE SMTP(Response_Code CHAR(250) , Command CHAR(250), Response_Parameter CHAR(250))")) {      
      finish_with_error(con);
  }
 
sprintf(query,"INSERT INTO SMTP (Response_Code, Command, Response_Parameter) VALUES ('%s','%s','%s')",d,e,f);
 printf("\nquery:- %s\n",query);

mysql_query(con, query);
}
}

	printf("\nSMTPS: ");
	
	printf("\nResponse Code: ");
	for(i = 66; i<=68; i++)
    	{    	
		x[i-66] = packet[i];
		printf("%c", packet[i]);
   	 }
		x[i-66] = '\0';

	printf("\nCommand: ");
	for(i = 66; i<=69; i++)
    	{    	
		y[i-66] = packet[i];
		printf("%c", packet[i]);
   	 }
		y[i-66] = '\0';

	printf("\nResponse Parameter: ");
	for(i = 70; i<=132; i++)
    	{    	
		z[i-70] = packet[i];
		printf("%c", packet[i]);
   	 }
		z[i-70] = '\0';

if (mysql_query(con, "DROP TABLE IF EXISTS SMTPS")) {
      finish_with_error(con);
  }


  if (mysql_query(con, "CREATE TABLE SMTPS(Response_Code CHAR(250) , Command CHAR(250), Response_Parameter CHAR(250))")) {      
      finish_with_error(con);
  }
 
sprintf(query,"INSERT INTO SMTPS(Response_Code, Command, Response_Parameter) VALUES ('%s','%s','%s')",x,y,z);

printf("\nquery:- %s\n",query);

mysql_query(con, query);
}
}

else if(num3 == 110 || num3 == 47261)
{
	printf("\nPOP: ");
	printf("\nResponse Indicator/Request Command: ");
	for(i = 66; i<=69; i++)
    	{    	
		x[i-66] = packet[i];
		printf("%c", packet[i]);
   	 }
		x[i-66] = '\0';

	printf("\nResponse Description: ");
	for(i = 70; i<=94; i++)
    	{    	
		y[i-70] = packet[i];
		printf("%c", packet[i]);
   	 }
		y[i-70] = '\0';

if (mysql_query(con, "DROP TABLE IF EXISTS POP")) {
      finish_with_error(con);
  }


  if (mysql_query(con, "CREATE TABLE POP(Response_Indicator CHAR(250) , Response_Description CHAR(250))")) {      
      finish_with_error(con);
  }
 
sprintf(query,"INSERT INTO POP (Response_Indicator, Response_Description) VALUES ('%s','%s')",x,y);
 printf("\nquery:- %s\n",query);

mysql_query(con, query);
}
}

else if(num3 == 22 || num3 == 59139)
{
	printf("\nSSHv2: ");
	printf("\nPadding Length: %d",packet[58]);
	e = packet[58];	

	printf("\nPacket length: "); //check here
	
	c = packet[54];
	q = packet[55];
	s = packet[56];
	h = packet[57];
	unsigned long num5;
	num5 = (c<<32) | (q<<16) |(s<<8) | h;
	
 	d = num5;
	printf("%ld", num5);

	printf("\nProtocol: ");
	for(i = 52; i<=315; i++)
    	{    	
		x[i-52] = packet[i];
		printf("%c", packet[i]);
   	 }
		x[i-52] = '\0';

	printf("\nCookie: ");
	for(i = 60; i<=75; i++)
    	{    	
		y[i-60] = packet[i];
		printf("%c", packet[i]);
   	 }
		y[i-60] = '\0';

	/*printf("\nKey Algorithm String: ");
	for(i = 80; i<=105; i++)
    	{    	
		printf("%c", (unsigned)packet[i]>126 ? '.' : packet[i]);
   	 }
	printf("\nHost Key Type: ");
	for(i = 68; i<=74; i++)
    	{    	
		printf("%c", (unsigned)packet[i]>126 ? '.' : packet[i]);
   	 }*/
	printf("\nRSA Public Exponent[e]: ");
	for(i = 79; i<=81; i++)
    	{    	
		z[i-79] = packet[i];
		printf("%c", packet[i]);
   	 }
		z[i-79] = '\0';

if (mysql_query(con, "DROP TABLE IF EXISTS SSHv2")) {
      finish_with_error(con);
  }


  if (mysql_query(con, "CREATE TABLE SSHv2(Packet_length INT(250) , Padding_length INT(250), Protocol CHAR(250), Cookie CHAR(250), RSA_public_exponent CHAR(250))")) {      
      finish_with_error(con);
  }
 
sprintf(query,"INSERT INTO SSHv2 (Packet_length, Padding_length, Protocol, Cookie, RSA_public_exponent) VALUES ('%d','%d','%s','%s','%s')",d,e,x,y,z);
printf("\nquery:- %s\n",query);

mysql_query(con, query);

}
    return;
}

int main(int argc, char *argv[]) 
{   
	char error_buffer[PCAP_ERRBUF_SIZE]; 
	pcap_t *handle = pcap_open_offline("smtp-test.pcap", error_buffer);  
    	char *device; //= "enp0s3";
    	int promiscuous = 0;
 	int snap_length = 1024;
 	int total_packet_count = -1;
    	u_char *my_arguments = NULL;
    	device = pcap_lookupdev(error_buffer);
    	printf("Device Name: %s\n", device);

    	if (device == NULL)
    	{
    		printf("unable to open: %s\n", error_buffer);
    		return(2);
    	}

con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  

  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }    
	pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);
   	
	return 0;
}	
