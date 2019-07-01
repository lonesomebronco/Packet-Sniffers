#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include <mysql/mysql.h>

MYSQL *con;      //connecting to MYSQL service
MYSQL_RES *res;
MYSQL_ROW row;


#define SIZE 60

int a,b,c,g,h,i,l,m,n,o,p,q,r,s,t,u,v,w,aa,bb,cc,dd,ii,jj,kk,yy,zz,aaa,bbb,ccc,ddd,eee,fff,ggg,hhh,iii;
int k = 0; 
char d[100], e[100], f[100], j[100], x[100], y[100], z[100], gg[100], hh[100], xx[100], ww[100], vv[100];
char query[1024];
unsigned long num84,num3, num4;
unsigned long num101, num102, num103, num104, num105, num106, num107, num108, num109, num110, num111, num112, num113, num114, num115, num116, num117, num118, num119, num120;


void finish_with_error(MYSQL *con)     		//error in MYSQL
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

	/* Find start of IP header */

    ip_header = packet + ethernet_header_length;

    ip_header_length = ((*ip_header) & 0x0F); // second half

    ip_header_length = ip_header_length * 4; //32 bit segment so 4 bytes
    printf("IP header length in bytes: %d\n", ip_header_length);

    unsigned int protocol = *(ip_header + 9);

  printf("Protocol No.:-%d\n",protocol);

  if(protocol == 180)
  {
          printf("Protocol: UDP\n");

printf("\nSource IP Address:- ");
  for(i = 34; i<=36; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[37]);



  printf("\nDestination IP Address:- ");
  for(i = 38; i<=40; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[41]);


  printf("\nSource Port Number:- ");
  a = packet[43];
  b = packet[43];
  num3 = (a<<8) | b;
   printf("%ld", num3);
  
  printf("\nDestination Port Number:- ");
    
  r = packet[44];
  o = packet[45];

  num4 = (r<<8) | o;
    printf("%ld", num4);

    printf("\nChecksum:0x");
    {
      for(i=40; i<=41;i++)
      {
        printf("%x",packet[i]);
      }
    }
printf("\n[Checksum Status Unverified]");



if(num3 == 514 || num3 == 59194 || num4 == 601 || num3 == 601 || num4 == 6514 || num3 == 6514)
{
  printf("\nProtocol:- Syslog");


printf("\nMessage Truncated:");
{
  for(i=50; i<=371; i++)
  {

    d[i-50] = packet[i];  //Copy the individual char
    printf("%c", packet[i]);
  
  }
    d[i-50] = '\0';  //null terminate the array

}

  con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO SYSLOG (Truncated_Message) VALUES ('%s')",d); //inserting the values in the table

printf("\nquery:- %s\n",query);  //printing the query

mysql_query(con, query);
  }
}
switch(protocol) 
{
  case IPPROTO_TCP:
  
      printf("Protocol: TCP\n");
      printf("Destination Mac Address:- ");
  for(i = 0; i<5; i++)
  {     
    printf("%X", packet[i]);
    printf(":");
  }
  printf("%X", packet[5]);

  printf("\nSource Mac Address:- ");
  for(i = 6; i<11; i++)
     {      
    printf("%X", packet[i]);
    printf(":");
     }
  printf("%X", packet[11]);

  printf("\nSource IP Address:- ");
  for(i = 26; i<=28; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[29]);

  printf("\nDestination IP Address:- ");
  for(i = 30; i<=32; i++)
     {       unsigned long num84;
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[33]);

  printf("\nSource Port Number:- ");
  a = packet[34];
  b = packet[35];
  unsigned long num3;
  num3 = (a<<8) | b;
   printf("%ld", num3);
  
  printf("\nDestination Port Number:- ");
    
  r = packet[36];
  o = packet[37];
  unsigned long num4;
  num4 = (r<<8) | o;
    printf("%ld", num4);

    if(num3 == 25 || num3 == 52031 || num3 == 2525 || num3 == 587 ||num4 == 25 || num4 == 52031 || num4 == 2525 || num4 == 587 ) //num3 is the Source Port Number and in SMTP source port no. can be either 25 or 520303
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

    con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO SMTP (Response_Code, Command, Response_Parameter) VALUES ('%s','%s','%s')",d,e,f); //inserting the values in the table

printf("\nquery:- %s\n",query);  //printing the query

mysql_query(con, query);

  }  

  else if(num3 == 110 || num3 == 47261) //num3 is the Source Port Number and in POP source port no. can be either 110 or 47261
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

con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO POP (Response_Indicator, Response_Description) VALUES ('%s','%s')",x,y); //inserting the values in the table

printf("\nquery:- %s\n",query);

mysql_query(con, query);  //printing the query


}  


else if(num3 == 445 || num3 == 38166 || num3 == 49612)
  {
    printf("\nSMB");
    
    printf("\nCommand:");
    zz = packet[83];
    yy = packet[82];
    unsigned long num90;
    num90 = (yy<<8) | zz;
    printf("%ld",num90);
    if(num90 == 0)
    {
      printf("\nNegotiate Protocol(0)");
      printf("\nServer Component:");
    
      for(i = 71; i<=73; i++)
      {     
        gg[i-71] = packet[i];
        printf("%c", packet[i]);
      }
      printf("2");

        gg[i-71] = '\0';
        printf("\nCredit Charge:");
    
      cc = packet[75];
      dd = packet[76];
    unsigned long num97;
    num97 = (cc<<8) | dd;
    printf("%ld", num97);
    
  printf("\nCredit Requested:");
    
      ii = packet[84];
      jj = packet[85];
    unsigned long num96;
    num96 = (ii<<8) | jj;
    printf("%lX", num96);
    
    con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO SMB_Negotiate_Protocol0 (Server_Component, Credit_Charge, Credit_Requested) VALUES ('%s','%ld','%lX')",gg,num97,num96); //inserting the values in the table

printf("\nquery:- %s\n",query);

mysql_query(con, query);
    
    }

    else if(num90 == 256)
    {
      printf("\nSession Setup(1)");
      printf("\nServer Component:");
    
      for(i = 71; i<=73; i++)
      {     
        gg[i-71] = packet[i];
        printf("%c", packet[i]);
      }
      printf("2");
        gg[i-71] = '\0';

        printf("\nCredit Charge:");
    
      cc = packet[75];
      dd = packet[76];
    unsigned long num97;
    num97 = (cc<<8) | dd;
    printf("%ld", num97);
    
printf("\nCredit Requested:");
    
      ii = packet[84];
      jj = packet[85];
    unsigned long num96;
    num96 = (ii<<8) | jj;
    printf("%lX", num96);
    
    con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO SMB_Session_Setup1 (Server_Component, Credit_Charge, Credit_Requested) VALUES ('%s','%ld','%lX')",gg,num97,num96); //inserting the values in the table

printf("\nquery:- %s\n",query);  //printing the query

mysql_query(con, query);

    }
    else if(num90 == 768)
    {
      printf("\nTree Connect(3)");
      printf("\nServer Component:");
    
      for(i = 71; i<=73; i++)
      {     
        gg[i-71] = packet[i];
        printf("%c", packet[i]);
      }
      printf("2");

        gg[i-71] = '\0';

        printf("\nCredit Charge:");
    
      cc = packet[75];
      dd = packet[76];
    unsigned long num97;
    num97 = (cc<<8) | dd;
    printf("%ld", num97);
    
printf("\nCredit Requested:");
    
      ii = packet[84];
      jj = packet[85];
    unsigned long num96;
    num96 = (ii<<8) | jj;
    printf("%lX", num96);
    
    con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO SMB_Tree_Connect3 (Server_Component, Credit_Charge, Credit_Requested) VALUES ('%s','%ld','%lX')",gg,num97,num96); //inserting the values in the table

printf("\nquery:- %s\n",query);  //printing the query

mysql_query(con, query);

    }
 
     else if(num90 == 65535 )
    {
      printf("\nNegotiate Protocol(0x72)");
      printf("\nServer Component:");
    
      for(i = 59; i<=61; i++)
      {     
        vv[i-58] = packet[i];
        printf("%c", packet[i]);
      }
        vv[i-58] = '\0';

        printf("\nNT_Status:0x");
    
      for(i=63; i<=66; i++)
      {

        gg[i-63] = packet[i];
        printf("%X", packet[i]);
      }
        gg[i-63] = '\0';
    
printf("\nSignature:");
    
       for(i=72; i<=79; i++)
      {
        hh[i-72] = packet[i];
        printf("%X", packet[i]);
      }
      hh[i-72] = '\0';
    
    printf("\nReserved:");
    aaa = packet[80];
    bbb = packet[81];

    num101 = (aaa<<8) | bbb;   
    printf("%lX",num101);

    printf("\nTree ID:");
    
      ii = packet[82];
      jj = packet[83];
    unsigned long num96;
    num96 = (ii<<8) | jj;
    printf("%ld", num96);
    
    printf("\nProcess ID: ");
    
      cc = packet[85];
      dd = packet[84];
    unsigned long num95;
    num95 = (cc<<8) | dd;
    printf("%ld", num95);
    
    printf("\nUser ID: ");
    
      aa = packet[86];
      bb = packet[87];
    unsigned long num94;
    num94 = (aa<<8) | bb;
    printf("%ld", num94);
    
    printf("\nWord Count: %d", packet[88]);
    int num64 = packet[88];
    
con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO SMB_Negotiate_Protocol0x72 (Server_Component, NT_Status, Signature, Reserved, TreeID, ProcessID, UserID, Word_Count) VALUES ('%s','%s','%s','%lX','%ld','%ld','%ld','%d')",vv,gg,hh,num101,num96,num95,num94,num64); //inserting the values in the table

printf("\nquery:- %s\n",query);  //printing the query

mysql_query(con, query);

  }
    else
    {
      printf("\nEncrypted SMB3");
      printf("\nServer Component:");
    
      for(i = 71; i<=73; i++)
      {     
        gg[i-71] = packet[i];
        printf("%c", packet[i]);
      }
      printf("2_TRANSFORM");
    
        gg[i-71] = '\0';
        printf("\nSignature:");
      
          for(i = 74; i<=89; i++)
         {     
           xx[i-74] = packet[i];
           printf("%X", packet[i]);
         }
          xx[i-74] = '\0';
        
        printf("\nNonce:");
        
          for(i = 90; i<=105; i++)
         {     
           ww[i-90] = packet[i];
           printf("%X", packet[i]);
         }
          ww[i-90] = '\0';
        
        printf("\nMessage Size:%d", packet[106]);
        a =  packet[106];
        
        printf("\nReserved:");
        
          ii = packet[110];
          jj = packet[111];
          unsigned long num95;
          num95 = (ii<<8) | jj;
          printf("%lX", num95);
    
        
        printf("\nData:");
        
          for(i=122; i<=267; i++)
          {
            printf("%X", packet[i]);
          }
        con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO Encrypted_SMB3 (Response_Code, Signature, Nonce, Message_Size, Reserved) VALUES ('%s','%s','%s','%d','%lX')",gg,xx,ww,a,num95); //inserting the values in the table

printf("\nquery:- %s\n",query);  //printing the query

mysql_query(con, query);

  }

    break;
    



case IPPROTO_UDP:
      printf("Protocol: UDP\n");

printf("\nSource IP Address:- ");
  for(i = 34; i<=36; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[37]);

  printf("\nDestination IP Address:- ");
  for(i = 38; i<=40; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[41]);


  printf("\nSource Port Number:- ");
  a = packet[34];
  b = packet[35];
  num3 = (a<<8) | b;
   printf("%ld", num3);
  
  printf("\nDestination Port Number:- ");
    
  r = packet[36];
  o = packet[37];

  num4 = (r<<8) | o;
    printf("%ld", num4);

printf("\nLength:- ");
    
  aa = packet[38];
  bb = packet[39];
  unsigned long num76;
  num4 = (bb<<8) | aa;
    printf("%d", packet[39]);    

    printf("\nChecksum:0x");
    {
      for(i=40; i<=41;i++)
      {
        printf("%x",packet[i]);
      }
    }
printf("\n[Checksum Status Unverified]");



if(num3 == 514 || num3 == 59194 || num4 == 601 || num3 == 601 || num4 == 6514 || num3 == 6514)
{
  printf("\nProtocol:- Syslog");


printf("\nMessage Truncated:");
{
  for(i=47; i<=371; i++)
  {

    d[i-54] = packet[i];  //Copy the individual char
    printf("%c", packet[i]);
  
  }
    d[i-54] = '\0';  //null terminate the array

}

}

      return;
   


    case IPPROTO_ICMP:
      printf("   Protocol: ICMP\n");
      aa = packet[46];
      bb = packet[47];
      cc = packet[48];
      dd = packet[49];
      ii = packet[50];
      jj = packet[51];
      kk = packet[52];
      yy = packet[53];
      if((aa == 1 && bb == 1 && cc == 1 && dd== 1) || (ii == 1 && jj == 1 && kk == 1 && yy == 1))
      {
           printf("\nSource IP Address:- ");
  for(i = 46; i<=48; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[49]);

  printf("\nDestination IP Address:- ");
  for(i = 50; i<=52; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[53]); 
  printf("\nSource IP Address:- ");
  for(i = 26; i<=28; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[29]);

  printf("\nDestination IP Address:- ");
  for(i = 30; i<=32; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[33]);
      }
  else
  {
    printf("\nSource IP Address:- ");
  for(i = 16; i<=18; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[19]);

  printf("\nDestination IP Address:- ");
  for(i = 20; i<=22; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[23]);

  printf("\nTime to live is:- %d", packet[12]);

  printf("\nHeader Checksum:-0x");
      for(i = 14; i<=15; i++)
      {
        printf("%x",packet[i]);
      }
  printf("(Validation Disabled)\n");
  
printf("ICMP:\n");
  
printf("\nTYPE:- ");
printf("%X",packet[24]);
num106 = packet[24];
printf("(Echo(ping)Request)\n");
  

printf("\nCODE:- ");
printf("%X\n",packet[25]);
num105 = packet[25];

printf("\nCHECKSUM:- ");
printf("0x");
    
        ggg = packet[26];
        hhh = packet[27];
        num104 = (ggg<<8) | hhh;
        printf("%lX", num104);

  printf("\n");

printf("\nIdentifier(BE/LE):- ");
printf("0x");   
        ccc = packet[28];
        ddd = packet[29];
        num102 = (ccc<<8) | ddd;
        printf("%lX", num102);

printf("\n");

printf("\nSEQ_NO(BE/LE):- ");
printf("0x");
  
        eee = packet[30];
        fff = packet[31];
        num103 = (eee<<8) | fff;
        printf("%lX", num103);
      printf("%X", packet[i]);

printf("\n");    

  printf("\nDATA:- ");
  for(i = 32; i<=103; i++)
  {     
          printf("%X", packet[i]);
  }

printf("\n");

printf("\nLENGTH OF DATA is:- ");
printf("72\n");
num107 = 72;
con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO ICMP (Identifier, SEQ_NO, Type, Code, Checksum, Length_of_data) VALUES ('%lX','%lX','%lX','%lX','%lX','%ld')",num102,num103,num106,num105,num104,num107); //inserting the values in the table

printf("\nquery:- %s\n",query);

mysql_query(con, query);
printf("\n");
}
      break;

    case IPPROTO_IP:
      printf("Protocol: IP\n");
      return;
      case IPPROTO_IGMP:
      printf("Protocol: IGMP\n");
      printf("\nSource IP Address:- ");
  for(i = 26; i<=28; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[29]); 

  printf("\nDestination IP Address:- ");
  for(i = 30; i<=32; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[33]); 
unsigned long int num85;
num85 = packet[38];
num84 = packet[41];
if(num85 == 17)
{
  printf("\nMembership Query(0x11)");
  printf("\nChecksum: 0x");
  {
    for(i = 36; i<=37; i++)
      {
        gg[i-36] = packet[i];
        printf("%x",packet[i]);
      }
      gg[i-36] = '\0';
  }
  printf("\nMulticast Address:- ");
  
    for(i = 42; i<=44; i++)
    {    

      printf("%d", packet[i]);
      printf(".");
    }
    printf("%d", packet[45]); 
    
    for(i = 42; i<=45; i++)
    {    
      xx[i-42] = packet[i];
    }
      xx[i-42] = '\0'; 

    con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO IGMP_Membership_Query0x11 (Checksum, Multicast_Address) VALUES ('%s','%s')",gg,xx); //inserting the values in the table

printf("\nquery:- %s\n",query);

mysql_query(con, query);
  
}
else if(num84 = 22)
{
  printf("\nType: Membership Report(0x16)");
printf("\nChecksum: 0x");

    for(i = 40; i<=41; i++)
      {
        gg[i-40] = packet[i];
        printf("%x",packet[i]);
      }
      gg[i-40] = '\0';

   printf("\nMulticast Address:- ");
  for(i = 42; i<=44; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[45]); 

  for(i = 42; i<=45; i++)
     {      
      xx[i-42] = packet[i];
     }
      xx[i-42] = '\0';

    con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO IGMP_Membership_Report0x16 (Checksum, Multicast_Address) VALUES ('%s','%s')",gg,xx); //inserting the values in the table

printf("\nquery:- %s\n",query);

mysql_query(con, query);
  
}

else if(num84 = 23)
{
  printf("\nType: Leave Group(0x17)");
printf("\nChecksum: 0x");
  
    for(i = 40; i<=41; i++)
      {
        gg[i-40] = packet[i];
        printf("%x",packet[i]);
      }
            gg[i-40] = '\0';
  
  printf("\nChecksum Status Good");

  printf("\nMulticast Address:- ");
  for(i = 42; i<=44; i++)
     {      
       printf("%d", packet[i]);
        printf(".");
     }
  printf("%d", packet[45]); 

 for(i = 42; i<=45; i++)
     {      
        xx[i-42] = packet[i];
     }
        xx[i-42] = '\0';

  con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO IGMP_Leave_Group0x17 (Checksum, Multicast_Address) VALUES ('%s','%s')",gg,xx); //inserting the values in the table

printf("\nquery:- %s\n",query);

mysql_query(con, query);
  
}
if(num85 == 18)
{
  printf("\nMembership Report(0x12)");
  printf("\nChecksum: 0x");
  {
    for(i = 40; i<=41; i++)
      {
        gg[i-40] = packet[i];
        printf("%x",packet[i]);
      }
      gg[i-40] = '\0';
  }
  printf("\nChecksum Status Good");
  printf("\nMulticast Address:- ");
  for(i = 42; i<=44; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
  printf("%d", packet[45]); 

  for(i = 42; i<=45; i++)
     {      
        xx[i-42] = packet[i];
     }
        xx[i-42] = '\0';

con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO IGMP_Membership_Report0x12 (Checksum, Multicast_Address) VALUES ('%s','%s')",gg,xx); //inserting the values in the table

printf("\nquery:- %s\n",query);

mysql_query(con, query);


}

else
{  
 printf("\nType");
      kk = packet[38];
      printf(" %X",kk);

      printf("\nReserved %X", packet[39]);
      aa = packet[39];

      printf("\nChecksum:-0x");
      for(i = 40; i<=41; i++)
      {
        gg[i-40] = packet[i];
        printf("%x",packet[i]);
      }
        gg[i-40] = '\0';
      printf("\nMulticast Address:- ");
  for(i = 42; i<=44; i++)
     {      
    printf("%d", packet[i]);
    printf(".");
     }
       printf("%d", packet[45]); 

     for(i = 42; i<=45; i++)
     {      
        xx[i-42] = packet[i];
     }
        xx[i-42] = '\0';

     con = mysql_init(NULL);

 if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  
        //logging into mysql databse Protocols                                       
  if (mysql_real_connect(con, "localhost", "root", "", 
          "Protocols", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }   
sprintf(query,"INSERT INTO IGMP_Type (Checksum, Multicast_Address, Reseved, Type) VALUES ('%s','%s', '%X', '%X')",gg,xx,aa,kk); //inserting the values in the table

printf("\nquery:- %s\n",query);

mysql_query(con, query);

}
   return;
   
      case IPPROTO_ENCAP:
      printf("here");
      return;
default:
     printf("No Protocol");
  }
  
	/* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */

    tcp_header = packet + ethernet_header_length + ip_header_length;

    tcp_header_length = (*(tcp_header + 12) & 0xF0) >> 4; //first half

    tcp_header_length = tcp_header_length * 4;
    printf("\nTCP header length in bytes: %d\n", tcp_header_length);

/* Add up all the header sizes to find the payload offset */

    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen - (ethernet_header_length + ip_header_length +  tcp_header_length);
    
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);
    printf("*****************************************************************************\n\n");
    
    }
  }

// printf("///////////////////////////////////////////////////////////////////////////////");

int main(int argc, char *argv[]) 
{    
  char error_buffer[PCAP_ERRBUF_SIZE]; 
  pcap_t *handle;  
      char *device; //= "enp0s3";
      int promiscuous = 0;
      int snap_length = 1024;
      int total_packet_count = -1;

      u_char *my_arguments;

      device = pcap_lookupdev(error_buffer);

      printf("Device Name: %s\n", device);

      if (device == NULL)
      {
        printf("unable to open: %s\n", error_buffer);
        return(2);
      }

  handle = pcap_open_live(device, snap_length, 0, 1024, error_buffer);
  
  pcap_loop(handle, total_packet_count, my_packet_handler, con);


    mysql_close(con);   //closing MYSQL connection

  printf("Sniffing Complete\n");    //Sniffing

    exit(0);

      
  return 0;
}
