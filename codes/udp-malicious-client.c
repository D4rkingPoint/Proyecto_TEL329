#include "contiki.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ip/uip-udp-packet.h"
#include "sys/ctimer.h"
#ifdef WITH_COMPOWER
#include "powertrace.h"
#endif
#include <stdio.h>
#include <string.h>

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#define UDP_EXAMPLE_ID  190

//#define DEBUG DEBUG_FULL
#include "net/ip/uip-debug.h"

#ifndef PERIOD
#define PERIOD 50 /* increase it to avoid flooding */
#endif

#define START_INTERVAL		(15 * CLOCK_SECOND)
#define SEND_INTERVAL		(PERIOD * CLOCK_SECOND)
#define SEND_TIME		(random_rand() % (SEND_INTERVAL))
#define MAX_PAYLOAD_LEN		60

static struct uip_udp_conn *client_conn;
static uip_ipaddr_t server_ipaddr;

static int counter = 0;

/* uip6.c intercepting UDP packets */
extern uint8_t intercept_on;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/

static int seq_id;

static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  printf("Malicious Node IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      printLongAddr(&uip_ds6_if.addr_list[i].ipaddr);
      printf("\n");
      /* hack to make address "final" */
      if (state == ADDR_TENTATIVE) {
			uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
set_global_address(void)
{
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

#if 0
/* Mode 1 - 64 bits inline */
   uip_ip6addr(&server_ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 1);
#elif 1
/* Mode 2 - 16 bits inline */
  uip_ip6addr(&server_ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#else
/* Mode 3 - derived from server link-local (MAC) address */
  uip_ip6addr(&server_ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0x0250, 0xc2ff, 0xfea8, 0xcd1a); //redbee-econotag
#endif
}
/*-----------------------------------------------------------------------*/
static void
send_packet(void *ptr)
{
  char buf[MAX_PAYLOAD_LEN];

  seq_id++; // TODO: change this with a random var

  printf("DATA sending to %d 'Hello %d'\n",
         server_ipaddr.u8[sizeof(server_ipaddr.u8) - 1], seq_id);

  sprintf(buf, "Custom Data %d ", seq_id);
  uip_udp_packet_sendto(client_conn, buf, strlen(buf),
                        &server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic;
  static struct ctimer backoff_timer;

  PROCESS_BEGIN();

  PROCESS_PAUSE();

  set_global_address();
  
  printf("UDP NORMAL client process started nbr:%d routes:%d\n",
         NBR_TABLE_CONF_MAX_NEIGHBORS, UIP_CONF_MAX_ROUTES);

  print_local_addresses();

  /* new connection with remote host */
  client_conn = udp_new(NULL, UIP_HTONS(UDP_SERVER_PORT), NULL); 
  if(client_conn == NULL) {
    printf("No UDP connection available, exiting the process!\n");
    PROCESS_EXIT();
  }
  udp_bind(client_conn, UIP_HTONS(UDP_CLIENT_PORT)); 

  PRINTF("Created a connection with the LEGAL server ");
  PRINT6ADDR(&client_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
			UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

  /* UDP INTERCEPTING on APP Layer. Currently UDP is intercepted in uip6.c 
  server_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  //udp_bind(server_conn, UIP_HTONS(1234));
  udp_bind(server_conn, UIP_HTONS(5678));
  printf("Malicious sensor listening on UDP port %u\n", 
  		UIP_HTONS(server_conn->lport)); */
  
  etimer_set(&periodic, SEND_INTERVAL);
  while(1) {
    PROCESS_YIELD();
    
    if(ev == tcpip_event) {
    	printf("Malicious: tcpip_event! HANDLE IT...\n");
      //tcpip_handler();
    }

    if(etimer_expired(&periodic)) {
       etimer_reset(&periodic);
      
       /* sending regular data to sink (e.g. temperature measurements) */
       //ctimer_set(&backoff_timer, SEND_TIME, send_packet, NULL);

	    if (counter == 5){ //start malicious behavior
	   	 intercept_on = 1;
			 printf("DATA Intercept:%d, MALICIOUS_LEVEL:%d, GREY_SINK_HOLE_ATTACK %d\n", 
					intercept_on, MALICIOUS_LEVEL, GREY_SINK_HOLE_ATTACK);
			 printf("If GREY_SINK_HOLE_ATTACK == 0, it means BLACK_SINK_HOLE_ATTACK\n");
	    } 
	  
	    if (counter == 500){ // end malicious behavior
			 intercept_on = 0;
			 printf("DATA Intercept:%d........................\n",intercept_on);
	    }
/****** Nothing beyond this point ******************/
	    counter++;	  
	    PRINTF("Counter %d\n",counter); 
	    
    } //etimer (&periodic)
  }//end while
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
