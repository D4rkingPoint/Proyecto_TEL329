#include "contiki.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "sys/etimer.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ip/uip-debug.h"
#include "simple-udp.h"
#include <stdio.h>
#include <string.h>

#define UDP_PORT 1234
#define SEND_INTERVAL (10 * CLOCK_SECOND)
#define TEMP_MIN 20
#define TEMP_MAX 35

static struct simple_udp_connection unicast_connection;
static uip_ipaddr_t receiver_addr;

/*---------------------------------------------------------------------------*/
PROCESS(sender_node_process, "Sender node process");
AUTOSTART_PROCESSES(&sender_node_process);
/*---------------------------------------------------------------------------*/
static void
set_global_address(void)
{
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, 0xfd00, 0, 0, 0, 0x212, 0x7403, 0x0003, 0x0303); // Sender address
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  printf("IPv6 addresses: \n");
  int i;
  uint8_t state;
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      uip_debug_ipaddr_print(&uip_ds6_if.addr_list[i].ipaddr);
      printf("\n");
    }
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sender_node_process, ev, data)
{
  static struct etimer periodic_timer;
  static char message[50];
  static int temperature;

  PROCESS_BEGIN();

  set_global_address();

  // Set the receiver's address
  uip_ip6addr(&receiver_addr, 0xfd00, 0, 0, 0, 0x212, 0x7402, 0x0002, 0x0202); // Receiver address

  simple_udp_register(&unicast_connection, UDP_PORT, NULL, UDP_PORT, NULL);

  printf("Sender node started. Ready to send data.\n");

  etimer_set(&periodic_timer, SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    // Generate random temperature
    temperature = TEMP_MIN + (random_rand() % (TEMP_MAX - TEMP_MIN + 1));

    // Format message
    snprintf(message, sizeof(message), "Sender ID%d : T:%dC", linkaddr_node_addr.u8[0], temperature);


    // Send message
    printf("Sending unicast to ");
    uip_debug_ipaddr_print(&receiver_addr);
    printf("\nMessage: %s\n", message);
    simple_udp_sendto(&unicast_connection, message, strlen(message) + 1, &receiver_addr);

    etimer_reset(&periodic_timer);
  }

  PROCESS_END();
}
