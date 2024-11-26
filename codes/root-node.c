#include "contiki.h"
#include "net/rpl/rpl.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "sys/etimer.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ip/uip-debug.h"
#include "simple-udp.h"
#include "dev/leds.h"
#include <stdio.h>
#include <string.h>

#define UDP_PORT 1234
static struct simple_udp_connection unicast_connection;

/*---------------------------------------------------------------------------*/
PROCESS(root_node_process, "Root node");
AUTOSTART_PROCESSES(&root_node_process);
/*---------------------------------------------------------------------------*/
static void
receiver_callback(struct simple_udp_connection *c,
                  const uip_ipaddr_t *sender_addr,
                  uint16_t sender_port,
                  const uip_ipaddr_t *receiver_addr,
                  uint16_t receiver_port,
                  const uint8_t *data,
                  uint16_t datalen)
{
  printf("Message received from receiver: ");
  uip_debug_ipaddr_print(sender_addr);
  printf("\nData: '%s'\n", (char *)data);
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  printf("IPv6 addresses: \n");
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
static void
set_global_address(void)
{
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, 0xfd00, 0, 0, 0, 0x212, 0x7401, 0x0001, 0x0101); // Root address
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  print_local_addresses();
}
/*---------------------------------------------------------------------------*/
static void
create_rpl_dag(void)
{
  uip_ipaddr_t ipaddr;
  struct uip_ds6_addr *root_if;

  uip_ip6addr(&ipaddr, 0xfd00, 0, 0, 0, 0x212, 0x7401, 0x0001, 0x0101); // Root address
  root_if = uip_ds6_addr_lookup(&ipaddr);
  if(root_if != NULL) {
    rpl_dag_t *dag;
    uip_ipaddr_t prefix;

    rpl_set_root(RPL_DEFAULT_INSTANCE, &ipaddr);
    dag = rpl_get_any_dag();
    uip_ip6addr(&prefix, 0xfd00, 0, 0, 0, 0, 0, 0, 0);
    rpl_set_prefix(dag, &prefix, 64);
    printf("Created a new RPL DAG\n");
  } else {
    printf("Failed to create a new RPL DAG\n");
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(root_node_process, ev, data)
{
  PROCESS_BEGIN();

  set_global_address();
  create_rpl_dag();

  // Register UDP connection
  simple_udp_register(&unicast_connection, UDP_PORT, NULL, UDP_PORT, receiver_callback);

  printf("Root node started. Ready to receive messages.\n");

  while(1) {
    PROCESS_WAIT_EVENT();
  }

  PROCESS_END();
}
