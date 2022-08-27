/*
 * Copyright (C) 2013 Christoph Leitner <c.leitner@student.uibk.ac.at>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "contiki.h"
#include "dev/leds.h"
#include "dev/button-sensor.h"
#include "dev/light-sensor.h"
#include "net/netstack.h"
#include "net/rime/rime.h"
#include "net/rime/channel.h"
#include "net/rime/broadcast.h"
#include "serial-shell.h"
#include "shell.h"
#include "lib/memb.h"
#include "lib/list.h"
#include <stdio.h>
#include <string.h>

#define NUM_BROADCASTS 10
#define NUM_UNICASTS 10
#define NUM_RUNICASTS 10

struct broadcast_entry {
  struct broadcast_entry *next;
  struct broadcast_conn c;
  uint16_t channel;
};

struct unicast_entry {
  struct unicast_entry *next;
  struct unicast_conn c;
  uint16_t channel;
};

struct runicast_entry {
  struct runicast_entry *next;
  struct runicast_conn c;
  uint16_t channel;
};

// dummy information that is sent
static const char payload[] = "Hello GNU Radio!";
static char in_buf[256];

static void broadcast_received(struct broadcast_conn *c, const linkaddr_t *from);
static void broadcast_sent(struct broadcast_conn *c, int status, int num_tx);
static struct broadcast_conn broadcast_connection;
static const struct broadcast_callbacks broadcast_callback = {
	broadcast_received, broadcast_sent
};

static void unicast_received(struct unicast_conn *c, const linkaddr_t *from);
static void unicast_sent(struct unicast_conn *c, int status, int num_tx);
static const struct unicast_callbacks unicast_callback = {
	unicast_received, unicast_sent
};

static void runicast_received(struct runicast_conn *c, const linkaddr_t *from, int seqno);
static void runicast_sent(struct runicast_conn *c, const linkaddr_t *to, uint8_t retransmissions);
static const struct runicast_callbacks runicast_callback = {
	runicast_received, runicast_sent
};


LIST(broadcast_list);
MEMB(broadcast_mem, struct broadcast_entry, NUM_BROADCASTS);

LIST(unicast_list);
MEMB(unicast_mem, struct unicast_entry, NUM_UNICASTS);

LIST(runicast_list);
MEMB(runicast_mem, struct runicast_entry, NUM_RUNICASTS);


PROCESS(spam_process, "spam process");
PROCESS(button_process, "button process");

/* ----------------Shell Commands----------------------------*/
PROCESS(shell_bc_open_process, "bc open");
SHELL_COMMAND(bc_open_command,
	      "bc_open",
	      "bc_open <channel>: open broadcast connection on specified channel",
	      &shell_bc_open_process);

PROCESS(shell_bc_close_process, "bc close");
SHELL_COMMAND(bc_close_command,
	      "bc_close",
	      "bc_close <channel>: close broadcast connection on specified channel",
	      &shell_bc_close_process);

PROCESS(shell_bc_send_process, "bc send");
SHELL_COMMAND(bc_send_command,
	      "bc_send",
	      "bc_send <channel> <message>: sends a message using broadcast on the specified channel",
	      &shell_bc_send_process);

PROCESS(shell_uc_open_process, "uc open");
SHELL_COMMAND(uc_open_command,
	      "uc_open",
	      "uc_open <channel>: open unicast connection on specified channel",
	      &shell_uc_open_process);

PROCESS(shell_uc_close_process, "uc close");
SHELL_COMMAND(uc_close_command,
	      "uc_close",
	      "uc_close <channel>: close unicast connection on specified channel",
	      &shell_uc_close_process);

PROCESS(shell_uc_send_process, "uc send");
SHELL_COMMAND(uc_send_command,
	      "uc_send",
	      "uc_send <channel> <target> <message>: sends a message to <target> using unicast on the specified channel",
	      &shell_uc_send_process);

PROCESS(shell_ruc_open_process, "ruc open");
SHELL_COMMAND(ruc_open_command,
	      "ruc_open",
	      "ruc_open <channel>: open reliable unicast connection on specified channel",
	      &shell_ruc_open_process);

PROCESS(shell_ruc_close_process, "ruc close");
SHELL_COMMAND(ruc_close_command,
	      "ruc_close",
	      "ruc_close <channel>: close reliable unicast connection on specified channel",
	      &shell_ruc_close_process);

PROCESS(shell_ruc_send_process, "uc send");
SHELL_COMMAND(ruc_send_command,
	      "ruc_send",
	      "ruc_send <channel> <target> <message>: sends a message to <target> using reliable unicast on the specified channel",
	      &shell_ruc_send_process);
/*-----------------------------------------------------------*/
AUTOSTART_PROCESSES(&button_process);

static void
update_leds() {
	static uint8_t i = 0;
	i++;
	leds_off(LEDS_ALL);
	switch(i % 3) {
	case 0:
		leds_on(LEDS_RED);
		break;
	case 1:
		leds_on(LEDS_GREEN);
		break;
	case 2:
		leds_on(LEDS_BLUE);
		break;
	}
}

static void
broadcast_sent(struct broadcast_conn *c, int status, int num_tx) {
	update_leds();
}

static void
broadcast_received(struct broadcast_conn *c, const linkaddr_t *from) {
	char *pkt = packetbuf_dataptr();
	static int8_t rssi;
	rssi = packetbuf_attr(PACKETBUF_ATTR_RSSI);

	printf("broadcast packet received from %d.%d on channel %d with RSSI %d, LQI %u\n",
			from->u8[0], from->u8[1],
			c->c.channel.channelno,
			rssi,
			packetbuf_attr(PACKETBUF_ATTR_LINK_QUALITY));

	printf("-------------------------------\n");
	int i;
	for(i = 0; i < packetbuf_datalen(); i++) {
		printf("%c", pkt[i]);
	}
	printf("\n");
	printf("-------------------------------\n");

}

static void
unicast_sent(struct unicast_conn *c, int status, int num_tx){
	update_leds();
}

static void
unicast_received(struct unicast_conn *c, const linkaddr_t *from){
	char *pkt = packetbuf_dataptr();
	static int8_t rssi;
	rssi = packetbuf_attr(PACKETBUF_ATTR_RSSI);

	printf("unicast packet received from %d.%d on channel %d with RSSI %d, LQI %u\n",
			from->u8[0], from->u8[1],
			c->c.c.channel.channelno,
			rssi,
			packetbuf_attr(PACKETBUF_ATTR_LINK_QUALITY));

	printf("-------------------------------\n");
	int i;
	for(i = 0; i < packetbuf_datalen(); i++) {
		printf("%c", pkt[i]);
	}
	printf("\n");
	printf("-------------------------------\n");
}

static void
runicast_sent(struct runicast_conn *c, const linkaddr_t *to, uint8_t retransmissions){
	printf("runicast sent to %d.%d on channel %d. retransmissions: %d\n",
		to->u8[0], to->u8[1], c->c.c.c.c.channel.channelno, retransmissions);
}

static void
runicast_received(struct runicast_conn *c, const linkaddr_t *from, int seqno){
	char *pkt = packetbuf_dataptr();
	static int8_t rssi;
	rssi = packetbuf_attr(PACKETBUF_ATTR_RSSI);

	printf("reliable unicast packet received from %d.%d on channel %d with RSSI %d, LQI %u\n",
			from->u8[0], from->u8[1],
			c->c.c.c.c.channel.channelno,
			rssi,
			packetbuf_attr(PACKETBUF_ATTR_LINK_QUALITY));

	printf("-------------------------------\n");
	int i;
	for(i = 0; i < packetbuf_datalen(); i++) {
		printf("%c", pkt[i]);
	}
	printf("\n");
	printf("-------------------------------\n");
}

void
shell_sdr_init(void)
{
  memb_init(&broadcast_mem);
  memb_init(&unicast_mem);
  memb_init(&runicast_mem);
  list_init(broadcast_list);
  list_init(unicast_list);
  list_init(runicast_list);
  serial_shell_init();
  shell_register_command(&bc_open_command);
  shell_register_command(&bc_close_command);
  shell_register_command(&bc_send_command);
  shell_register_command(&uc_open_command);
  shell_register_command(&uc_close_command);
  shell_register_command(&uc_send_command);
  shell_register_command(&ruc_open_command);
  shell_register_command(&ruc_close_command);
  shell_register_command(&ruc_send_command);
}

	
PROCESS_THREAD(shell_bc_open_process, ev, data)
{
  uint16_t channel;
  long channel_long;
  const char *next;
  char buf[6];
  PROCESS_BEGIN();

  channel_long = shell_strtolong((char *)data, &next);
  if(channel_long <= 0 || channel_long > 65535){
    shell_output_str(&bc_open_command, "channel has to be in range of [1-65535]", "");
    PROCESS_EXIT();
  }
  channel = (uint16_t) channel_long;
  snprintf(buf, sizeof(buf), "%d", channel);

  struct broadcast_entry *to_add = memb_alloc(&broadcast_mem);
  list_add(broadcast_list, to_add);
  to_add->channel = channel;
  broadcast_open(&to_add->c, channel, &broadcast_callback);
  shell_output_str(&bc_open_command, "opened broadcast connection on channel: ", buf);

  PROCESS_END();
}

PROCESS_THREAD(shell_bc_close_process, ev, data)
{
  uint16_t channel;
  long channel_long;
  const char *next;
  char buf[6];
  PROCESS_BEGIN();

  channel_long = shell_strtolong((char *)data, &next);
  if(channel_long <= 0 || channel_long > 65535){
    shell_output_str(&bc_close_command, "channel has to be in range of [1-65535]", "");
    PROCESS_EXIT();
  }
  channel = (uint16_t) channel_long;
  snprintf(buf, sizeof(buf), "%d", channel);
  struct broadcast_entry *e = list_head(broadcast_list);
  while(e != NULL){
    if(e->channel == channel){
      struct broadcast_entry *to_remove = e;
      e = e->next;
      broadcast_close(&to_remove->c);
      list_remove(broadcast_list, to_remove);
      memb_free(&broadcast_mem, to_remove);
      shell_output_str(&bc_close_command, "closed broadcast connection on channel: ", buf);
      PROCESS_EXIT();
    }
  }
  shell_output_str(&bc_close_command, "bc_close error: channel not open","");

  PROCESS_END();
}

PROCESS_THREAD(shell_bc_send_process, ev, data)
{
  uint16_t channel;
  long channel_long;
  const char *next;
  char buf[6];
  char msg_buf[128];
  size_t msg_size;
  PROCESS_BEGIN();

  channel_long = shell_strtolong((char *)data, &next);
  if(channel_long <= 0 || channel_long > 65535){
    shell_output_str(&bc_send_command, "channel has to be in range [1-65535]", "");
    PROCESS_EXIT();
  }
  channel = (uint16_t) channel_long;
  snprintf(buf, sizeof(buf), "%d", channel);

  msg_size = strlen(next);
  if(msg_size == 0){
    shell_output_str(&bc_send_command, "bc_send usage:", bc_send_command.description);
    PROCESS_EXIT();
  }

  memcpy(msg_buf, next, msg_size);

  packetbuf_copyfrom(&msg_buf, msg_size);

  struct broadcast_entry *e = NULL;
  for(e = list_head(broadcast_list); e != NULL; e = e->next){
    if(e->channel == channel){
      broadcast_send(&e->c);
      shell_output_str(&bc_send_command, "sent broadcast message on channel: ", buf);
      PROCESS_EXIT();
    }
  }
  shell_output_str(&bc_send_command, "bc_send error: channel not open, use bc_open <channel> before trying to send","");

  PROCESS_END();
}

PROCESS_THREAD(shell_uc_open_process, ev, data)
{
  uint16_t channel;
  long channel_long;
  const char *next;
  char buf[6];
  PROCESS_BEGIN();
  channel_long = shell_strtolong((char *)data, &next);
  if(channel_long <= 0 || channel_long > 65535){
    shell_output_str(&uc_open_command, "channel has to be in range of [1-65535]", "");
    PROCESS_EXIT();
  }
  channel = (uint16_t) channel_long;
  snprintf(buf, sizeof(buf), "%d", channel);

  struct unicast_entry *to_add = memb_alloc(&unicast_mem);
  list_add(unicast_list, to_add);
  to_add->channel = channel;
  unicast_open(&to_add->c, channel, &unicast_callback);
  shell_output_str(&uc_open_command, "opened unicast connection on channel: ", buf);

  PROCESS_END();
}

PROCESS_THREAD(shell_uc_close_process, ev, data)
{
  uint16_t channel;
  long channel_long;
  const char *next;
  char buf[6];
  PROCESS_BEGIN();

  channel_long = shell_strtolong((char *)data, &next);
  if(channel_long <= 0 || channel_long > 65535){
    shell_output_str(&uc_close_command, "channel has to be in range of [1-65535]", "");
    PROCESS_EXIT();
  }
  channel = (uint16_t) channel_long;
  snprintf(buf, sizeof(buf), "%d", channel);
  struct unicast_entry *e = list_head(unicast_list);
  while(e != NULL){
    if(e->channel == channel){
      struct unicast_entry *to_remove = e;
      e = e->next;
      unicast_close(&to_remove->c);
      list_remove(unicast_list, to_remove);
      memb_free(&unicast_mem, to_remove);
      shell_output_str(&uc_close_command, "closed unicast connection on channel: ", buf);
      PROCESS_EXIT();
    }
  }
  shell_output_str(&uc_close_command, "uc_close error: channel not open","");

  PROCESS_END();
}

PROCESS_THREAD(shell_uc_send_process, ev, data)
{
  uint16_t channel;
  long channel_long;
  const char *next;
  linkaddr_t target;
  long rime_long;
  char buf[6];
  char msg_buf[128];
  size_t msg_size;
  PROCESS_BEGIN();

  channel_long = shell_strtolong((char *)data, &next);
  if(channel_long <= 0 || channel_long > 65535){
    shell_output_str(&uc_send_command, "channel has to be in range [1-65535]", "");
    PROCESS_EXIT();
  }
  channel = (uint16_t) channel_long;
  snprintf(buf, sizeof(buf), "%d", channel);

  rime_long = shell_strtolong(next, &next);
  if(rime_long < 0 || rime_long > 255){
    shell_output_str(&uc_send_command, "rimeaddress[0] has to be in range [0-255]","");
    PROCESS_EXIT();
  }
  if(*next != '.'){
    shell_output_str(&uc_send_command, "wrong target address format, need u8[0].u8[1]","");
    PROCESS_EXIT();
  }
  target.u8[0] = (uint8_t) rime_long;
  ++next;
  rime_long = shell_strtolong(next, &next);
  if(rime_long < 0 || rime_long > 255){
    shell_output_str(&uc_send_command, "rimeaddress[1] has to be in range [0-255]","");
    PROCESS_EXIT();
  }
  target.u8[1] = (uint8_t) rime_long;

  while(*next == ' '){
    next++;
  }

  msg_size = strlen(next);
  if(msg_size == 0){
    shell_output_str(&uc_send_command, "uc_send usage:", uc_send_command.description);
    PROCESS_EXIT();
  }

  memcpy(msg_buf, next, msg_size);

  packetbuf_copyfrom(&msg_buf, msg_size);

  struct unicast_entry *e = NULL;
  for(e = list_head(unicast_list); e != NULL; e = e->next){
    if(e->channel == channel){
      unicast_send(&e->c, &target);
      shell_output_str(&uc_send_command, "sent unicast message on channel: ", buf);
      PROCESS_EXIT();
    }
  }
  shell_output_str(&uc_send_command, "uc_send error: channel not open, use uc_open <channel> before trying to send","");

  PROCESS_END();
}

PROCESS_THREAD(shell_ruc_open_process, ev, data)
{
  uint16_t channel;
  long channel_long;
  const char *next;
  char buf[6];
  PROCESS_BEGIN();
  channel_long = shell_strtolong((char *)data, &next);
  if(channel_long <= 0 || channel_long > 65535){
    shell_output_str(&ruc_open_command, "channel has to be in range of [1-65535]", "");
    PROCESS_EXIT();
  }
  channel = (uint16_t) channel_long;
  snprintf(buf, sizeof(buf), "%d", channel);

  struct runicast_entry *to_add = memb_alloc(&runicast_mem);
  list_add(runicast_list, to_add);
  to_add->channel = channel;
  runicast_open(&to_add->c, channel, &runicast_callback);
  shell_output_str(&ruc_open_command, "opened reliable unicast connection on channel: ", buf);

  PROCESS_END();
}

PROCESS_THREAD(shell_ruc_close_process, ev, data)
{
  uint16_t channel;
  long channel_long;
  const char *next;
  char buf[6];
  PROCESS_BEGIN();

  channel_long = shell_strtolong((char *)data, &next);
  if(channel_long <= 0 || channel_long > 65535){
    shell_output_str(&ruc_close_command, "channel has to be in range of [1-65535]", "");
    PROCESS_EXIT();
  }
  channel = (uint16_t) channel_long;
  snprintf(buf, sizeof(buf), "%d", channel);
  struct runicast_entry *e = list_head(runicast_list);
  while(e != NULL){
    if(e->channel == channel){
      struct runicast_entry *to_remove = e;
      e = e->next;
      runicast_close(&to_remove->c);
      list_remove(runicast_list, to_remove);
      memb_free(&runicast_mem, to_remove);
      shell_output_str(&ruc_close_command, "closed unicast connection on channel: ", buf);
      PROCESS_EXIT();
    }
  }
  shell_output_str(&ruc_close_command, "uc_close error: channel not open","");

  PROCESS_END();
}

PROCESS_THREAD(shell_ruc_send_process, ev, data)
{
  uint16_t channel;
  long channel_long;
  const char *next;
  linkaddr_t target;
  long rime_long;
  char buf[6];
  char msg_buf[128];
  size_t msg_size;
  PROCESS_BEGIN();

  channel_long = shell_strtolong((char *)data, &next);
  if(channel_long <= 0 || channel_long > 65535){
    shell_output_str(&ruc_send_command, "channel has to be in range [1-65535]", "");
    PROCESS_EXIT();
  }
  channel = (uint16_t) channel_long;
  snprintf(buf, sizeof(buf), "%d", channel);

  rime_long = shell_strtolong(next, &next);
  if(rime_long < 0 || rime_long > 255){
    shell_output_str(&ruc_send_command, "rimeaddress[0] has to be in range [0-255]","");
    PROCESS_EXIT();
  }
  if(*next != '.'){
    shell_output_str(&ruc_send_command, "wrong target address format, need u8[0].u8[1]","");
    PROCESS_EXIT();
  }
  target.u8[0] = (uint8_t) rime_long;
  ++next;
  rime_long = shell_strtolong(next, &next);
  if(rime_long < 0 || rime_long > 255){
    shell_output_str(&ruc_send_command, "rimeaddress[1] has to be in range [0-255]","");
    PROCESS_EXIT();
  }
  target.u8[1] = (uint8_t) rime_long;

  while(*next == ' '){
    next++;
  }

  msg_size = strlen(next);
  if(msg_size == 0){
    shell_output_str(&ruc_send_command, "ruc_send usage:", ruc_send_command.description);
    PROCESS_EXIT();
  }

  memcpy(msg_buf, next, msg_size);

  packetbuf_copyfrom(&msg_buf, msg_size);

  struct runicast_entry *e = NULL;
  for(e = list_head(runicast_list); e != NULL; e = e->next){
    if(e->channel == channel){
      runicast_send(&e->c, &target,3);
      shell_output_str(&ruc_send_command, "sent reliable unicast message on channel: ", buf);
      PROCESS_EXIT();
    }
  }
  shell_output_str(&ruc_send_command, "ruc_send error: channel not open, use ruc_open <channel> before trying to send","");

  PROCESS_END();
}

/* periodic broadcast light sensor data */
PROCESS_THREAD(spam_process, ev, data) {

	PROCESS_BEGIN();
	SENSORS_ACTIVATE(light_sensor);

	// init
	leds_off(LEDS_ALL);
	int light_val = 0;

	while(1) {
		// wait a bit
		static struct etimer et;
		etimer_set(&et, 1 * CLOCK_SECOND / 2);
		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

		// send packet
		light_val = light_sensor.value(LIGHT_SENSOR_PHOTOSYNTHETIC);
		packetbuf_copyfrom(&light_val, sizeof(int));
		broadcast_send(&broadcast_connection);
	}

	SENSORS_DEACTIVATE(light_sensor);
	PROCESS_END();
}

/* init and react on button press */
PROCESS_THREAD(button_process, ev, data) {

	PROCESS_BEGIN();
	SENSORS_ACTIVATE(button_sensor);

	shell_sdr_init();
	broadcast_open(&broadcast_connection, 129, &broadcast_callback);

	process_start(&spam_process, NULL);

	static int dummy = 0;

	while(1) {
		leds_off(LEDS_ALL);

		// wait for button press
		PROCESS_WAIT_EVENT_UNTIL(ev == sensors_event &&
				data == &button_sensor);

		packetbuf_copyfrom(&dummy, sizeof(int));
		broadcast_send(&broadcast_connection);
	}

	PROCESS_END();
}
