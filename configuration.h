/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/* Values returned by parse_config_from_string. */

#define CONFIG_ACTION_DONE 0
#define CONFIG_ACTION_QUIT 1
#define CONFIG_ACTION_DUMP 2
#define CONFIG_ACTION_MONITOR 3
#define CONFIG_ACTION_UNMONITOR 4
#define CONFIG_ACTION_NO 5

#define AUTH_TYPE_NONE 0
#define AUTH_TYPE_SHA256 1
#define AUTH_TYPE_BLAKE2S128 2

/*Values for defined DSCP_Classes with their ToS-Value (See https://linuxreviews.org/Type_of_Service_(ToS)_and_DSCP_Values)*/
#define DSCP_DF   0x00  //Default Forwarding
#define DSCP_LE   0x04  // Lower-Effort
#define DSCP_CS1  0x20  // Low-Priority Data
#define DSCP_AF11 0x28  //high-throughput assured forwarding
#define DSCP_AF12 0x30  //high-throughput assured forwarding
#define DSCP_AF13 0x38  //high-throughput  assured forwarding
#define DSCP_CS2  0x40  // OAM
#define DSCP_AF21 0x48  //low-latency assured forwarding
#define DSCP_AF22 0x50  //low-latency assured forwarding
#define DSCP_AF23 0x58  //low-latency assured forwarding
#define DSCP_CS3  0x60  //video broadcasting
#define DSCP_AF31 0x68  //multimedia streaming assured forwarding
#define DSCP_AF32 0x70  //multimedia streaming assured forwarding
#define DSCP_AF33 0x78  //multimedia streaming assured forwarding
#define DSCP_CS4  0x80  //real-time interactive
#define DSCP_AF41 0x88  //multimedia streaming assured forwarding
#define DSCP_AF42 0x90  //multimedia streaming assured forwarding
#define DSCP_AF43 0x98  //multimedia streaming assured forwarding
#define DSCP_CS5  0xa0  //Signaling
#define DSCP_EF   0xb8  // Telephony
#define DSCP_CS6  0xc0  //Network Routing Control

extern unsigned char* dscp_values; // Required for setup, will move to configuration later
extern unsigned int dscp_values_len; // Required to control number of values in loop and needed in other classes

struct filter_result {
    unsigned int add_metric; /* allow = 0, deny = INF, metric = <0..INF> */
    unsigned char *src_prefix;
    unsigned char src_plen;
    unsigned char *tos;
    unsigned int table;
    unsigned char *pref_src;
};

struct filter {
    int af;
    char *ifname;
    unsigned int ifindex;
    unsigned char *id;
    unsigned char *prefix;
    unsigned char plen;
    unsigned char plen_ge, plen_le;
    unsigned char *src_prefix;
    unsigned char src_plen;
    unsigned char src_plen_ge, src_plen_le;
    unsigned char *tos;
    unsigned char *neigh;
    int proto;                  /* May be negative */
    struct filter_result action;
    struct filter *next;
};

extern struct interface_conf *default_interface_conf;

void flush_ifconf(struct interface_conf *if_conf);

int parse_config_from_file(const char *filename, int *line_return);
int parse_config_from_string(char *string, int n, const char **message_return);
void renumber_filters(void);

int input_filter(const unsigned char *id,
                 const unsigned char *prefix, unsigned short plen,
                 const unsigned char *src_prefix, unsigned short src_plen,
                 const unsigned char *tos,
                 const unsigned char *neigh, unsigned int ifindex);
int output_filter(const unsigned char *id,
                  const unsigned char *prefix, unsigned short plen,
                  const unsigned char *src_prefix, unsigned short src_plen,
                  const unsigned char *tos,
                  unsigned int ifindex);
int redistribute_filter(const unsigned char *prefix, unsigned short plen,
                    const unsigned char *src_prefix, unsigned short src_plen,
                    const unsigned char *tos,
                    unsigned int ifindex, int proto,
                    struct filter_result *result);
int install_filter(const unsigned char *prefix, unsigned short plen,
                   const unsigned char *src_prefix, unsigned short src_plen,
                   const unsigned char *tos,
                   unsigned int ifindex, struct filter_result *result);
int finalise_config(void);
