/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
Copyright (c) 2021 by Florian Wiedner

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

struct xroute {
    unsigned char prefix[16];
    unsigned char plen;
    unsigned char src_prefix[16];
    unsigned char src_plen;
    unsigned char tos[1];
    unsigned short metric;
    unsigned int ifindex;
    int proto;
};

struct xroute_stream;

struct xroute *find_xroute(const unsigned char *prefix, unsigned char plen,
                const unsigned char *src_prefix, unsigned char src_plen,
                const unsigned char *tos);
int add_xroute(unsigned char prefix[16], unsigned char plen,
               unsigned char src_prefix[16], unsigned char src_plen,
               unsigned char tos[1],
               unsigned short metric, unsigned int ifindex, int proto);
void flush_xroute(struct xroute *xroute);
int xroutes_estimate(void);
struct xroute_stream *xroute_stream();
struct xroute *xroute_stream_next(struct xroute_stream *stream);
void xroute_stream_done(struct xroute_stream *stream);
int kernel_addresses(int ifindex, int ll,
                     struct kernel_route *routes, int maxroutes);
int check_xroutes(int send_updates);
