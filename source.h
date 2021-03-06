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

#define SOURCE_GC_TIME 200

struct source {
    unsigned char id[8];
    unsigned char prefix[16];
    unsigned char plen;
    unsigned char src_prefix[16];
    unsigned char src_plen;
    unsigned char tos[1]; // Storing the additional index-partner for QoS-based routing
    unsigned short seqno;
    unsigned short metric;
    unsigned short route_count;
    time_t time;
};

struct source *find_source(const unsigned char *id,
                           const unsigned char *prefix,
                           unsigned char plen,
                           const unsigned char *src_prefix,
                           unsigned char src_plen,
                           const unsigned char *tos,
                           int create, unsigned short seqno);
struct source *retain_source(struct source *src);
void release_source(struct source *src);
void update_source(struct source *src,
                   unsigned short seqno, unsigned short metric);
void expire_sources(void);
void check_sources_released(void);
