#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "lws_protocol.h"

/// sdk全局变量
static struct {
    uint16_t service_nonce;
    uint16_t sync_nonce;
    ed25519_public_key pk;
    big_num fork;
    char id[100];

    void *nonce_ctx;
    void *datetime_ctx;
    void *device_id_ctx;
    void *fork_ctx;
    void *publick_key_ctx;
    void *sign_ed25519_ctx;

    NonceGet nonce_get;
    DatetimeGet datetime_get;
    DeviceIDGet device_id_get;
    ForkGet fork_get;
    PublicKeyGet public_key_get;
    SignEd25519 sign_ed25519_get;
} G;

/// 交易结构体
typedef struct _Transaction {
    uint16_t version;
    uint16_t type;
    uint32_t timestamp;
    uint32_t lock_until;
    unsigned char hash_anchor[32];
    uint8_t size0;
    unsigned char *input;
    uint8_t prefix;
    unsigned char address[32];
    uint64_t amount;
    uint64_t tx_fee;
    uint8_t size1;
    unsigned char *vch_data;
    uint8_t size2;
    unsigned char sign[64];
} _Transaction;

/// 客户端验证请求结构体
struct ServiceReq {
    uint16_t nonce;
    uint8_t prefix;
    unsigned char address[32];
    uint32_t version;
    uint32_t timestamp;
    uint8_t fork_num;
    unsigned char *fork_list;
    uint16_t reply_utxo;
    char *topic_prefix;
    uint16_t sign_size;
    unsigned char sign[64];
    ed25519_secret_key sk;
    ed25519_public_key pk;
};

/// 客户端验证响应结构体
struct _ServiceReply {
    uint16_t nonce;
    uint32_t version;
    uint8_t error;
    uint32_t address_id;
    unsigned char fork_bitmap[8];
    key_seed seed;
};

/// 数据同步请求结构体
struct SyncReq {
    uint16_t nonce;
    uint32_t address_id;
    unsigned char fork_id[32];
    unsigned char utxo_hash[32];
    unsigned char signature[20];
};

/// 数据同步响应结构体
struct _SyncReply {
    uint16_t nonce;
    uint8_t error;
    unsigned char block_hash[32];
    uint32_t block_height;
    uint32_t block_time;
    uint16_t utxo_num;
    // ArrayList *utxo_list;
    uint8_t continue_flag;
};

/// UTXO struct
struct UTXO {
    unsigned char txid[32];
    uint8_t out;
    uint32_t block_height;
    uint16_t type;
    uint64_t amount;
    unsigned char sender[33];
    uint32_t lock_until;
    uint16_t data_size;
    unsigned char *data;
    uint64_t new_amount;
    int is_used;
};

struct UTXOIndex {
    unsigned char txid[32];
    uint8_t out;
};

struct UTXOUpdateItem {
    uint8_t op_type;
    struct UTXOIndex index;
    uint32_t blocke_height;
    struct UTXO new_utxo;
};

struct UTXOUpdate {
    uint16_t nonce;
    uint32_t address_id;
    unsigned char fork_id[32];
    unsigned char block_hash[32];
    uint32_t block_height;
    uint32_t block_time;
    uint16_t update_num;
    // ArrayList *update_list;
    uint8_t continue_flag;
};

struct UTXOAbort {
    uint16_t nonce;
    uint32_t address_id;
    uint8_t reason;
    unsigned char signature[20];
};

struct SendTxReq {
    uint16_t nonce;
    uint32_t address_id;
    unsigned char fork_id[32];
    uint8_t *tx_data;
    unsigned char signature[20];
};

struct SendTxReply {
    uint16_t nonce;
    uint8_t error;
    uint8_t err_code;
    unsigned char txid[64];
    char *err_desc;
};

/**
 * @brief  hex2char
 * Convert hex to unsigned char array(bytes)
 *
 *
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/11/18 17:0:47
 * @param  char *           hex -input hex string
 * @param  unsigned char *  bin -output unsigned char array
 * @return static size_t
 */
static size_t hex_to_uchar(const char *hex, unsigned char *bin)
{
    size_t len = strlen(hex);
    size_t final_len = len / 2;
    size_t i, j;
    for (i = 0, j = 0; j < final_len; i += 2, j++) {
        bin[j] = (unsigned char)((hex[i] % 32 + 9) % 25 * 16 + (hex[i + 1] % 32 + 9) % 25);
    }

    return final_len;
}

/**
 * @brief  uchar_to_hex
 * binary stream to hex string
 *
 *
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2020/9/11 1:8:43
 * @param  const unsigned char * bin
 * @param  const size_t     size
 * @param  char *           hex
 * @return static size_t
 */
static size_t uchar_to_hex(const unsigned char *bin, const size_t size, char *hex)
{
    const char symbol[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    for (int i = 0; i < size; i++) {
        unsigned char c = *((unsigned char *)(bin + sizeof(unsigned char) * i));
        unsigned char hex_l = c & 0x0f;
        unsigned char hex_h = (c >> 4);
        *hex = symbol[hex_h];
        *(hex + 1) = symbol[hex_l];
        hex += 2;
    }

    return 2 * size;
}

/**
 * @brief  reverse
 * reverse the unisgned char array
 *
 *
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2020/9/11 11:8:51
 * @param  unsigned char *  p
 * @param  int              size
 * @return  void
 */
static void reverse(unsigned char *p, int size)
{
    int i;
    unsigned char tmp;
    for (i = 0; i < size / 2; i++) {
        tmp = p[i];
        p[i] = p[size - 1 - i];
        p[size - 1 - i] = tmp;
    }
}

int big_num_compare(big_num data1, big_num data2)
{
    int i;
    for (i = 31; i >= 0; i--) {
        // printf("%d, data1:%u, data2:%u\n", i, data1->pn[i], data2->pn[i]);
        if (data1[i] > data2[i]) {
            return 1;
        }

        if (data1[i] == data2[i]) {
            continue;
        }

        if (data1[i] < data2[i]) {
            return -1;
        }
    }

    return 0;
}

int hook_nonce_get(const NonceGet callback, void *ctx)
{
    G.nonce_get = callback;
    G.nonce_ctx = ctx;
    return 0;
}

int hook_datetime_get(const DatetimeGet callback, void *ctx)
{
    G.datetime_get = callback;
    G.datetime_ctx = ctx;
    return 0;
}

int hook_device_id_get(const DeviceIDGet callback, void *ctx)
{
    G.device_id_get = callback;
    G.device_id_ctx = ctx;
    return 0;
}

int hook_fork_get(const ForkGet callback, void *ctx)
{
    G.fork_get = callback;
    G.fork_ctx = ctx;
    return 0;
}

int hook_public_key_get(const PublicKeyGet callback, void *ctx)
{
    G.public_key_get = callback;
    G.publick_key_ctx = ctx;
    return 0;
}

int hook_public_sign_ed25519(const SignEd25519 callback, void *ctx)
{
    G.sign_ed25519_get = callback;
    G.sign_ed25519_ctx = ctx;
    return 0;
}

/**
 * @brief  serialize_join
 * serialize unsigned char array
 *
 *
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/8/7 17:4:50
 * @param  size_t *         size -i/o array len，first call set to zero
 * @param  void *           thing -void ptr for something that need to be serialized
 * @param  size_t           size_thing -length of things that need to be serialized(byte size)
 * @param  unsigned char *  data -output series
 * @return static size_t -size
 */
static size_t serialize_join(size_t *size, void *thing, size_t size_thing, unsigned char *data)
{
    memcpy(data + *size, thing, size_thing);
    *size += size_thing;
    return *size;
}

/**
 * @brief  deserialize_join
 * Deserialize to struct case
 *
 *
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/8/19 21:20:28
 * @param  size_t *         size -byte length counter
 * @param  unsigned char *  data -data series
 * @param  void *           thing -struct case ptr
 * @param  size_t           size_thing -something that need tobe deserialized
 * @return static size_t -size
 */
static size_t deserialize_join(size_t *size, const unsigned char *data, void *thing, size_t size_thing)
{
    memcpy(thing, data + *size, size_thing);
    *size += size_thing;

    return *size;
}

/**
 * @brief  service_req_serialize
 * ServiceReq object serialized to bytes(unsigned char)
 *
 *
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/11/18 17:32:58
 * @param  struct ServiceReq * req
 * @param  unsigned char *  data
 * @return static size_t
 */
static size_t service_req_serialize(struct ServiceReq *req, unsigned char *data)
{
    size_t size = 0;
    size_t size_thing = sizeof(req->nonce);
    serialize_join(&size, &req->nonce, size_thing, data);

    size_thing = sizeof(req->prefix);
    serialize_join(&size, &req->prefix, size_thing, data);

    size_thing = sizeof(req->address);
    serialize_join(&size, &req->address, size_thing, data);

    size_thing = sizeof(req->version);
    serialize_join(&size, &req->version, size_thing, data);

    size_thing = sizeof(req->timestamp);
    serialize_join(&size, &req->timestamp, size_thing, data);

    size_thing = sizeof(req->fork_num);
    serialize_join(&size, &req->fork_num, size_thing, data);

    size_thing = sizeof(unsigned char) * 32;
    serialize_join(&size, req->fork_list, size_thing, data);

    size_thing = sizeof(req->reply_utxo);
    serialize_join(&size, &req->reply_utxo, size_thing, data);

    size_thing = strlen(req->topic_prefix) + 1;
    serialize_join(&size, req->topic_prefix, size_thing, data);

    unsigned char buff[64] = {0};
    G.sign_ed25519_get(G.sign_ed25519_ctx, data, size, buff);

    // TODO:签名位置
    req->sign_size = sizeof(buff);

    size_thing = sizeof(req->sign_size);
    serialize_join(&size, &req->sign_size, size_thing, data);

    size_thing = sizeof(buff);
    serialize_join(&size, buff, size_thing, data);

    return size;
}

static ServiceReplyP service_reply_deserialize(const unsigned char *data)
{
    ServiceReplyP service_reply;
    size_t size = 0;
    size_t size_thing = sizeof(service_reply.nonce);
    deserialize_join(&size, data, &service_reply.nonce, size_thing);

    size_thing = sizeof(service_reply.version);
    deserialize_join(&size, data, &service_reply.version, size_thing);

    size_thing = sizeof(service_reply.error);
    deserialize_join(&size, data, &service_reply.error, size_thing);

    size_thing = sizeof(service_reply.address_id);
    deserialize_join(&size, data, &service_reply.address_id, size_thing);

    size_thing = sizeof(service_reply.fork_bitmap);
    deserialize_join(&size, data, service_reply.fork_bitmap, size_thing);

    size_thing = sizeof(service_reply.seed);
    deserialize_join(&size, data, service_reply.seed, size_thing);

    return service_reply;
}

int lws_protocol_init()
{
    //
    if (NULL == G.fork_ctx) {
        return -1;
    }

    G.fork_get(G.fork_ctx, G.fork);

    //
    if (NULL == G.publick_key_ctx) {
        return -2;
    }

    G.public_key_get(G.publick_key_ctx, G.pk);

    //
    if (NULL == G.device_id_ctx) {
        return -3;
    }

    G.device_id_get(G.device_id_ctx, G.id);

    return 0;
}

/**
 * @brief  create_service_req
 * Create service request objuect
 *
 *
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/11/18 17:17:12
 * @param  LwsClient *      lws_client -LWS client
 * @return static struct ServiceReq -serviceReq instance
 */
static struct ServiceReq create_service_req()
{
    time_t now_time = G.datetime_get(G.datetime_ctx);
    G.service_nonce = G.nonce_get(G.nonce_ctx);

    struct ServiceReq service_req;
    memset(&service_req, 0x00, sizeof(struct ServiceReq));
    service_req.nonce = G.service_nonce;
    service_req.prefix = 1;
    memcpy(service_req.address, G.pk, 32);
    service_req.version = 1;
    service_req.timestamp = now_time;
    service_req.fork_num = 1;
    service_req.fork_list = G.fork;
    service_req.reply_utxo = 0;
    service_req.topic_prefix = G.id;
    memcpy(&service_req.pk[0], G.pk, 32);

    return service_req;
}

static struct SyncReq create_sync_req(const ServiceReplyP *service_reply)
{
    G.sync_nonce = G.nonce_get(G.nonce_ctx);

    struct SyncReq sync_req;
    memset(&sync_req, 0x00, sizeof(struct SyncReq));
    // sync_req.nonce = service_reply->nonce;
    sync_req.nonce = G.sync_nonce;
    sync_req.address_id = service_reply->address_id;
    memcpy(sync_req.fork_id, G.fork, 32);

    unsigned char data[100] = {'\0'};
    size_t size = 0;
    size_t size_thing = sizeof(sync_req.nonce);
    serialize_join(&size, &sync_req.nonce, size_thing, data);

    size_thing = sizeof(sync_req.address_id);
    serialize_join(&size, &sync_req.address_id, size_thing, data);

    size_thing = sizeof(sync_req.fork_id);
    serialize_join(&size, &sync_req.fork_id, size_thing, data);

    // utxo_hash
    // utxo_hash(lws_client->utxo_list, &lws_client->utxo_list_mutex, sync_req.utxo_hash);

    size_thing = sizeof(sync_req.utxo_hash);
    serialize_join(&size, &sync_req.utxo_hash, size_thing, data);

    // signature
    char api_seed_hex[65] = {'\0'};

    key_seed api_seed;
    memcpy(api_seed, service_reply->seed, 32);
    reverse(api_seed, 32);
    uchar_to_hex(api_seed, 32, api_seed_hex);

    char private_key_hex[65] = {'\0'};
    unsigned char sk[32];
    // memcpy(sk, lws_client->sk, 32);
    reverse(sk, 32);
    uchar_to_hex(sk, 32, private_key_hex);

    shared_key api_key;
    unsigned char sig_buff[20];
    // shared(private_key_hex, api_seed_hex, api_key);
    // HMAC(EVP_ripemd160(), api_key, sizeof(api_key), data, size, sig_buff, NULL);

    memcpy(sync_req.signature, sig_buff, sizeof(sig_buff));

    return sync_req;
}

/**
 * @brief  sync_req_serialize
 * SyncReq serialize
 *
 *
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/11/18 18:3:40
 * @param  struct SyncReq * req  -SyncReq instance
 * @param  unsigned char *  data -SyncReq serialized bytes
 * @return static size_t -data length(bytes len)
 */
static size_t sync_req_serialize(struct SyncReq *req, unsigned char *data)
{
    size_t size = 0;
    size_t size_thing = sizeof(req->nonce);
    serialize_join(&size, &req->nonce, size_thing, data);

    size_thing = sizeof(req->address_id);
    serialize_join(&size, &req->address_id, size_thing, data);

    size_thing = sizeof(req->fork_id);
    serialize_join(&size, &req->fork_id, size_thing, data);

    size_thing = sizeof(req->utxo_hash);
    serialize_join(&size, &req->utxo_hash, size_thing, data);

    size_thing = sizeof(req->signature);
    serialize_join(&size, &req->signature, size_thing, data);

    return size;
}

size_t lws_service_request(unsigned char *data)
{
    struct ServiceReq service_req = create_service_req();
    return service_req_serialize(&service_req, data);
}

int lws_service_reply_handle(const unsigned char *data, const size_t len, ServiceResult *result)
{
    if (NULL == result) {
        return -1;
    }
    ServiceReplyP service_reply = service_reply_deserialize(data);

    // printf("G.nonce:%d, reply.nonce:%d\n", G.service_nonce, service_reply.nonce);

    if (0 == service_reply.error && G.service_nonce == service_reply.nonce) {
        result->address_id = service_reply.address_id;
        memcpy(result->fork_bitmap, service_reply.fork_bitmap, 8);
        memcpy(result->seed, service_reply.seed, 32);
    }

    return service_reply.error;
}

// size_t lws_sync_request(const ServiceReplyP *reply, unsigned char *data)
// {
//     struct SyncReq sync_req = create_sync_req(reply);
//     return sync_req_serialize(&sync_req, data);
// }

// int lws_sync_reply_handle(const unsigned char *data, unsigned char *utxo_array, size_t *count) { return 0; }
