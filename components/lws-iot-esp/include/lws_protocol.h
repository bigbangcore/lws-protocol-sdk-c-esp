/** 
 * @file lws_protocol.h
 * @brief 文件描述
 * 
 */

#ifndef LWS_PROTOCOL_H
#define LWS_PROTOCOL_H

#ifdef __cplusplus
extern "c" {
#endif

typedef unsigned char big_num[32];
typedef big_num ed25519_signature;
typedef big_num ed25519_public_key;
typedef big_num ed25519_secret_key;
typedef big_num curve25519_key;
typedef big_num key_seed;
typedef big_num shared_key;

typedef struct _ServiceReply ServiceReplyP;
typedef struct _SyncReply SyncReply;

typedef struct _ServiceResult {
    uint32_t address_id;
    unsigned char fork_bitmap[8];
    key_seed seed;
} ServiceResult;

typedef unsigned int (*NonceGet)(const void *ctx);
typedef unsigned int (*DatetimeGet)(const void *ctx);
typedef int (*DeviceIDGet)(const void *ctx, char *id);
typedef int (*ForkGet)(const void *ctx, big_num fork_out);
typedef int (*PublicKeyGet)(const void *ctx, ed25519_public_key pk_out);
typedef int (*SignEd25519)(const void *ctx, const unsigned char *data, const size_t len, ed25519_signature signature);

// 注册用户回调函数
int hook_nonce_get(const NonceGet callback, void *ctx);
int hook_datetime_get(const DatetimeGet callback, void *ctx);
int hook_device_id_get(const DeviceIDGet callback, void *ctx);
int hook_fork_get(const ForkGet callback, void *ctx);
int hook_public_key_get(const PublicKeyGet callback, void *ctx);
int hook_public_sign_ed25519(const SignEd25519 callback, void *ctx);

int big_num_compare(big_num data1, big_num data2);

// 初始化sdk 须在用户回调注册完毕后执行
int lws_protocol_init();

// 服务请求/响应
size_t lws_service_req(unsigned char *data);
int lws_service_reply_handle(const unsigned char *data, const size_t len, ServiceResult *result);

// 同步请求/响应
// size_t lws_sync_req(const ServiceReplyP *reply, unsigned char *data);
// int lws_sync_reply_handle(const unsigned char *data, unsigned char *utxo_array, size_t *count);

// // 交易请求/响应
// size_t lws_send_tx_req(const ServiceReplyP *reply, unsigned char *data);
// int lws_send_tx_handle(const unsigned char *data);

#ifdef __cplusplus
}
#endif
#endif