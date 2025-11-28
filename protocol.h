// protocol.h
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <sys/types.h>

// 一些固定参数，可按需要调整
#define MAX_KEY_LEN   32
#define MAX_VAL_LEN   128
#define MAX_ITEMS     128
#define MAX_LIST_BUF  4096

// System V IPC key，只要 client/server 一致即可
// 真正交作业时可以改成 ftok 生成的 key
#define SHM_KEY  0x1234
#define SEM_KEY  0x5678
#define MSG_KEY  0x4321

// 操作类型
enum {
    OP_PUT = 1,
    OP_GET,
    OP_DEL,
    OP_LIST,
    OP_SHUTDOWN
};

// 响应状态码
enum {
    ST_OK = 0,
    ST_NOT_FOUND = 1,
    ST_FULL = 2,
    ST_ERROR = 3
};

// ------------------ 共享内存中的数据库结构 ----------------

struct kv_item {
    int used;  // 0 未使用, 1 已使用
    char key[MAX_KEY_LEN];
    char value[MAX_VAL_LEN];
};

struct kv_db {
    struct kv_item items[MAX_ITEMS];
};

// ------------------ 消息队列 请求/响应 -------------------

struct kv_request {
    long mtype;        // 消息类型：固定为 1（请求）
    int op;            // 操作类型 OP_PUT / OP_GET ...
    pid_t pid;         // 客户端进程 ID，用于回包的 mtype
    char key[MAX_KEY_LEN];
    char value[MAX_VAL_LEN];
};

struct kv_response {
    long mtype;        // 消息类型：= 请求里的 pid
    int status;        // 状态码
    char value[MAX_VAL_LEN];       // GET/PUT/DEL 的返回信息
    char listing[MAX_LIST_BUF];    // LIST 的结果
};

#endif // PROTOCOL_H
