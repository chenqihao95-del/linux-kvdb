// client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include "protocol.h"

void usage(const char *prog) {
    fprintf(stderr, "用法:\n");
    fprintf(stderr, "  %s put <key> <value>\n", prog);
    fprintf(stderr, "  %s get <key>\n", prog);
    fprintf(stderr, "  %s del <key>\n", prog);
    fprintf(stderr, "  %s list\n", prog);
    fprintf(stderr, "  %s shutdown   (关闭服务器)\n", prog);
}

// 发送请求并等待响应
void send_request(struct kv_request *req) {
    int msgid = msgget(MSG_KEY, 0666);
    if (msgid == -1) {
        perror("msgget");
        exit(1);
    }

    // 请求消息类型固定为 1
    req->mtype = 1;
    req->pid = getpid();

    if (msgsnd(msgid,
               req,
               sizeof(struct kv_request) - sizeof(long),
               0) == -1) {
        perror("msgsnd");
        exit(1);
    }

    struct kv_response resp;
    ssize_t r = msgrcv(msgid,
                       &resp,
                       sizeof(struct kv_response) - sizeof(long),
                       req->pid,  // 只收发给自己的响应
                       0);
    if (r == -1) {
        perror("msgrcv");
        exit(1);
    }

    // 输出结果
    if (req->op == OP_LIST) {
        if (resp.listing[0] == '\0') {
            printf("(empty)\n");
        } else {
            printf("%s", resp.listing);
        }
    } else {
        printf("status=%d, msg=%s\n", resp.status, resp.value);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    struct kv_request req;
    memset(&req, 0, sizeof(req));

    if (strcmp(argv[1], "put") == 0) {
        if (argc != 4) {
            usage(argv[0]);
            return 1;
        }
        req.op = OP_PUT;
        strncpy(req.key, argv[2], MAX_KEY_LEN - 1);
        req.key[MAX_KEY_LEN - 1] = '\0';
        strncpy(req.value, argv[3], MAX_VAL_LEN - 1);
        req.value[MAX_VAL_LEN - 1] = '\0';

    } else if (strcmp(argv[1], "get") == 0) {
        if (argc != 3) {
            usage(argv[0]);
            return 1;
        }
        req.op = OP_GET;
        strncpy(req.key, argv[2], MAX_KEY_LEN - 1);
        req.key[MAX_KEY_LEN - 1] = '\0';

    } else if (strcmp(argv[1], "del") == 0) {
        if (argc != 3) {
            usage(argv[0]);
            return 1;
        }
        req.op = OP_DEL;
        strncpy(req.key, argv[2], MAX_KEY_LEN - 1);
        req.key[MAX_KEY_LEN - 1] = '\0';

    } else if (strcmp(argv[1], "list") == 0) {
        req.op = OP_LIST;

    } else if (strcmp(argv[1], "shutdown") == 0) {
        req.op = OP_SHUTDOWN;

    } else {
        usage(argv[0]);
        return 1;
    }

    send_request(&req);
    return 0;
}
