// server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/msg.h>

#include "protocol.h"

#define PERSIST_FILE "kvdb.dat"

// System V semctl 需要这个 union
union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

// 全局变量，便于退出时清理
int g_shmid = -1;
int g_semid = -1;
int g_msgid = -1;
struct kv_db *g_db = NULL;

// -------------- 信号量封装 --------------

int sem_create_or_get(key_t key) {
    int semid = semget(key, 1, IPC_CREAT | 0666);
    if (semid == -1) {
        perror("semget");
        exit(1);
    }

    // 尝试设置初始值为 1（可能已经存在）
    union semun arg;
    arg.val = 1;
    if (semctl(semid, 0, SETVAL, arg) == -1) {
        perror("semctl SETVAL");
        // 这里不直接退出：如果信号量已经存在，可能会失败，但不影响使用
    }

    return semid;
}

void sem_lock(int semid) {
    struct sembuf sb = {0, -1, 0}; // P 操作
    if (semop(semid, &sb, 1) == -1) {
        perror("semop P");
        exit(1);
    }
}

void sem_unlock(int semid) {
    struct sembuf sb = {0, +1, 0}; // V 操作
    if (semop(semid, &sb, 1) == -1) {
        perror("semop V");
        exit(1);
    }
}

// -------------- 持久化 --------------

void load_from_file(const char *filename, struct kv_db *db) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        // 第一次启动，没有文件不算错误
        memset(db, 0, sizeof(struct kv_db));
        return;
    }
    size_t n = fread(db, 1, sizeof(struct kv_db), fp);
    if (n != sizeof(struct kv_db)) {
        fprintf(stderr, "load_from_file: file size mismatch, reset db\n");
        memset(db, 0, sizeof(struct kv_db));
    }
    fclose(fp);
}

void save_to_file(const char *filename, struct kv_db *db) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("fopen persist");
        return;
    }
    fwrite(db, 1, sizeof(struct kv_db), fp);
    fclose(fp);
}

// -------------- KV 操作（在持有锁的前提下调用） --------------

int kv_put(struct kv_db *db, const char *key, const char *value) {
    int free_idx = -1;

    for (int i = 0; i < MAX_ITEMS; ++i) {
        if (db->items[i].used) {
            if (strncmp(db->items[i].key, key, MAX_KEY_LEN) == 0) {
                // 覆盖
                strncpy(db->items[i].value, value, MAX_VAL_LEN - 1);
                db->items[i].value[MAX_VAL_LEN - 1] = '\0';
                return ST_OK;
            }
        } else if (free_idx == -1) {
            free_idx = i;
        }
    }

    if (free_idx == -1) {
        return ST_FULL;
    }

    db->items[free_idx].used = 1;
    strncpy(db->items[free_idx].key, key, MAX_KEY_LEN - 1);
    db->items[free_idx].key[MAX_KEY_LEN - 1] = '\0';
    strncpy(db->items[free_idx].value, value, MAX_VAL_LEN - 1);
    db->items[free_idx].value[MAX_VAL_LEN - 1] = '\0';

    return ST_OK;
}

int kv_get(struct kv_db *db, const char *key, char *out_value) {
    for (int i = 0; i < MAX_ITEMS; ++i) {
        if (db->items[i].used &&
            strncmp(db->items[i].key, key, MAX_KEY_LEN) == 0) {
            strncpy(out_value, db->items[i].value, MAX_VAL_LEN);
            out_value[MAX_VAL_LEN - 1] = '\0';
            return ST_OK;
        }
    }
    return ST_NOT_FOUND;
}

int kv_del(struct kv_db *db, const char *key) {
    for (int i = 0; i < MAX_ITEMS; ++i) {
        if (db->items[i].used &&
            strncmp(db->items[i].key, key, MAX_KEY_LEN) == 0) {
            db->items[i].used = 0;
            db->items[i].key[0] = '\0';
            db->items[i].value[0] = '\0';
            return ST_OK;
        }
    }
    return ST_NOT_FOUND;
}

void kv_list(struct kv_db *db, char *buf, size_t bufsize) {
    buf[0] = '\0';
    size_t len = 0;

    for (int i = 0; i < MAX_ITEMS; ++i) {
        if (db->items[i].used) {
            char line[256];
            snprintf(line, sizeof(line), "%s = %s\n",
                     db->items[i].key, db->items[i].value);
            size_t line_len = strlen(line);

            if (len + line_len + 1 >= bufsize)
                break;

            memcpy(buf + len, line, line_len);
            len += line_len;
        }
    }
    buf[len] = '\0';
}

// -------------- 清理 & 信号处理 --------------

void cleanup() {
    if (g_db) {
        // 退出前持久化
        sem_lock(g_semid);
        save_to_file(PERSIST_FILE, g_db);
        sem_unlock(g_semid);

        shmdt(g_db);
        g_db = NULL;
    }

    if (g_shmid != -1) {
        // 这里选择删除共享内存
        shmctl(g_shmid, IPC_RMID, NULL);
        g_shmid = -1;
    }
    if (g_semid != -1) {
        semctl(g_semid, 0, IPC_RMID);
        g_semid = -1;
    }
    if (g_msgid != -1) {
        msgctl(g_msgid, IPC_RMID, NULL);
        g_msgid = -1;
    }
}

void sigint_handler(int sig) {
    (void)sig;
    printf("\nServer exiting (SIGINT)...\n");
    cleanup();
    exit(0);
}

// -------------- 主函数 --------------

int main() {
    // 注册 SIGINT 处理，Ctrl+C 时保存数据
    signal(SIGINT, sigint_handler);

    // 1. 创建/获取共享内存
    g_shmid = shmget(SHM_KEY, sizeof(struct kv_db), IPC_CREAT | 0666);
    if (g_shmid == -1) {
        perror("shmget");
        exit(1);
    }

    g_db = (struct kv_db *)shmat(g_shmid, NULL, 0);
    if (g_db == (void *)-1) {
        perror("shmat");
        exit(1);
    }

    // 2. 创建/获取信号量
    g_semid = sem_create_or_get(SEM_KEY);

    // 3. 创建/获取消息队列
    g_msgid = msgget(MSG_KEY, IPC_CREAT | 0666);
    if (g_msgid == -1) {
        perror("msgget");
        exit(1);
    }

    // 4. 从文件加载数据库
    sem_lock(g_semid);
    load_from_file(PERSIST_FILE, g_db);
    sem_unlock(g_semid);

    printf("KV Server started. Waiting for requests...\n");

    // 5. 主循环：接收请求 -> 操作共享内存 -> 发送响应
    while (1) {
        struct kv_request req;
        ssize_t r = msgrcv(g_msgid,
                           &req,
                           sizeof(struct kv_request) - sizeof(long),
                           1, // 只收 mtype = 1 的请求
                           0);
        if (r == -1) {
            if (errno == EINTR) {
                // 被信号打断，继续
                continue;
            }
            perror("msgrcv");
            break;
        }

        struct kv_response resp;
        memset(&resp, 0, sizeof(resp));
        resp.mtype = req.pid; // 回包用客户端的 pid

        if (req.op == OP_SHUTDOWN) {
            printf("Receive shutdown request from pid=%d\n", req.pid);
            resp.status = ST_OK;
            snprintf(resp.value, sizeof(resp.value), "server shutting down");
            msgsnd(g_msgid,
                   &resp,
                   sizeof(struct kv_response) - sizeof(long),
                   0);
            break;
        }

        // 针对数据库的操作要加锁
        sem_lock(g_semid);

        switch (req.op) {
            case OP_PUT: {
                int st = kv_put(g_db, req.key, req.value);
                resp.status = st;
                if (st == ST_OK) {
                    snprintf(resp.value, sizeof(resp.value), "OK");
                } else if (st == ST_FULL) {
                    snprintf(resp.value, sizeof(resp.value), "DB FULL");
                } else {
                    snprintf(resp.value, sizeof(resp.value), "ERROR");
                }
                break;
            }
            case OP_GET: {
                char val[MAX_VAL_LEN];
                int st = kv_get(g_db, req.key, val);
                resp.status = st;
                if (st == ST_OK) {
                    snprintf(resp.value, sizeof(resp.value), "%s", val);
                } else {
                    snprintf(resp.value, sizeof(resp.value), "NOT FOUND");
                }
                break;
            }
            case OP_DEL: {
                int st = kv_del(g_db, req.key);
                resp.status = st;
                if (st == ST_OK) {
                    snprintf(resp.value, sizeof(resp.value), "DELETED");
                } else {
                    snprintf(resp.value, sizeof(resp.value), "NOT FOUND");
                }
                break;
            }
            case OP_LIST: {
                resp.status = ST_OK;
                kv_list(g_db, resp.listing, sizeof(resp.listing));
                break;
            }
            default: {
                resp.status = ST_ERROR;
                snprintf(resp.value, sizeof(resp.value), "UNKNOWN OP");
                break;
            }
        }

        sem_unlock(g_semid);

        if (msgsnd(g_msgid,
                   &resp,
                   sizeof(struct kv_response) - sizeof(long),
                   0) == -1) {
            perror("msgsnd");
            break;
        }
    }

    printf("Server exiting...\n");
    cleanup();
    return 0;
}
