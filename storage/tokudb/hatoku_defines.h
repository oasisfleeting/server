#ifndef _HATOKU_DEF
#define _HATOKU_DEF

#include "db.h"
extern "C" {
#include "toku_os.h"
}


extern ulong tokudb_debug;


//
// returns maximum length of dictionary name, such as key-NAME
// NAME_CHAR_LEN is max length of the key name, and have upper bound of 10 for key-
//
#define MAX_DICT_NAME_LEN NAME_CHAR_LEN + 10


// QQQ how to tune these?
#define HA_TOKUDB_RANGE_COUNT   100
/* extra rows for estimate_rows_upper_bound() */
#define HA_TOKUDB_EXTRA_ROWS    100

/* Bits for share->status */
#define STATUS_PRIMARY_KEY_INIT 0x1

// tokudb debug tracing
#define TOKUDB_DEBUG_INIT 1
#define TOKUDB_DEBUG_OPEN 2
#define TOKUDB_DEBUG_ENTER 4
#define TOKUDB_DEBUG_RETURN 8
#define TOKUDB_DEBUG_ERROR 16
#define TOKUDB_DEBUG_TXN 32
#define TOKUDB_DEBUG_AUTO_INCREMENT 64
#define TOKUDB_DEBUG_LOCK 256
#define TOKUDB_DEBUG_LOCKRETRY 512

#define TOKUDB_TRACE(f, ...) \
    printf("%d:%s:%d:" f, my_tid(), __FILE__, __LINE__, ##__VA_ARGS__);


inline unsigned int my_tid() {
    return (unsigned int)toku_os_gettid();
}



#define TOKUDB_DBUG_ENTER(f, ...)      \
{ \
    if (tokudb_debug & TOKUDB_DEBUG_ENTER) { \
        TOKUDB_TRACE(f "\n", ##__VA_ARGS__); \
    } \
} \
    DBUG_ENTER(__FUNCTION__);


#define TOKUDB_DBUG_RETURN(r) \
{ \
    int rr = (r); \
    if ((tokudb_debug & TOKUDB_DEBUG_RETURN) || (rr != 0 && (tokudb_debug & TOKUDB_DEBUG_ERROR))) { \
        TOKUDB_TRACE("%s:return %d\n", __FUNCTION__, rr); \
    } \
    DBUG_RETURN(rr); \
}

#define TOKUDB_DBUG_DUMP(s, p, len) \
{ \
    TOKUDB_TRACE("%s:%s", __FUNCTION__, s); \
    uint i;                                                             \
    for (i=0; i<len; i++) {                                             \
        printf("%2.2x", ((uchar*)p)[i]);                                \
    }                                                                   \
    printf("\n");                                                       \
}


typedef enum {
    hatoku_iso_not_set = 0,
    hatoku_iso_read_uncommitted,
    hatoku_iso_serializable
} HA_TOKU_ISO_LEVEL;



typedef struct st_tokudb_stmt_progress {
    ulonglong inserted;
    ulonglong updated;
    ulonglong deleted;
    ulonglong queried;
} tokudb_stmt_progress;


typedef struct st_tokudb_trx_data {
    DB_TXN *all;
    DB_TXN *stmt;
    DB_TXN *sp_level;
    uint tokudb_lock_count;
    HA_TOKU_ISO_LEVEL iso_level;
    tokudb_stmt_progress stmt_progress;
    bool checkpoint_lock_taken;
} tokudb_trx_data;

extern char *tokudb_data_dir;
extern const char *ha_tokudb_ext;

static void reset_stmt_progress (tokudb_stmt_progress* val) {
    val->deleted = 0;
    val->inserted = 0;
    val->updated = 0;
    val->queried = 0;
}

static int get_name_length(const char *name) {
    int n = 0;
    const char *newname = name;
    n += strlen(newname);
    n += strlen(ha_tokudb_ext);
    return n;
}

//
// returns maximum length of path to a dictionary
//
static int get_max_dict_name_path_length(const char *tablename) {
    int n = 0;
    n += get_name_length(tablename);
    n += 1; //for the '-'
    n += MAX_DICT_NAME_LEN;
    return n;
}

static void make_name(char *newname, const char *tablename, const char *dictname) {
    const char *newtablename = tablename;
    char *nn = newname;
    assert(tablename);
    assert(dictname);
    nn += sprintf(nn, "%s", newtablename);
    nn += sprintf(nn, "-%s", dictname);
}

static inline void commit_txn(DB_TXN* txn, u_int32_t flags) {
    int r;
    r = txn->commit(txn, flags);
    if (r != 0) {
        sql_print_error("tried committing transaction %p and got error code %d", txn, r);
    }
    assert(r == 0);
}

static inline void abort_txn(DB_TXN* txn) {
    int r;
    r = txn->abort(txn);
    if (r != 0) {
        sql_print_error("tried aborting transaction %p and got error code %d", txn, r);
    }
    assert(r == 0);
}


#endif