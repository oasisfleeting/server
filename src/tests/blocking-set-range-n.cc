/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
// vim: ft=cpp:expandtab:ts=8:sw=4:softtabstop=4:
#ident "$Id$"
#ident "Copyright (c) 2007-2012 Tokutek Inc.  All rights reserved."
#ident "The technology is licensed by the Massachusetts Institute of Technology, Rutgers State University of New Jersey, and the Research Foundation of State University of New York at Stony Brook under United States of America Serial No. 11/760379 and to the patents and/or patent applications resulting from it."
// verify that cursor set range operations suspend the conflicting threads when another transaction 
// owns a lock on the key.  the key is at the right edge of the key space.

#include "test.h"
#include "toku_pthread.h"

static void populate(DB_ENV *db_env, DB *db, uint64_t nrows) {
    int r;

    DB_TXN *txn = NULL;
    r = db_env->txn_begin(db_env, NULL, &txn, 0); assert(r == 0);

    for (uint64_t i = 0; i < nrows; i++) {

        uint64_t k = htonl(i);
        uint64_t v = i;
        DBT key = { .data = &k, .size = sizeof k };
        DBT val = { .data = &v, .size = sizeof v };
        r = db->put(db, txn, &key, &val, 0); assert(r == 0);
    }

    r = txn->commit(txn, 0); assert(r == 0);
}

struct my_callback_context {
    DBT key;
    DBT val;
};

#if TOKUDB
static void copy_dbt(DBT *dest, DBT const *src) {
    assert(dest->flags == DB_DBT_REALLOC);
    dest->size = src->size;
    dest->data = toku_xrealloc(dest->data, dest->size);
    memcpy(dest->data, src->data, dest->size);
}

static int blocking_set_range_callback(DBT const *a UU(), DBT const *b UU(), void *e UU()) {
    DBT const *found_key = a;
    DBT const *found_val = b;
    struct my_callback_context *context = (struct my_callback_context *) e;
    copy_dbt(&context->key, found_key);
    copy_dbt(&context->val, found_val);
    return 0;
}
#endif

static void blocking_set_range(DB_ENV *db_env, DB *db, uint64_t nrows, long sleeptime, uint64_t the_key) {
    int r;

    struct my_callback_context context;
    dbt_init_realloc(&context.key);
    dbt_init_realloc(&context.val);

    for (uint64_t i = 0; i < nrows; i++) {
        DB_TXN *txn = NULL;
        r = db_env->txn_begin(db_env, NULL, &txn, 0); assert(r == 0);

        DBC *cursor = NULL;
        r = db->cursor(db, txn, &cursor, 0); assert(r == 0); // get a write lock on the key

        uint64_t k = htonl(the_key);
        DBT key = { .data = &k, .size = sizeof k };
#if TOKUDB
        r = cursor->c_getf_set_range(cursor, DB_RMW, &key, blocking_set_range_callback, &context); assert(r == DB_NOTFOUND);
#else
        r = cursor->c_get(cursor, &key, &context.val, DB_SET_RANGE + DB_RMW); assert(r == DB_NOTFOUND);
#endif
        usleep(sleeptime);

        r = cursor->c_close(cursor); assert(r == 0);

        r = txn->commit(txn, 0); assert(r == 0);
        if (verbose)
            printf("%lu %" PRIu64 "\n", (unsigned long) toku_pthread_self(), i);
    }

    toku_free(context.key.data);
    toku_free(context.val.data);
}

struct blocking_set_range_args {
    DB_ENV *db_env;
    DB *db;
    uint64_t nrows;
    long sleeptime;
    uint64_t the_key;
};

static void *blocking_set_range_thread(void *arg) {
    struct blocking_set_range_args *a = (struct blocking_set_range_args *) arg;
    blocking_set_range(a->db_env, a->db, a->nrows, a->sleeptime, a->the_key);
    return arg;
}

static void run_test(DB_ENV *db_env, DB *db, int nthreads, uint64_t nrows, long sleeptime, uint64_t the_key) {
    int r;
    toku_pthread_t tids[nthreads];
    struct blocking_set_range_args a = { db_env, db, nrows, sleeptime, the_key };
    for (int i = 0; i < nthreads-1; i++) {
        r = toku_pthread_create(&tids[i], NULL, blocking_set_range_thread, &a); assert(r == 0);
    }
    blocking_set_range(db_env, db, nrows, sleeptime, the_key);
    for (int i = 0; i < nthreads-1; i++) {
        void *ret;
        r = toku_pthread_join(tids[i], &ret); assert(r == 0);
    }
}

int test_main(int argc, char * const argv[]) {
    uint64_t cachesize = 0;
    uint32_t pagesize = 0;
    uint64_t nrows = 10;
    int nthreads = 2;
    long sleeptime = 100000;
    const char *db_env_dir = ENVDIR;
    const char *db_filename = "test.db";
    int db_env_open_flags = DB_CREATE | DB_PRIVATE | DB_INIT_MPOOL | DB_INIT_TXN | DB_INIT_LOCK | DB_INIT_LOG | DB_THREAD;

    // parse_args(argc, argv);
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose++;
            continue;
        }
        if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            if (verbose > 0)
                verbose--;
            continue;
        }
        if (strcmp(argv[i], "--nrows") == 0 && i+1 < argc) {
            nrows = atoll(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--nthreads") == 0 && i+1 < argc) {
            nthreads = atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--sleeptime") == 0 && i+1 < argc) {
            sleeptime = atol(argv[++i]);
            continue;
        }
        assert(0);
    }

    // setup env
    int r;
    char rm_cmd[strlen(db_env_dir) + strlen("rm -rf ") + 1];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", db_env_dir);
    r = system(rm_cmd); assert(r == 0);

    r = toku_os_mkdir(db_env_dir, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH); assert(r == 0);

    DB_ENV *db_env = NULL;
    r = db_env_create(&db_env, 0); assert(r == 0);
    if (cachesize) {
        const uint64_t gig = 1 << 30;
        r = db_env->set_cachesize(db_env, cachesize / gig, cachesize % gig, 1); assert(r == 0);
    }
    r = db_env->open(db_env, db_env_dir, db_env_open_flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); assert(r == 0);
#if TOKUDB
    r = db_env->set_lock_timeout(db_env, 30 * 1000); assert(r == 0);
#endif

    // create the db
    DB *db = NULL;
    r = db_create(&db, db_env, 0); assert(r == 0);
    if (pagesize) {
        r = db->set_pagesize(db, pagesize); assert(r == 0);
    }
    r = db->open(db, NULL, db_filename, NULL, DB_BTREE, DB_CREATE|DB_AUTO_COMMIT|DB_THREAD, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); assert(r == 0);

    // populate the db
    populate(db_env, db, nrows);

    run_test(db_env, db, nthreads, nrows, sleeptime, nrows);

    // close env
    r = db->close(db, 0); assert(r == 0); db = NULL;
    r = db_env->close(db_env, 0); assert(r == 0); db_env = NULL;

    return 0;
}