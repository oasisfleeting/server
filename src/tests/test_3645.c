/* -*- mode: C; c-basic-offset: 4 -*- */
#ident "Copyright (c) 2007 Tokutek Inc.  All rights reserved."
#include "test.h"

#include <stdio.h>
#include <stdlib.h>

#include <toku_pthread.h>
#include <unistd.h>
#include <memory.h>
#include <sys/stat.h>
#include <db.h>


//
// This test verifies that running evictions on a writer thread
// are ok. We create a dictionary bigger than the cachetable (around 4x greater).
// Then, we spawn a bunch of pthreads that do the following:
//  - scan dictionary forward with bulk fetch
//  - scan dictionary forward slowly
//  - scan dictionary backward with bulk fetch
//  - scan dictionary backward slowly
//  - update existing values in the dictionary with db->put(DB_YESOVERWRITE)
// With the small cachetable, this should produce quite a bit of churn in reading in and evicting nodes.
// If the test runs to completion without crashing, we consider it a success.
//

BOOL run_test;
int time_of_test;

struct arg {
    int n;
    DB *db;
    DB_ENV* env;
    BOOL fast;
    BOOL fwd;
};

static int
go_fast(DBT const *a, DBT  const *b, void *c) {
    assert(a);
    assert(b);
    assert(c==NULL);
    return TOKUDB_CURSOR_CONTINUE;
}
static int
go_slow(DBT const *a, DBT  const *b, void *c) {
    assert(a);
    assert(b);
    assert(c==NULL);
    return 0;
}

static void *scan_db(void *arg) {
    struct arg *myarg = (struct arg *) arg;
    DB_ENV* env = myarg->env;
    DB* db = myarg->db;
    DB_TXN* txn = NULL;
    int r = env->txn_begin(env, 0, &txn, DB_READ_UNCOMMITTED); CKERR(r);
    while(run_test) {
        DBC* cursor = NULL;
        CHK(db->cursor(db, txn, &cursor, 0));
        while (r != DB_NOTFOUND) {
            if (myarg->fwd) {
                r = cursor->c_getf_next(cursor, 0, myarg->fast ? go_fast : go_slow, NULL);
            }
            else {
                r = cursor->c_getf_prev(cursor, 0, myarg->fast ? go_fast : go_slow, NULL);
            }
            assert(r==0 || r==DB_NOTFOUND);
        }
        
        CHK(cursor->c_close(cursor));
    }
    CHK(txn->commit(txn,0));
    return arg;
}

static void *ptquery_db(void *arg) {
    struct arg *myarg = (struct arg *) arg;
    DB_ENV* env = myarg->env;
    DB* db = myarg->db;
    DB_TXN* txn = NULL;
    int n = myarg->n;
    int r = env->txn_begin(env, 0, &txn, DB_READ_UNCOMMITTED); CKERR(r);
    while(run_test) {
        int rand_key = random() % n;        
        DBT key;
        DBT val;
        memset(&val, 0, sizeof(val));
        dbt_init(&key, &rand_key, sizeof(rand_key));
        r = db->get(db, txn, &key, &val, 0);
        assert(r != DB_NOTFOUND);
    }
    CHK(txn->commit(txn,0));
    return arg;
}

static void *update_db(void *arg) {
    struct arg *myarg = (struct arg *) arg;
    DB_ENV* env = myarg->env;
    DB* db = myarg->db;
    int n = myarg->n;

    DB_TXN* txn = NULL;
    while (run_test) {
        int r = env->txn_begin(env, 0, &txn, DB_READ_UNCOMMITTED); CKERR(r);
        for (u_int32_t i = 0; i < 1000; i++) {
            int rand_key = random() % n;
            int rand_val = random();
            DBT key, val;
            r = db->put(
                db, 
                txn, 
                dbt_init(&key, &rand_key, sizeof(rand_key)), 
                dbt_init(&val, &rand_val, sizeof(rand_val)), 
                0
                );
            CKERR(r);
        }
        CHK(txn->commit(txn,0));
    }
    return arg;
}

static void *test_time(void *arg) {
    assert(arg == NULL);
    usleep(time_of_test*1000*1000);
    printf("should now end test\n");
    run_test = FALSE;
    return arg;
}


static void
test_evictions (int nseconds) {
    int n = 100000;
    if (verbose) printf("test_rand_insert:%d \n", n);

    DB_TXN * const null_txn = 0;
    const char * const fname = "test.bulk_fetch.brt";
    int r;

    r = system("rm -rf " ENVDIR);
    CKERR(r);
    r=toku_os_mkdir(ENVDIR, S_IRWXU+S_IRWXG+S_IRWXO); assert(r==0);

    /* create the dup database file */
    DB_ENV *env;
    r = db_env_create(&env, 0); assert(r == 0);
    r=env->set_default_bt_compare(env, int_dbt_cmp); CKERR(r);
    // set the cache size to 10MB
    r = env->set_cachesize(env, 0, 100000, 1); CKERR(r);
    r=env->open(env, ENVDIR, DB_INIT_LOCK|DB_INIT_LOG|DB_INIT_MPOOL|DB_INIT_TXN|DB_CREATE|DB_PRIVATE, S_IRWXU+S_IRWXG+S_IRWXO); CKERR(r);

    DB *db;
    r = db_create(&db, env, 0);
    assert(r == 0);
    r = db->set_flags(db, 0);
    assert(r == 0);
    r = db->set_pagesize(db, 4096);
    assert(r == 0);
    r = db->set_readpagesize(db, 1024);
    assert(r == 0);
    r = db->open(db, null_txn, fname, "main", DB_BTREE, DB_CREATE, 0666);
    assert(r == 0);

    int keys[n];
    for (int i=0; i<n; i++) {
        keys[i] = i;
    }
    
    for (int i=0; i<n; i++) {
        DBT key, val;
        r = db->put(db, null_txn, dbt_init(&key, &keys[i], sizeof keys[i]), dbt_init(&val, &i, sizeof i), 0);
        assert(r == 0);
    } 

    //
    // the threads that we want:
    //   - one thread constantly updating random values
    //   - one thread doing table scan with bulk fetch
    //   - one thread doing table scan without bulk fetch
    //   - one thread doing random point queries
    //
    toku_pthread_t mytids[7];
    struct arg myargs[7];
    for (u_int32_t i = 0; i < sizeof(myargs)/sizeof(myargs[0]); i++) {
        myargs[i].n = n;
        myargs[i].db = db;
        myargs[i].env = env;
        myargs[i].fast = TRUE;
        myargs[i].fwd = TRUE;
    }

    // make the forward fast scanner
    myargs[0].fast = TRUE;
    myargs[0].fwd = TRUE;
    CHK(toku_pthread_create(&mytids[0], NULL, scan_db, &myargs[0]));

    // make the forward slow scanner
    myargs[1].fast = FALSE;
    myargs[1].fwd = TRUE;
    CHK(toku_pthread_create(&mytids[1], NULL, scan_db, &myargs[1]));

    // make the backward fast scanner
    myargs[2].fast = TRUE;
    myargs[2].fwd = FALSE;
    CHK(toku_pthread_create(&mytids[2], NULL, scan_db, &myargs[2]));

    // make the backward slow scanner
    myargs[3].fast = FALSE;
    myargs[3].fwd = FALSE;
    CHK(toku_pthread_create(&mytids[3], NULL, scan_db, &myargs[3]));

    // make the guy that updates the db
    CHK(toku_pthread_create(&mytids[4], NULL, update_db, &myargs[4]));

    // make the guy that does point queries
    CHK(toku_pthread_create(&mytids[5], NULL, ptquery_db, &myargs[5]));

    run_test = TRUE;
    time_of_test = nseconds;
    // make the guy that sleeps
    CHK(toku_pthread_create(&mytids[6], NULL, test_time, NULL));
    
    for (u_int32_t i = 0; i < sizeof(myargs)/sizeof(myargs[0]); i++) {
        void *ret;
        r = toku_pthread_join(mytids[i], &ret); assert_zero(r);
    }


    r = db->close(db, 0); CKERR(r);
    r = env->close(env, 0); CKERR(r);
}

int
test_main(int argc, char *const argv[]) {
    parse_args(argc, argv);
    test_evictions(60);
    return 0;
}