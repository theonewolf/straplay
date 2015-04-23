#!/usr/bin/env python
# vim:set nospell:

from sqlite3 import connect
from os.path import exists
from random import randint

DB_FNAME        =   'test.db'
SCHEMA_FNAME    =   'schema.sql'
INSERT_SQL      =   'INSERT INTO `test` (data) values (%s);'
UPDATE_SQL      =   'UPDATE `test` set data = %s where id = %s;'



def create_db(fname, dbfname):
    schema = None
    with open(fname) as schema:
        schema = schema.read()
        with connect(dbfname) as conn:
            conn.execute(schema)

def run_random_workload(n, dbfname):
    with connect(dbfname) as conn:
        for _ in xrange(n):
            rn = randint(0,4000000)
            conn.execute(INSERT_SQL % rn)

    with connect(dbfname) as conn:
        for _ in xrange(n):
            id = randint(1, 1000)
            rn = randint(0,4000000)

            conn.execute(UPDATE_SQL % (rn, id))


if __name__ == '__main__':

    if not exists(DB_FNAME):
        create_db(SCHEMA_FNAME, DB_FNAME)
    
    run_random_workload(1000, DB_FNAME)
