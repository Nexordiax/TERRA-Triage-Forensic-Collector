/* Independent synthetic RPM package inventory; generated with Berkeley DB 5.3.
 * Build: cc make_rpm_bdb.c -ldb -o make_rpm_bdb
 * Run: ./make_rpm_bdb header.bin output.db hash|btree
 * Only creates a NEW development fixture; never used by TERRA collectors.
 */
#include <db.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 4) return 1;
    FILE *input = fopen(argv[1], "rb");
    if (!input) return 2;
    fseek(input, 0, SEEK_END);
    long size = ftell(input);
    if (size < 0 || size > 1000000) return 3;
    rewind(input);
    void *blob = malloc(size);
    if (!blob || fread(blob, 1, size, input) != (size_t)size) return 4;
    fclose(input);
    DB *database = NULL;
    int status = db_create(&database, NULL, 0);
    if (status) return 5;
    database->set_pagesize(database, 4096);
    status = database->open(database, NULL, argv[2], NULL,
                            strcmp(argv[3], "hash") == 0 ? DB_HASH : DB_BTREE,
                            DB_CREATE | DB_EXCL, 0600);
    if (status) return 6;
    unsigned int identifier = 1;
    DBT key = {0}, value = {0};
    key.data = &identifier; key.size = sizeof(identifier);
    value.data = blob; value.size = (unsigned int)size;
    status = database->put(database, NULL, &key, &value, DB_NOOVERWRITE);
    database->close(database, 0);
    free(blob);
    return status ? 7 : 0;
}
