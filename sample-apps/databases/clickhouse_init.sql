CREATE DATABASE IF NOT EXISTS db;
DROP TABLE IF EXISTS db.pets;

CREATE TABLE IF NOT EXISTS db.pets (
   pet_id UInt32,
   pet_name String NOT NULL,
   owner String NOT NULL
) ENGINE = MergeTree() ORDER BY pet_id;
