#!/bin/bash
sleep 4
psql -U postgres -c "CREATE ROLE testuser WITH LOGIN SUPERUSER PASSWORD 'testuser'"
psql -U postgres -c "CREATE DATABASE velodrome;"
psql -U postgres -c "grant all privileges on database velodrome to testuser;"
psql -U postgres -c "CREATE DATABASE trackings;"
psql -U postgres -c "grant all privileges on database trackings to testuser;"
psql -U postgres -d trackings -c "CREATE EXTENSION IF NOT EXISTS pg_trgm"
psql -U postgres -d trackings -c "CREATE EXTENSION IF NOT EXISTS postgis"
psql -U postgres -d trackings -c "CREATE EXTENSION IF NOT EXISTS unaccent"
psql -U postgres -d velodrome -c "CREATE EXTENSION IF NOT EXISTS pg_trgm"
psql -U postgres -d velodrome -c "CREATE EXTENSION IF NOT EXISTS postgis"
psql -U postgres -d velodrome -c "CREATE EXTENSION IF NOT EXISTS unaccent"
echo "done"
