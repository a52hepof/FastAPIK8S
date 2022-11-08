from passlib.hash import bcrypt


password_hash=bcrypt.hash('34')
print(password_hash)




## instalar sqlite3 https://www.imaginanet.com/blog/primeros-pasos-con-sqlite3-comandos-basicos.html
'''
(FastApiKUBERNETES_precioLuz) ubuntuserver@ubuntuserver-desktop:~/Escritorio/GSAD/FastApiKUBERNETES_precioLuz$ python3 hashes.py 
$2b$12$PyhdJi9.k7eyy4sXpLY3mevCgHmxWhr/hQGhLkZhd7sk8XZmM9SyS

(FastApiKUBERNETES_precioLuz) ubuntuserver@ubuntuserver-desktop:~/Escritorio/GSAD/FastApiKUBERNETES_precioLuz$ sqlite3 db.sqlite3 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.

sqlite> .tables
user

sqlite> .schema
CREATE TABLE IF NOT EXISTS "user" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "username" VARCHAR(50) NOT NULL UNIQUE,
    "password_hash" VARCHAR(128) NOT NULL,
    "companies" VARCHAR(128) NOT NULL
);
CREATE TABLE sqlite_sequence(name,seq);

sqlite> insert into user (username, password_hash, companies) values ('fernando','$asdf3 l4l4','company');
Error: UNIQUE constraint failed: user.username

sqlite> insert into user (username, password_hash, companies) values ('admin','$asdf3 l4l4','company'); 
'''
