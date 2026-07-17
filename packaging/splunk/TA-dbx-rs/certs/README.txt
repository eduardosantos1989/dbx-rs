Deployable database TLS material belongs in a connector-specific subdirectory.

PostgreSQL uses certs/psql, Oracle uses certs/oracle, SQL Server uses certs/mssql, MySQL uses
certs/mysql, and MariaDB uses certs/mariadb. Installation-specific files are ignored by default. Do
not place database passwords, HEC tokens, or generated HEC private identity in this directory.
