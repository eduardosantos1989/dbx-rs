Database query assets belong in a connector-specific subdirectory.

PostgreSQL uses queries/psql, Oracle uses queries/oracle, SQL Server uses queries/mssql, MySQL uses
queries/mysql, and MariaDB uses queries/mariadb. Deployment-specific SQL is ignored by default and
should be distributed through an approved deployment process. Only explicitly reviewed examples
belong in the public source tree.
