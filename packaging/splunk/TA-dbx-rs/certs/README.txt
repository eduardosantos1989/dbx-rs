Deployable database TLS material belongs in a connector-specific subdirectory.

PostgreSQL uses certs/psql. Installation-specific files are ignored by default. Do not place
database passwords, HEC tokens, or generated HEC private identity in this directory.
