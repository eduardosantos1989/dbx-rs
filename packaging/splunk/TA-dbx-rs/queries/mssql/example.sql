SELECT CAST(SYSUTCDATETIME() AS datetime2(6)) AS collected_at, DB_NAME() AS database_name, CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')) AS server_version
