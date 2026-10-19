/*
  Обход всех доступных баз, сбор dbo.v8users.

  Первые 11 колонок — как раньше, порядок не меняется:
    DatabaseName; Name; Descr; OSName; Changed; RolesID; Show; Data; EAuth; AdmRole; UsSprH

  В конце добавлена:
    LoginEnabled  — 1, если можно войти паролем (EAuth<>0) или через ОС (OSName заполнен)

  «Недействителен» в справочнике Пользователи (БСП) здесь не видно — это другая таблица.

  Удалённый вариант с логином: export_v8users.py
*/
SET NOCOUNT ON;

IF OBJECT_ID('tempdb..#AllUsers') IS NOT NULL
    DROP TABLE #AllUsers;

CREATE TABLE #AllUsers (
    [DatabaseName] NVARCHAR(255)  NOT NULL,
    [Name]         NVARCHAR(255)  NULL,
    [Descr]        NVARCHAR(MAX)  NULL,
    [OSName]       NVARCHAR(255)  NULL,
    [Changed]      DATETIME       NULL,
    [RolesID]      NVARCHAR(MAX)  NULL,
    [Show]         INT            NULL,
    [Data]         VARBINARY(MAX) NULL,
    [EAuth]        INT            NULL,
    [AdmRole]      INT            NULL,
    [UsSprH]       NVARCHAR(255)  NULL
);

DECLARE @DatabaseName SYSNAME;
DECLARE @SQL NVARCHAR(MAX);

DECLARE db_cursor CURSOR LOCAL FAST_FORWARD FOR
SELECT name
FROM sys.databases
WHERE state = 0
  AND HAS_DBACCESS(name) = 1
  AND name NOT IN (N'master', N'model', N'msdb', N'tempdb')
  AND name NOT LIKE N'ReportServer%'
ORDER BY name;

OPEN db_cursor;
FETCH NEXT FROM db_cursor INTO @DatabaseName;

WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        SET @SQL = N'
        IF EXISTS (
            SELECT 1
            FROM ' + QUOTENAME(@DatabaseName) + N'.sys.tables AS t
            INNER JOIN ' + QUOTENAME(@DatabaseName) + N'.sys.schemas AS s ON s.schema_id = t.schema_id
            WHERE t.name = N''v8users'' AND s.name = N''dbo'' AND t.type = N''U''
        )
        BEGIN
            INSERT INTO #AllUsers
                ([DatabaseName], [Name], [Descr], [OSName], [Changed],
                 [RolesID], [Show], [Data], [EAuth], [AdmRole], [UsSprH])
            SELECT
                @db,
                u.[Name],
                u.[Descr],
                u.[OSName],
                u.[Changed],
                CONVERT(NVARCHAR(4000), u.[RolesID]),
                CONVERT(INT, u.[Show]),
                CONVERT(VARBINARY(MAX), u.[Data]),
                CONVERT(INT, u.[EAuth]),
                CONVERT(INT, u.[AdmRole]),
                CONVERT(NVARCHAR(255), u.[UsSprH])
            FROM ' + QUOTENAME(@DatabaseName) + N'.[dbo].[v8users] AS u;
        END';

        EXEC sp_executesql @SQL, N'@db SYSNAME', @db = @DatabaseName;

        PRINT N'Обработана база: ' + @DatabaseName;
    END TRY
    BEGIN CATCH
        PRINT N'Ошибка в базе ' + @DatabaseName + N': ' + ERROR_MESSAGE();
    END CATCH;

    FETCH NEXT FROM db_cursor INTO @DatabaseName;
END;

CLOSE db_cursor;
DEALLOCATE db_cursor;

SELECT
    [DatabaseName],
    [Name],
    [Descr],
    [OSName],
    [Changed],
    [RolesID],
    [Show],
    '0x' + CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), [Data]), 2) AS [Data],
    [EAuth],
    [AdmRole],
    [UsSprH],
    CASE
        WHEN ISNULL([EAuth], 0) <> 0 THEN 1
        WHEN NULLIF(LTRIM(RTRIM([OSName])), N'') IS NOT NULL THEN 1
        ELSE 0
    END AS [LoginEnabled]
FROM #AllUsers
ORDER BY [DatabaseName], [Name];

DROP TABLE #AllUsers;
