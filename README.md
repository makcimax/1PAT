# 1C Password Audit Tool (1PAT)

**English** · [Русский](README.ru.md)

A set of scripts for auditing 1C passwords.

This project is based on [DPAT](https://github.com/clr2of8/DPAT). The author thanks the authors of that project.

This repository was created using information from the article [«Ещё 1 раз про пентест 1С»](https://ardent101.github.io/posts/1c/). The author also thanks its author (Ardent101).

## What you need

- Python 3.9 or newer
- `impacket` — only if you use remote export from an MSSQL server
- `pycryptodome` — only if you decrypt `1CV8Clst.lst`:

```bash
virtualenv env
source env/bin/activate
pip install impacket pycryptodome
```

## Scripts

| File | Purpose |
| --- | --- |
| `export_v8users.py` | Connects to MSSQL and exports `v8users` from every database in the target format |
| `decrypt_v8users.py` | Decrypts the `DATA` column from `v8users` dumps in the target format |
| `decrypt_v8clst.py` | Decrypts DBMS account passwords from a `1CV8Clst.lst` file |
| `export_decrypt_v8users.py` | Combines `export_v8users.py` and `decrypt_v8users.py` |
| `1pat.py` | Builds an HTML report for a 1C password audit |

## How to export a password dump from MSSQL

### One database, from SSMS

If you can run SQL on the 1C MSSQL server, run this query in the database you need and save the result as a CSV file.

```sql
SELECT
    DB_NAME() AS DatabaseName,
    u.[Name],
    u.[Descr],
    u.[OSName],
    u.[Changed],
    CONVERT(NVARCHAR(4000), u.[RolesID]) AS RolesID,
    CONVERT(INT, u.[Show]) AS [Show],
    '0x' + CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), u.[Data]), 2) AS [Data],
    CONVERT(INT, u.[EAuth]) AS EAuth,
    CONVERT(INT, u.[AdmRole]) AS AdmRole,
    CONVERT(NVARCHAR(255), u.[UsSprH]) AS UsSprH,
    CASE
        WHEN ISNULL(u.[EAuth], 0) <> 0 THEN 1
        WHEN NULLIF(LTRIM(RTRIM(u.[OSName])), N'') IS NOT NULL THEN 1
        ELSE 0
    END AS LoginEnabled
FROM dbo.v8users AS u
ORDER BY u.[Name];
```

### Every database, from SSMS

To export from every database on the server, run:

```sql
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

        PRINT N'Processed database: ' + @DatabaseName;
    END TRY
    BEGIN CATCH
        PRINT N'Error in database ' + @DatabaseName + N': ' + ERROR_MESSAGE();
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
```

The same script is in [`sql/export_v8users.sql`](sql/export_v8users.sql).

### Remote export from every database

To export remotely from every database, use `export_decrypt_v8users.py` (or `export_v8users.py` if you do not need to decrypt `DATA`):

```bash
python3 export_decrypt_v8users.py 'CORP/auditor:Secret@sql.example.local' --windows-auth -o dump.txt
python3 export_v8users.py 'CORP/auditor:Secret@sql.example.local' --windows-auth -o raw.txt
```

## Decrypt the `DATA` column

If the dump still has an encrypted `DATA` column (blobs like `0x…`), decrypt it with `decrypt_v8users.py`:

```bash
python3 decrypt_v8users.py raw.txt -o dump.txt
```

## Decrypt DBMS passwords from `1CV8Clst.lst`

The `1CV8Clst.lst` file (usually `C:\Program Files\1cv8\srvinfo\reg_xxxx\1CV8Clst.lst`) stores identifiers and encrypted passwords of the DBMS administrative accounts used by the 1C cluster. The encryption key and initialization vector are publicly known and constant. You can decrypt `1CV8Clst.lst` with `decrypt_v8clst.py`:

```bash
python3 decrypt_v8clst.py 1CV8Clst.lst -o dbms.txt
```

The result is a semicolon-separated table:

```
infobase;description;dbms;server;database;user;password
```

You can also decrypt a single Base64 blob:

```bash
python3 decrypt_v8clst.py '<Base64>'
```

## Collecting hashes for cracking

To collect every SHA1 hash, run:

```bash
grep -oE '[0-9a-fA-F]{40}' dump.txt > hashes.txt
```

You can then attack the collected SHA1 hashes with a wordlist in Hashcat:

```bash
hashcat -m 100 hashes.txt wordlist.txt --potfile-path hashcat.potfile
```

## Build the password report

```bash
python3 1pat.py -v dump.txt -c hashcat.potfile --no-prompt
```

By default the main report file is `_1CPasswordAuditReport.html` in the `1PAT Report` folder. The HTML report language is Russian by default (`-l en` for English).

If hashcat recovered only the password for the uppercase SHA1 hash, `1pat.py` also tries case variations itself.

## Command-line help

### `export_v8users.py`

```
usage: export_v8users.py [-h] [--host HOST] [-port PORT] [--domain DOMAIN]
                         [-windows-auth] [-hashes LMHASH:NTHASH] [-no-pass]
                         [-k] [-aesKey HEX] [-dc-ip IP] [-target-ip IP]
                         [--database DATABASES] [-o OUTPUT]
                         [--timeout TIMEOUT] [--page-size PAGE_SIZE] [-v]
                         [target]

Export dbo.v8users from a remote MSSQL server. Password is passed as an
argument. Authentication matches Impacket mssqlclient.

positional arguments:
  target                [[domain/]username[:password]@]host, same format as
                        Impacket

options:
  -h, --help            show this help message and exit
  --host HOST           SQL Server host if target is omitted
  -port PORT, --port PORT
                        TDS port, default 1433
  --domain DOMAIN       Domain if it is not in target
  -windows-auth, --windows-auth
                        Windows Authentication (NTLM), not a SQL login
  --database DATABASES  Limit to this database. Repeatable
  -o OUTPUT, --output OUTPUT
                        Output file. Defaults to stdout
  --timeout TIMEOUT     Connect timeout in seconds, default 30
  --page-size PAGE_SIZE
                        Users per OFFSET/FETCH page. Default 0 = one SELECT
                        per database (works on SQL Server 2008). Use 50+ only
                        on SQL Server 2012+
  -v, --verbose         Print extra diagnostic information

authentication:
  -hashes LMHASH:NTHASH, --hashes LMHASH:NTHASH
                        NTLM hashes, format LMHASH:NTHASH. :NTHASH is accepted
  -no-pass, --no-pass   Do not require a password (for -k and a KRB5CCNAME
                        ticket)
  -k, --kerberos        Kerberos. Uses KRB5CCNAME or credentials from the
                        command line
  -aesKey HEX, --aes-key HEX
                        Kerberos AES key, 128 or 256 bits

connection:
  -dc-ip IP, --dc-ip IP
                        Domain controller for Kerberos. Defaults to the domain
                        in target
  -target-ip IP, --target-ip IP
                        Server IP when target is a NetBIOS name
```

### `decrypt_v8clst.py`

```
usage: decrypt_v8clst.py [-h] [-o OUTPUT] [-v] input

Decrypts DBMS account passwords from a 1CV8Clst.lst file. The AES-128-CBC
key and IV are public 1C platform constants.

positional arguments:
  input                 1CV8Clst.lst file, a single Base64 ciphertext, or '-'
                        for stdin

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file. Defaults to stdout
  -v, --verbose         Print extra diagnostic information
```

### `decrypt_v8users.py`

```
usage: decrypt_v8users.py [-h] [-o OUTPUT] [-v] input_file

Decrypts the DATA field (0x...) to name:desc:osname:date:hash1:hash2. Other
fields are kept. Lines that cannot be decrypted are dropped.

positional arguments:
  input_file            Input v8users table dump in UTF-8

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file. Defaults to stdout
  -v, --verbose         Print extra diagnostic information
```

### `export_decrypt_v8users.py`

```
usage: export_decrypt_v8users.py [-h] [--host HOST] [-port PORT]
                                 [--domain DOMAIN] [-windows-auth]
                                 [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                                 [-aesKey HEX] [-dc-ip IP] [-target-ip IP]
                                 [--database DATABASES] [-o OUTPUT]
                                 [--timeout TIMEOUT] [--page-size PAGE_SIZE]
                                 [-v]
                                 [target]

Export all v8users tables from a remote MSSQL server and decrypt the DATA
field (0x...) in one pass. The password is passed as an argument.
Authentication matches Impacket mssqlclient.

positional arguments:
  target                [[domain/]username[:password]@]host, same format as
                        Impacket

options:
  -h, --help            show this help message and exit
  --host HOST           SQL Server host if target is omitted
  -port PORT, --port PORT
                        TDS port, default 1433
  --domain DOMAIN       Domain if it is not in target
  -windows-auth, --windows-auth
                        Windows Authentication (NTLM), not a SQL login
  --database DATABASES  Limit to this database. Repeatable
  -o OUTPUT, --output OUTPUT
                        Output file. Defaults to stdout
  --timeout TIMEOUT     Connect timeout in seconds, default 30
  --page-size PAGE_SIZE
                        Users per OFFSET/FETCH page. Default 0 = one SELECT
                        per database (works on SQL Server 2008). Use 50+ only
                        on SQL Server 2012+
  -v, --verbose         Print extra diagnostic information

authentication:
  -hashes LMHASH:NTHASH, --hashes LMHASH:NTHASH
                        NTLM hashes, format LMHASH:NTHASH. :NTHASH is accepted
  -no-pass, --no-pass   Do not require a password (for -k and a KRB5CCNAME
                        ticket)
  -k, --kerberos        Kerberos. Uses KRB5CCNAME or credentials from the
                        command line
  -aesKey HEX, --aes-key HEX
                        Kerberos AES key, 128 or 256 bits

connection:
  -dc-ip IP, --dc-ip IP
                        Domain controller for Kerberos. Defaults to the domain
                        in target
  -target-ip IP, --target-ip IP
                        Server IP when target is a NetBIOS name
```

### `1pat.py`

```
usage: 1pat.py [-h] -v V8USERS -c CRACKFILE [-o OUTPUTFILE]
               [-d REPORTDIRECTORY] [-w] [-s] [-g [GROUPLISTS ...]] [--open]
               [--no-prompt] [-l {en,ru}] [--verbose]

1C Password Audit Tool (1PAT): HTML password-audit report from a v8users table
dump and a Hashcat potfile.

options:
  -h, --help            show this help message and exit
  -v V8USERS, --v8users V8USERS
                        v8users dump (semicolon-separated)
  -c CRACKFILE, --crackfile CRACKFILE
                        Password cracking output in Hashcat potfile form
  -o OUTPUTFILE, --outputfile OUTPUTFILE
                        HTML report file name, defaults to
                        _1CPasswordAuditReport.html
  -d REPORTDIRECTORY, --reportdirectory REPORTDIRECTORY
                        Folder for HTML files, defaults to 1PAT Report
  -w, --writedb         Write SQLite database to disk as "pass_audit.db"
  -s, --sanitize        Sanitize the report and prepend the directory with
                        "Sanitized - "
  -g [GROUPLISTS ...], --grouplists [GROUPLISTS ...]
                        Files with usernames of a group. The group name is
                        taken from the file name. Example: -g
                        "Administrators.txt"
  --open                Open the HTML report in a browser after generation
  --no-prompt           Do not ask whether to open the report
  -l {en,ru}, --lang {en,ru}
                        HTML report language: en or ru (default)
  --verbose             Print extra diagnostic information. -v is already used
                        for the v8users file
```
