# 1C Password Audit Tool (1PAT)

[English](README.md) · **Русский**

Набор скриптов для аудита паролей системы 1С.

Настоящий проект основан на проекте [DPAT](https://github.com/clr2of8/DPAT). Автор выражает благодарность авторам указанного проекта.
При создании указанного репозитория использовалась информация из статьи .[«Ещё 1 раз про пентест 1С»](https://ardent101.github.io/posts/1c/). Автор также выражает благодарность её автору (Ardent101). 

## Что нужно

- Python 3.9 или новее
- `impacket` — только если используется скрипт удалённой выгрузки данных с сервера MSSQL
- `pycryptodome` — только если расшифровывается файл `1CV8Clst.lst`:

```bash
virtualenv env
source env/bin/activate
pip install impacket pycryptodome
```

## Описание скриптов

| Файл | Назначение |
| --- | --- |
| `export_v8users.py` | Подключается к MSSQL и выгружает данные из таблиц `v8users` всех баз данных в целевом формате |
| `decrypt_v8users.py` | Расшифровывает столбец `DATA` из данных таблиц `v8users` в целевом формате |
| `decrypt_v8clst.py` | Расшифровывает пароли учётных записей СУБД из файла `1CV8Clst.lst` |
| `export_decrypt_v8users.py` | Объединение скриптов `export_v8users.py` и `decrypt_v8users.py` |
| `1pat.py` | Генерирует отчёт аудита паролей системы 1С в HTML-формате |

## Как выгрузить дамп данных о паролях с сервера MSSQL

### Самостоятельная выгрузка из одной базы данных на сервере MSSQL

Если есть доступ к выполнению SQL-запросов на сервере MSSQL системы 1С, можно выполнить запрос в нужной базе данных и затем сохранить результат в файле в формате CSV.

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

### Самостоятельная выгрузка со всех баз данных на сервере MSSQL

Чтобы выгрузить данные со всех баз данных, можно выполнить:

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
```

Тот же скрипт лежит в [`sql/export_v8users.sql`](sql/export_v8users.sql).

### Удалённая выгрузка со всех баз данных на сервере MSSQL

Чтобы выгрузить данные со всех баз данных удалённо, можно воспользоваться скриптом `export_decrypt_v8users.py` (или `export_v8users.py`, если не требуется расшифровка столбца `DATA`):

```bash
python3 export_decrypt_v8users.py 'CORP/auditor:Secret@sql.example.local' --windows-auth -o dump.txt
python3 export_v8users.py 'CORP/auditor:Secret@sql.example.local' --windows-auth -o raw.txt
```

## Расшифровка столбца `DATA`

Если выгрузка содержит нерасшифрованный столбец `DATA` (блобы вида `0x…`), можно воспользоваться скриптом `decrypt_v8users.py` для его расшифровки:

```bash
python3 decrypt_v8users.py raw.txt -o dump.txt
```

## Расшифровка паролей СУБД из `1CV8Clst.lst`

Файл `1CV8Clst.lst` (обычно `C:\Program Files\1cv8\srvinfo\reg_xxxx\1CV8Clst.lst`) хранит идентификаторы и шифрованные пароли административных учётных записей СУБД, использующихся кластером 1С. Ключ шифрования и инициализационный вектор являются общеизвестными и постоянными. Файл `1CV8Clst.lst` можно дешифровать с использованием скрипта `decrypt_v8clst.py`:

```bash
python3 decrypt_v8clst.py 1CV8Clst.lst -o dbms.txt
```

Результат — таблица с полями через точку с запятой:

```
infobase;description;dbms;server;database;user;password
```

Отдельно можно расшифровать один блок в Base64:

```bash
python3 decrypt_v8clst.py '<Base64>'
```

## Сбор хешей для брута

Для сбора всех SHA1-хешей можно воспользоваться следующей командой:

```bash
grep -oE '[0-9a-fA-F]{40}' dump.txt > hashes.txt
```

В дальнейшем можно произвести перебор по словарю собранных SHA1-хешей с помощью утилиты Hashcat:

```bash
hashcat -m 100 hashes.txt wordlist.txt --potfile-path hashcat.potfile
```

## Создание отчёта о статистике паролей

```bash
python3 1pat.py -v dump.txt -c hashcat.potfile --no-prompt
```

По умолчанию главный файл отчёта — `_1CPasswordAuditReport.html` в каталоге `1PAT Report`. Язык HTML-отчёта по умолчанию русский (`-l en` для английского).

Если hashcat подобрал только пароль от SHA1 хеша пароля в верхнем регистре, то 1pat.py сам дополнительно перебирает регистр.

## Справка по флагам

### `export_v8users.py`

```
использование: export_v8users.py [-h] [--host HOST] [-port PORT]
                         [--domain DOMAIN] [-windows-auth]
                         [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                         [-aesKey HEX] [-dc-ip IP] [-target-ip IP]
                         [--database DATABASES] [-o OUTPUT]
                         [--timeout TIMEOUT] [--page-size PAGE_SIZE] [-v]
                         [target]

Выгрузка dbo.v8users с удалённого сервера MSSQL. Пароль передаётся
аргументом. Способы входа совпадают с Impacket mssqlclient.

позиционные аргументы:
  target                [[domain/]username[:password]@]host, тот же формат,
                        что у Impacket

параметры:
  -h, --help            показать эту справку и выйти
  --host HOST           хост SQL Server, если target не указан
  -port PORT, --port PORT
                        порт TDS, по умолчанию 1433
  --domain DOMAIN       домен, если его нет в target
  -windows-auth, --windows-auth
                        проверка подлинности Windows (NTLM), не SQL-логин
  --database DATABASES  только эта база данных. Можно указать несколько раз
  -o OUTPUT, --output OUTPUT
                        файл вывода. По умолчанию stdout
  --timeout TIMEOUT     таймаут подключения в секундах, по умолчанию 30
  --page-size PAGE_SIZE
                        сколько учёток читать за страницу OFFSET/FETCH.
                        По умолчанию 0 — один SELECT на базу (SQL Server
                        2008). Значение 50+ только для SQL Server 2012+
  -v, --verbose         дополнительная диагностика

проверка подлинности:
  -hashes LMHASH:NTHASH, --hashes LMHASH:NTHASH
                        хеши NTLM в формате LMHASH:NTHASH. Допускается
                        :NTHASH
  -no-pass, --no-pass   не требовать пароль (для -k и билета KRB5CCNAME)
  -k, --kerberos        Kerberos. Берёт KRB5CCNAME или данные из командной
                        строки
  -aesKey HEX, --aes-key HEX
                        AES-ключ Kerberos, 128 или 256 бит

подключение:
  -dc-ip IP, --dc-ip IP
                        контроллер домена для Kerberos. По умолчанию домен
                        из target
  -target-ip IP, --target-ip IP
                        IP сервера, если target — имя NetBIOS
```

### `decrypt_v8clst.py`

```
использование: decrypt_v8clst.py [-h] [-o OUTPUT] [-v] input

Расшифровывает пароли учётных записей СУБД из файла 1CV8Clst.lst.
Ключ и IV AES-128-CBC — общеизвестные константы платформы 1С.

позиционные аргументы:
  input                 файл 1CV8Clst.lst, один блок в Base64 или '-' для stdin

параметры:
  -h, --help            показать эту справку и выйти
  -o OUTPUT, --output OUTPUT
                        файл вывода. По умолчанию stdout
  -v, --verbose         дополнительная диагностика
```

### `decrypt_v8users.py`

```
использование: decrypt_v8users.py [-h] [-o OUTPUT] [-v] input_file

Производит дешифровку поля DATA (0x...)
name:desc:osname:date:hash1:hash2. Остальные поля не меняются. Строки,
которые расшифровать нельзя, отбрасываются.

позиционные аргументы:
  input_file            входной дамп таблицы v8users в UTF-8

параметры:
  -h, --help            показать эту справку и выйти
  -o OUTPUT, --output OUTPUT
                        файл вывода. По умолчанию stdout
  -v, --verbose         дополнительная диагностика
```

### `export_decrypt_v8users.py`

```
использование: export_decrypt_v8users.py [-h] [--host HOST] [-port PORT]
                                 [--domain DOMAIN] [-windows-auth]
                                 [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                                 [-aesKey HEX] [-dc-ip IP] [-target-ip IP]
                                 [--database DATABASES] [-o OUTPUT]
                                 [--timeout TIMEOUT] [--page-size PAGE_SIZE]
                                 [-v]
                                 [target]

Выгрузка всех таблиц v8users с удалённого сервера MSSQL и расшифровка поля
DATA (0x...) за один проход. Пароль передаётся аргументом. Способы входа
совпадают с Impacket mssqlclient.

позиционные аргументы:
  target                [[domain/]username[:password]@]host, тот же формат,
                        что у Impacket

параметры:
  -h, --help            показать эту справку и выйти
  --host HOST           хост SQL Server, если target не указан
  -port PORT, --port PORT
                        порт TDS, по умолчанию 1433
  --domain DOMAIN       домен, если его нет в target
  -windows-auth, --windows-auth
                        проверка подлинности Windows (NTLM), не SQL-логин
  --database DATABASES  только эта база данных. Можно указать несколько раз
  -o OUTPUT, --output OUTPUT
                        файл вывода. По умолчанию stdout
  --timeout TIMEOUT     таймаут подключения в секундах, по умолчанию 30
  --page-size PAGE_SIZE
                        сколько учёток читать за страницу OFFSET/FETCH.
                        По умолчанию 0 — один SELECT на базу (SQL Server
                        2008). Значение 50+ только для SQL Server 2012+
  -v, --verbose         дополнительная диагностика

проверка подлинности:
  -hashes LMHASH:NTHASH, --hashes LMHASH:NTHASH
                        хеши NTLM в формате LMHASH:NTHASH. Допускается
                        :NTHASH
  -no-pass, --no-pass   не требовать пароль (для -k и билета KRB5CCNAME)
  -k, --kerberos        Kerberos. Берёт KRB5CCNAME или данные из командной
                        строки
  -aesKey HEX, --aes-key HEX
                        AES-ключ Kerberos, 128 или 256 бит

подключение:
  -dc-ip IP, --dc-ip IP
                        контроллер домена для Kerberos. По умолчанию домен
                        из target
  -target-ip IP, --target-ip IP
                        IP сервера, если target — имя NetBIOS
```

### `1pat.py`

```
использование: 1pat.py [-h] -v V8USERS -c CRACKFILE [-o OUTPUTFILE]
               [-d REPORTDIRECTORY] [-w] [-s] [-g [GROUPLISTS ...]] [--open]
               [--no-prompt] [-l {en,ru}] [--verbose]

1C Password Audit Tool (1PAT): HTML-отчёт аудита паролей из выгрузки таблицы
v8users и potfile Hashcat.

параметры:
  -h, --help            показать эту справку и выйти
  -v V8USERS, --v8users V8USERS
                        дамп v8users (поля через точку с запятой)
  -c CRACKFILE, --crackfile CRACKFILE
                        результат подбора паролей в формате potfile Hashcat
  -o OUTPUTFILE, --outputfile OUTPUTFILE
                        имя главного HTML-файла, по умолчанию
                        _1CPasswordAuditReport.html
  -d REPORTDIRECTORY, --reportdirectory REPORTDIRECTORY
                        каталог для HTML-файлов, по умолчанию 1PAT Report
  -w, --writedb         записать базу SQLite на диск как pass_audit.db
  -s, --sanitize        спрятать пароли и хеши; к каталогу добавится
                        префикс «Sanitized - »
  -g [GROUPLISTS ...], --grouplists [GROUPLISTS ...]
                        файлы с именами участников группы. Имя группы берётся
                        из имени файла. Пример: -g "Administrators.txt"
  --open                сразу открыть HTML-отчёт в браузере
  --no-prompt           не спрашивать, открывать ли отчёт
  -l {en,ru}, --lang {en,ru}
                        язык HTML-отчёта: en или ru (по умолчанию)
  --verbose             дополнительная диагностика. Флаг -v уже занят
                        файлом v8users
```
