# CVE-2019-15802 decrypter

The Zyxel firmware for the GS1900 switches, at least version 2.40(AAHH.2)C0,
contains a hardcoded parameters which are used for AES256-CBC encryption an
decryption of passwords. These parameters (IV, salt and password) are fixed
for all devices running the firmware.

```c
salt[] = "1A3BB2F78D6EC7D8";
iv[32] = "2268BA68768B58C3687D4F205923A741";
key_data[64] = "EC14D4F5BC6B9A3766D31EF9A1BB854121FB938B606462C70B2D0E26549C486A";
```

A longer write-up of this (and the associated issues) is available [here](https://jasper.la/exploring-zyxel-gs1900-firmware-with-ghidra.html) and Zyxel's advisory is [here]().

## decrypter

Based on the code in `libsal.so` (responsible the encryption and decryption in the
firmware) I hacked up a quick tool to demonstrate how these hardcoded parameters
can be used to decrypt passwords, e.g. in combination with [CVE-2019-15799](https://vimeo.com/354726424).

The hardcoded credentials in the firmware ([CVE-2019-15801](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15799)) 
were also encrypted with this key.
