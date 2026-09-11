"""Public test data only. Requires Python's OpenSSL scrypt and gcc.
Usage: python3 generate.py /path/to/aez5_software.zip /tmp/aez-comparison
The official C sources are compiled without modification. The empty
crypto_aead.h supplies the absent competition harness header; the bridge
uses Encrypt/Decrypt directly with aezeed parameters, not CAESAR defaults.
"""
import ctypes as c
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
import zipfile

archive, out = Path(sys.argv[1]), Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
source = out / 'ref'
source.mkdir(exist_ok=True)
with zipfile.ZipFile(archive) as z:
    for name in ['encrypt.c', 'blake2b.c', 'blake2b.h', 'rijndael-alg-fst.c', 'rijndael-alg-fst.h']:
        (source / name).write_bytes(z.read('crypto_aead/aezv5/ref/' + name))
(source / 'crypto_aead.h').write_text('/* No competition harness needed. */\n')
bridge = Path(__file__).with_name('bridge.c').resolve()
library = (out / 'reference.so').resolve()
subprocess.run(['gcc', '-shared', '-fPIC', '-O2', '-I', str(source), str(bridge),
                str(source / 'blake2b.c'), str(source / 'rijndael-alg-fst.c'),
                '-o', str(library)], check=True)
lib = c.CDLL(str(library))
for name, count in [('ref_extract', 2), ('ref_raw_decrypt', 3), ('ref_encrypt', 4), ('ref_decrypt', 3)]:
    fn = getattr(lib, name)
    fn.argtypes = [c.c_void_p] * count
    fn.restype = c.c_int if name == 'ref_decrypt' else None

def call(name, length, *args):
    result = c.create_string_buffer(length)
    status = getattr(lib, name)(*args, result)
    return result.raw, status

def crc(data):
    x = 0xffffffff
    for b in data:
        x ^= b
        for _ in range(8):
            x = (x >> 1) ^ (0x82f63b78 if x & 1 else 0)
    return (x ^ 0xffffffff).to_bytes(4, 'big')

def pack(cipher, salt):
    body = b'\0' + cipher + salt
    return body + crc(body)

assert crc(b'123456789').hex() == 'e3069283'

rng = random.Random(20260909)
def rand(n):
    return bytes(rng.randrange(256) for _ in range(n))
raw, end = [], []
for i in range(256):
    key = bytes([[0, 255, 85, 170][i]]) * 32 if i < 4 else rand(32)
    salt = rand(5)
    cipher = rand(23)
    encoded = pack(cipher, salt)
    plain, _ = call('ref_raw_decrypt', 23, key, encoded)
    extracted, _ = call('ref_extract', 48, key)
    assert extracted == hashlib.blake2b(key, digest_size=48).digest()
    raw.append(dict(Key=key.hex(), Encoded=encoded.hex(), Plain=plain.hex(), Extracted=extracted.hex()))

for i in range(32):
    password = ['', 'aezeed', 'ASCII !* password', '  秘密 café 🗝  ', 'e\u0301', 'é', 'x' * 200, ' '][i % 8]
    passbytes = password.encode() or b'aezeed'
    salt = rand(5)
    key = hashlib.scrypt(passbytes, salt=salt, n=32768, r=8, p=1, dklen=32, maxmem=67108864)
    plain = bytes([i if i < 31 else 255]) + rand(18)
    cipher, _ = call('ref_encrypt', 23, key, salt, plain)
    encoded = pack(cipher, salt)
    decoded, status = call('ref_decrypt', 19, key, encoded)
    assert status == 0 and decoded == plain
    tampered = bytearray(cipher); tampered[i % 23] ^= 1 << (i % 8)
    damaged = pack(bytes(tampered), salt)
    _, status = call('ref_decrypt', 19, key, damaged)
    assert status == -1
    changed_salt = bytes([salt[0] ^ 1]) + salt[1:]
    changed = pack(cipher, changed_salt)
    _, status = call('ref_decrypt', 19, key, changed)
    assert status == -1
    end.append(dict(Encoded=encoded.hex(), Password=password, Entropy=plain[3:].hex(),
                    Tampered=damaged.hex(), ChangedSalt=changed.hex(), Key=key.hex()))

result = dict(ArchiveSha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
              SourceHashes={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir()},
              Raw=raw, EndToEnd=end)
(out / 'vectors.json').write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf8')
print('Generated 256 raw AEZ comparisons and 32 end-to-end cases with official C. All C roundtrips and tamper rejections passed.')
