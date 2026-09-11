"""Import downloaded upstream vectors; never runs during tests and makes no HTTP calls.

Usage: python3 tests/reference/import-official-vectors.py /path/to/downloads
Inputs: vectors.json, bip-0032.mediawiki, bip-0350.mediawiki,
bip-0086.mediawiki, bip-0143.mediawiki, wallet-test-vectors.json,
test-vectors.csv. See fixtures/manifest.json for upstream sources and hashes.
Review all fixture/manifest diffs after updating; do not update expectations
by capturing output from the implementation under test.
"""
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys


def main(directory):
    target = Path(__file__).resolve().parents[1] / 'fixtures'
    manifest = json.loads((target / 'manifest.json').read_text())
    by_name = {v['file']: v for v in manifest}

    def save(name, value, source_name):
        source = directory / source_name
        data = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode()
        (target / name).write_bytes(data)
        by_name[name].update(sha256=hashlib.sha256(data).hexdigest(),
                             sourceSha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                             retrieved=datetime.date.today().isoformat())

    v = json.loads((directory / 'vectors.json').read_text(encoding='utf-8'))
    save('bip39.json', {lang:v[lang] for lang in ['english','japanese']}, 'vectors.json')
    s = (directory / 'bip-0032.mediawiki').read_text()
    valid = []
    for block in re.split(r'===Test vector \d+===', s)[1:5]:
        seed = re.search(r'Seed \(hex\): (\w+)', block)[1]
        for path, pub, prv in re.findall(r'\* Chain (.+)\n\*\* ext pub: (\w+)\n\*\* ext prv: (\w+)', block):
            valid.append(dict(seed=seed, path=path.replace('<sub>H</sub>', "'"), public=pub, private=prv))
    invalid = [dict(key=k,reason=r) for k,r in re.findall(r'^\* (\w+) \((.+)\)$', s.split('===Test vector 5===')[1], re.M)]
    assert len(valid)==17 and len(invalid)==16, 'Upstream BIP32 format or cases changed'
    save('bip32.json', dict(valid=valid, invalid=invalid), 'bip-0032.mediawiki')
    s = (directory / 'bip-0350.mediawiki').read_text().split('===Test vectors for v0-v16')[1].split('==Appendix')[0]
    a,b = s.split('The following list gives invalid')
    valid=[dict(address=x,script=y) for x,y in re.findall(r'\* <tt>(.*?)</tt>: <tt>(.*?)</tt>',a)]
    invalid=[dict(address=x,reason=y) for x,y in re.findall(r'\* <tt>(.*?)</tt>: (.*)',b)]
    assert len(valid)==8 and len(invalid)==15, 'Upstream BIP350 format or cases changed'
    save('bip350.json', dict(valid=valid,invalid=invalid), 'bip-0350.mediawiki')
    s = (directory / 'bip-0086.mediawiki').read_text()
    cases=[dict(path=path,**dict(re.findall(r'^(\w+)\s*= (\S+)',body,re.M))) for path,body in
           re.findall(r'// Account 0, .*? = (m/[^\n]+)\n(.*?)(?=\n//|</pre>)',s,re.S)]
    assert len(cases)==4, 'Upstream BIP86 format or cases changed'
    save('bip86.json', cases, 'bip-0086.mediawiki')
    s = (directory / 'bip-0143.mediawiki').read_text()
    raws=list(re.finditer(r'(?:unsigned transaction:|following transaction is [^\n]+?examples:)\s*([0-9a-f]+)',s))
    cases=[]
    for m in re.finditer(r'(?:hash )?preimage(?: for [A-Z|]+)?:\s*([0-9a-f]+)',s):
        pre=m[1]
        digest=re.search(r'sighash:\s*([0-9a-f]{64})',s[m.end():],re.I)[1]
        raw=[r[1] for r in raws if r.start()<m.start()][-1]
        assert hashlib.sha256(hashlib.sha256(bytes.fromhex(pre)).digest()).hexdigest()==digest
        cases.append(dict(raw=raw,preimage=pre,hash=digest))
    assert len(cases)==14, 'Upstream BIP143 format or cases changed'
    save('bip143.json', cases, 'bip-0143.mediawiki')
    save('bip341-wallet.json', (directory / 'wallet-test-vectors.json').read_bytes(), 'wallet-test-vectors.json')
    save('bip340.csv', (directory / 'test-vectors.csv').read_bytes(), 'test-vectors.csv')
    (target / 'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')


if __name__ == '__main__':
    main(Path(sys.argv[1]))
