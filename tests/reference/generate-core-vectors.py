"""Offline reference fixtures using Python's stdlib, independently of PowerShell.

Run from any directory: python3 tests/reference/generate-core-vectors.py
This small affine-curve implementation is for public test data only.
It is deliberately not a production cryptography library.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def sha(data):
    return hashlib.sha256(data).digest()


def double_sha(data):
    return sha(sha(data))


def hash160(data):
    return hashlib.new('ripemd160', sha(data)).digest()


def tagged(tag, data):
    t = sha(tag.encode())
    return sha(t + t + data)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3*x*x) * pow(2*y, -1, P) if a == b else (v-y)*pow(u-x, -1, P)) % P
    rx = (slope*slope-x-u) % P
    return rx, (slope*(x-rx)-y) % P


def mul(k, point=G):
    r = None
    k %= N
    while k:
        if k & 1:
            r = add(r, point)
        point = add(point, point)
        k >>= 1
    return r


def public(d, compressed=True):
    x, y = mul(d)
    return (bytes([2+(y & 1)]) + x.to_bytes(32,'big') if compressed else
            b'\x04' + x.to_bytes(32,'big') + y.to_bytes(32,'big'))


def base58(data):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = int.from_bytes(data + double_sha(data)[:4], 'big')
    result = ''
    while value:
        value, digit = divmod(value, 58)
        result = alphabet[digit] + result
    return '1'*(len(data)-len(data.lstrip(b'\0'))) + result


def bech32(program, hrp, version):
    alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    bits = ''.join(f'{b:08b}' for b in program)
    bits += '0' * (-len(bits) % 5)
    data = [version] + [int(bits[i:i+5],2) for i in range(0,len(bits),5)]
    chk = 1
    expanded = [ord(c)>>5 for c in hrp]+[0]+[ord(c)&31 for c in hrp]
    for value in expanded+data+[0]*6:
        high = chk >> 25
        chk = ((chk & 0x1ffffff)<<5) ^ value
        for i, gen in enumerate([0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]):
            if (high>>i)&1:
                chk ^= gen
    chk ^= 1 if version == 0 else 0x2bc830a3
    return hrp+'1'+''.join(alphabet[x] for x in data+[chk>>(5*i)&31 for i in range(5,-1,-1)])


def cs(n):
    if n < 253:
        return bytes([n])
    for size, prefix in [(2,253),(4,254),(8,255)]:
        if n < 1 << (8*size):
            return bytes([prefix])+n.to_bytes(size,'little')
    raise ValueError(n)


def field(data):
    return cs(len(data))+data


def nonce(d, digest):
    seed = d.to_bytes(32,'big')+(int.from_bytes(digest,'big') % N).to_bytes(32,'big')
    k, v = b'\0'*32, b'\1'*32
    mac = lambda key, data: hmac.new(key,data,hashlib.sha256).digest()
    k = mac(k,v+b'\0'+seed)
    v = mac(k,v)
    k = mac(k,v+b'\1'+seed)
    v = mac(k,v)
    while True:
        v = mac(k,v)
        candidate = int.from_bytes(v,'big')
        if 0 < candidate < N:
            return candidate
        k = mac(k,v+b'\0')
        v = mac(k,v)


def sign(d, digest):
    k = nonce(d,digest)
    x,y = mul(k)
    r = x % N
    s = (int.from_bytes(digest,'big') + r*d)*pow(k,-1,N) % N
    rec = (2 if x >= N else 0) | (y & 1)
    if s > N//2:
        s = N-s
        rec ^= 1
    return r,s,rec


def der_int(n):
    b = n.to_bytes((n.bit_length()+7)//8,'big')
    if b[0]&128:
        b=b'\0'+b
    return b'\2'+field(b)


def generate():
    result = {'addresses':[], 'ecdsa':[], 'messages':[], 'sighashes':[]}
    for d in [1,2,3,7,N-1]:
        pub=public(d)
        wscript=b'\x21'+pub+b'\xac'
        witness=sha(wscript)
        p=mul(d)
        even=(p[0],p[1] if p[1]%2==0 else P-p[1])
        tweak=int.from_bytes(tagged('TapTweak',p[0].to_bytes(32,'big')),'big')
        output=add(even,mul(tweak))[0].to_bytes(32,'big')
        internal=int('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',16)
        y=pow((internal**3+7)%P,(P+1)//4,P)
        h=(internal,y if y%2==0 else P-y)
        tapscript=b'\x20'+pub[1:]+b'\xac'
        leaf=tagged('TapLeaf',b'\xc0'+field(tapscript))
        q=add(h,mul(int.from_bytes(tagged('TapTweak',internal.to_bytes(32,'big')+leaf),'big')))
        script_output=q[0].to_bytes(32,'big')
        control=bytes([0xc0+(q[1]&1)])+internal.to_bytes(32,'big')
        for testnet in [False,True]:
            hrp='tb' if testnet else 'bc'
            prefix=b'\xc4' if testnet else b'\x05'
            entry=dict(private=f'{d:064x}',public=pub.hex(),uncompressed=public(d,False).hex(),testnet=testnet)
            entry.update(wif=base58((b'\xef' if testnet else b'\x80')+d.to_bytes(32,'big')+b'\1'),
                         wifUC=base58((b'\xef' if testnet else b'\x80')+d.to_bytes(32,'big')))
            scripts={
                'P2PKH': b'\x76\xa9\x14'+hash160(pub)+b'\x88\xac',
                'P2SH': b'\xa9\x14'+hash160(wscript)+b'\x87',
                'P2SH-P2WPKH': b'\xa9\x14'+hash160(b'\0\x14'+hash160(pub))+b'\x87',
                'P2SH-P2WSH': b'\xa9\x14'+hash160(b'\0\x20'+witness)+b'\x87',
                'P2WPKH': b'\0\x14'+hash160(pub), 'P2WSH': b'\0\x20'+witness, 'P2TR': b'\x51\x20'+output, 'P2TR-SP': b'\x51\x20'+script_output}
            addresses={}
            for name,script in scripts.items():
                if name=='P2PKH':
                    addr=base58((b'\x6f' if testnet else b'\0')+hash160(pub))
                elif name.startswith('P2SH'):
                    addr=base58(prefix+script[2:-1])
                else:
                    addr=bech32(script[2:],hrp,1 if name.startswith('P2TR') else 0)
                addresses[name]=dict(address=addr,script=script.hex())
            entry['addresses']=addresses
            entry['tapScript']=tapscript.hex()
            entry['controlBlock']=control.hex()
            result['addresses'].append(entry)
    for d,data in [(1,b'\x00'),(2,b'hello'),(3,bytes(range(256)))]:
        digest=double_sha(data)
        r,s,rec=sign(d,digest)
        der=der_int(r)+der_int(s)
        result['ecdsa'].append(dict(private=f'{d:064x}',public=public(d).hex(),data=data.hex(),digest=digest.hex(),nonce=f'{nonce(d,digest):064x}',signature=(b'\x30'+field(der)+b'\1').hex()))
    for text in ['', 'hello', '日本語 🔑', 'a'*252, 'a'*253, 'a'*65536]:
        message=text.encode()
        digest=double_sha(field(b'Bitcoin Signed Message:\n')+field(message))
        r,s,rec=sign(1,digest)
        result['messages'].append(dict(message=text,signature=base64.b64encode(bytes([31+rec])+r.to_bytes(32,'big')+s.to_bytes(32,'big')).decode()))

    inputs=[dict(txid=bytes(range(32)).hex(),index=3,sequence=0xfffffffd,value=100000,script='0014'+'11'*20),dict(txid=bytes(range(32,64)).hex(),index=7,sequence=0xfffffffc,value=200000,script='5120'+'22'*32)]
    outputs=[dict(value=120000,script='76a914'+'33'*20+'88ac'),dict(value=179000,script='0014'+'44'*20)]
    result['transaction']=dict(version=2,locktime=500,inputs=inputs,outputs=outputs)
    outpoints=[bytes.fromhex(i['txid'])[::-1]+i['index'].to_bytes(4,'little') for i in inputs]
    sequences=[i['sequence'].to_bytes(4,'little') for i in inputs]
    serialized_out=[o['value'].to_bytes(8,'little')+field(bytes.fromhex(o['script'])) for o in outputs]
    version=(2).to_bytes(4,'little');locktime=(500).to_bytes(4,'little')
    for index in range(2):
        for flag in [1,2,3,0x81,0x82,0x83]:
            base=flag&31; acp=bool(flag&128)
            script=b'\x76\xa9\x14'+b'\x11'*20+b'\x88\xac'
            pre=(version+(bytes(32) if acp else double_sha(b''.join(outpoints)))+
                 (bytes(32) if acp or base in [2,3] else double_sha(b''.join(sequences)))+
                 outpoints[index]+field(script)+inputs[index]['value'].to_bytes(8,'little')+sequences[index]+
                 (double_sha(b''.join(serialized_out)) if base==1 else double_sha(serialized_out[index]) if base==3 else bytes(32))+
                 locktime+flag.to_bytes(4,'little'))
            result['sighashes'].append(dict(kind='segwit',index=index,flag=flag,scriptCode=field(script).hex(),preimage=pre.hex(),digest=double_sha(pre).hex()))
        for flag in [0,1,2,3,0x81,0x82,0x83]:
            for ext in [0,1]:
                for annex in [b'',b'\x50\x12\x34']:
                    base=flag&3;acp=bool(flag&128)
                    pre=bytes([flag])+version+locktime
                    if not acp:
                        pre+=sha(b''.join(outpoints))+sha(b''.join(i['value'].to_bytes(8,'little') for i in inputs))
                        pre+=sha(b''.join(field(bytes.fromhex(i['script'])) for i in inputs))+sha(b''.join(sequences))
                    if base not in [2,3]:
                        pre+=sha(b''.join(serialized_out))
                    pre+=bytes([2*ext+bool(annex)])
                    if acp:
                        pre+=outpoints[index]+inputs[index]['value'].to_bytes(8,'little')+field(bytes.fromhex(inputs[index]['script']))+sequences[index]
                    else:
                        pre+=index.to_bytes(4,'little')
                    if annex:
                        pre+=sha(field(annex))
                    if base==3:
                        pre+=sha(serialized_out[index])
                    leaf=b'\x55'*32 if ext else b''
                    if ext:
                        pre+=leaf+b'\0'+bytes.fromhex('ffffffff')
                    result['sighashes'].append(dict(kind='taproot',index=index,flag=flag,extension=ext,annex=annex.hex(),leaf=leaf.hex(),preimage=pre.hex(),digest=tagged('TapSighash',b'\0'+pre).hex()))
    return result


if __name__=='__main__':
    target=Path(__file__).resolve().parents[1]/'fixtures/core.json'
    target.write_text(json.dumps(generate(),indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(target)
