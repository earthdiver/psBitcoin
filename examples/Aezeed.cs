// aezeed v0 decoding for psBitcoin. No external assemblies or network access.
// Copyright (c) 2026 earthdiver1. CC BY-SA 4.0, like psBitcoin.
// AEZ-Tiny adapted from Yawning Angel's CC0 AEZ v5 implementation:
// https://github.com/Yawning/aez/tree/e49e68abd344
// Format: https://github.com/lightningnetwork/lnd/tree/master/aezeed
// scrypt: RFC 7914; BLAKE2b: RFC 7693; AES round: FIPS 197.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace PsBitcoin
{
    // Deliberately limited to aezeed v0's fixed sizes and parameters, not a
    // general-purpose AEZ/scrypt API. All owned working arrays are wiped.
    public sealed class AezeedEntropyDecoder : IDisposable
    {
        private readonly List<Array> buffers = new List<Array>();
        private byte[] Bytes(int n) { byte[] a = new byte[n]; buffers.Add(a); return a; }
        private uint[] Words(int n) { uint[] a = new uint[n]; buffers.Add(a); return a; }
        private ulong[] Longs(int n) { ulong[] a = new ulong[n]; buffers.Add(a); return a; }
        private AezeedEntropyDecoder() { }
        public void Dispose()
        {
            foreach (Array a in buffers) Array.Clear(a, 0, a.Length);
            buffers.Clear();
        }

        public static byte[] Decode(byte[] encoded, byte[] passphrase)
        {
            if (encoded == null || encoded.Length != 33)
                throw new ArgumentException("aezeed must encode exactly 33 bytes (24 words).");
            if (encoded[0] != 0)
                throw new ArgumentException("Unsupported aezeed cipher version; only version 0 is supported.");
            uint crc = 0xffffffff;
            for (int i = 0; i < 29; i++)
            {
                crc ^= encoded[i];
                for (int j = 0; j < 8; j++)
                    crc = (crc >> 1) ^ (0x82f63b78U & (0U - (crc & 1)));
            }
            uint expected = ((uint)encoded[29] << 24) | ((uint)encoded[30] << 16)
                | ((uint)encoded[31] << 8) | encoded[32];
            if (~crc != expected)
                throw new ArgumentException("Invalid aezeed checksum; check the mnemonic words and order.");

            using (AezeedEntropyDecoder d = new AezeedEntropyDecoder())
            {
                byte[] salt = d.Bytes(5);
                Array.Copy(encoded, 24, salt, 0, 5);
                byte[] password = passphrase;
                if (password == null || password.Length == 0)
                {
                    password = d.Bytes(6);
                    Array.Copy(new byte[] { 97, 101, 122, 101, 101, 100 }, password, 6);
                }
                byte[] key = d.Scrypt(password, salt);
                byte[] plain = d.DecryptTiny(key, encoded);
                int invalid = 0;
                for (int i = 19; i < 23; i++) invalid |= plain[i];
                if (invalid != 0)
                    throw new ArgumentException("Invalid aezeed passphrase or authentication tag.");
                // As in LND aezeed.ToCipherSeed, the internal version is
                // metadata, not a condition for extracting entropy. A wallet
                // may validate it when selecting its child derivation scheme.
                // The outer cipher version and authentication were checked above.
                byte[] entropy = new byte[16];
                Array.Copy(plain, 3, entropy, 0, 16);
                return entropy;
            }
        }

        private static uint Read32(byte[] b, int p)
        {
            return (uint)b[p] | ((uint)b[p + 1] << 8)
                | ((uint)b[p + 2] << 16) | ((uint)b[p + 3] << 24);
        }
        private static uint Rotate(uint x, int n) { return (x << n) | (x >> (32 - n)); }
        private static ulong RotateRight(ulong x, int n) { return (x >> n) | (x << (64 - n)); }

        // PBKDF2-HMAC-SHA256 with one iteration, as required by scrypt.
        private byte[] Pbkdf(byte[] password, byte[] salt, int length)
        {
            byte[] result = Bytes(length), input = Bytes(salt.Length + 4);
            Array.Copy(salt, input, salt.Length);
            using (HMACSHA256 hmac = new HMACSHA256(password))
            {
                for (int offset = 0, block = 1; offset < length; offset += 32, block++)
                {
                    input[salt.Length] = (byte)(block >> 24);
                    input[salt.Length + 1] = (byte)(block >> 16);
                    input[salt.Length + 2] = (byte)(block >> 8);
                    input[salt.Length + 3] = (byte)block;
                    byte[] hash = hmac.ComputeHash(input);
                    try { Array.Copy(hash, 0, result, offset, Math.Min(32, length - offset)); }
                    finally { Array.Clear(hash, 0, hash.Length); }
                }
            }
            return result;
        }

        private static void Quarter(uint[] x, int a, int b, int c, int d)
        {
            unchecked
            {
                x[b] ^= Rotate(x[a] + x[d], 7);
                x[c] ^= Rotate(x[b] + x[a], 9);
                x[d] ^= Rotate(x[c] + x[b], 13);
                x[a] ^= Rotate(x[d] + x[c], 18);
            }
        }

        // Salsa20/8 BlockMix, r=8. Scratch buffers are reused for every round.
        private static void BlockMix(uint[] input, uint[] output, uint[] state, uint[] work)
        {
            Array.Copy(input, 240, state, 0, 16);
            for (int block = 0; block < 16; block++)
            {
                for (int k = 0; k < 16; k++) work[k] = state[k] ^= input[block * 16 + k];
                for (int round = 0; round < 4; round++)
                {
                    Quarter(work, 0, 4, 8, 12); Quarter(work, 5, 9, 13, 1);
                    Quarter(work, 10, 14, 2, 6); Quarter(work, 15, 3, 7, 11);
                    Quarter(work, 0, 1, 2, 3); Quarter(work, 5, 6, 7, 4);
                    Quarter(work, 10, 11, 8, 9); Quarter(work, 15, 12, 13, 14);
                }
                int target = (block / 2 + (block % 2) * 8) * 16;
                for (int k = 0; k < 16; k++)
                    output[target + k] = state[k] = unchecked(state[k] + work[k]);
            }
        }

        private byte[] Scrypt(byte[] password, byte[] salt)
        {
            const int n = 32768, size = 256; // N=32768, r=8, p=1, dkLen=32
            byte[] b = Pbkdf(password, salt, 1024);
            uint[] x = Words(size), y = Words(size), v = Words(n * size);
            uint[] state = Words(16), work = Words(16);
            for (int i = 0; i < size; i++) x[i] = Read32(b, i * 4);
            for (int i = 0; i < n; i++)
            {
                Array.Copy(x, 0, v, i * size, size);
                BlockMix(x, y, state, work);
                uint[] swap = x; x = y; y = swap;
            }
            for (int i = 0; i < n; i++)
            {
                int offset = (int)(x[240] & (n - 1)) * size;
                for (int k = 0; k < size; k++) x[k] ^= v[offset + k];
                BlockMix(x, y, state, work);
                uint[] swap = x; x = y; y = swap;
            }
            for (int i = 0; i < size; i++)
                for (int k = 0; k < 4; k++) b[i * 4 + k] = (byte)(x[i] >> (8 * k));
            return Pbkdf(password, b, 32);
        }

        private static readonly ulong[] IV = {
            0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
            0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
        };
        private static readonly byte[,] Sigma = {
            {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
            {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
            {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
            {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
            {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
            {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
            {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
            {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
            {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
            {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0}
        };
        private static void G(ulong[] v, int a, int b, int c, int d, ulong x, ulong y)
        {
            unchecked
            {
                v[a] += v[b] + x; v[d] = RotateRight(v[d] ^ v[a], 32);
                v[c] += v[d]; v[b] = RotateRight(v[b] ^ v[c], 24);
                v[a] += v[b] + y; v[d] = RotateRight(v[d] ^ v[a], 16);
                v[c] += v[d]; v[b] = RotateRight(v[b] ^ v[c], 63);
            }
        }

        // BLAKE2b-384 of exactly 32 bytes (one final block), AEZ-Extract.
        private byte[] Extract(byte[] key)
        {
            ulong[] h = Longs(8), v = Longs(16), m = Longs(16);
            Array.Copy(IV, h, 8);
            h[0] ^= 0x01010030UL;
            Array.Copy(h, v, 8); Array.Copy(IV, 0, v, 8, 8);
            v[12] ^= 32; v[14] = ~v[14];
            for (int i = 0; i < 4; i++)
                m[i] = Read32(key, i * 8) | ((ulong)Read32(key, i * 8 + 4) << 32);
            for (int round = 0; round < 12; round++)
            {
                int s = round % 10;
                G(v,0,4,8,12,m[Sigma[s,0]],m[Sigma[s,1]]);
                G(v,1,5,9,13,m[Sigma[s,2]],m[Sigma[s,3]]);
                G(v,2,6,10,14,m[Sigma[s,4]],m[Sigma[s,5]]);
                G(v,3,7,11,15,m[Sigma[s,6]],m[Sigma[s,7]]);
                G(v,0,5,10,15,m[Sigma[s,8]],m[Sigma[s,9]]);
                G(v,1,6,11,12,m[Sigma[s,10]],m[Sigma[s,11]]);
                G(v,2,7,8,13,m[Sigma[s,12]],m[Sigma[s,13]]);
                G(v,3,4,9,14,m[Sigma[s,14]],m[Sigma[s,15]]);
            }
            byte[] result = Bytes(48);
            for (int i = 0; i < 6; i++)
            {
                h[i] ^= v[i] ^ v[i + 8];
                for (int j = 0; j < 8; j++) result[8 * i + j] = (byte)(h[i] >> (8 * j));
            }
            return result;
        }

        private static byte Multiply(byte a, byte b)
        {
            int result = 0, x = a, y = b;
            for (int i = 0; i < 8; i++)
            {
                result ^= x & -(y & 1);
                x = ((x << 1) ^ (0x11b & -(x >> 7))) & 255;
                y >>= 1;
            }
            return (byte)result;
        }
        private static byte SubByte(byte x)
        {
            // x^254 in GF(256), followed by AES's affine map. No secret-indexed table.
            byte x2 = Multiply(x, x), x3 = Multiply(x2, x);
            byte x6 = Multiply(x3, x3), x12 = Multiply(x6, x6);
            byte x15 = Multiply(x12, x3);
            // x^15 -> x^240; multiply by x^12 and x^2.
            byte inverse = x15;
            for (int i = 0; i < 4; i++) inverse = Multiply(inverse, inverse);
            inverse = Multiply(Multiply(inverse, x12), x2);
            int t = inverse;
            return (byte)(t ^ ((t << 1) | (t >> 7)) ^ ((t << 2) | (t >> 6))
                ^ ((t << 3) | (t >> 5)) ^ ((t << 4) | (t >> 4)) ^ 0x63);
        }

        private byte[] iKey, jKey, lKey, twiceI, twiceJ, fourJ, sixL, aesWork;
        private static void Xor(byte[] target, byte[] source)
        {
            for (int k = 0; k < 16; k++) target[k] ^= source[k];
        }
        private byte[] Multiple(byte[] source, int n)
        {
            byte[] result = Bytes(16), t = Bytes(16);
            Array.Copy(source, t, 16);
            for (; n > 0; n >>= 1)
            {
                if ((n & 1) != 0) Xor(result, t);
                int high = t[0] >> 7;
                for (int k = 0; k < 15; k++) t[k] = (byte)((t[k] << 1) | (t[k + 1] >> 7));
                t[15] = (byte)((t[15] << 1) ^ (135 & -high));
            }
            return result;
        }

        // Four AES rounds, each including MixColumns, with round keys J,I,L,0.
        private void AES4(byte[] block, byte[] j, byte[] i, byte[] l)
        {
            if (j != null) Xor(block, j);
            Xor(block, i);
            if (l != null) Xor(block, l);
            for (int round = 0; round < 4; round++)
            {
                for (int col = 0; col < 4; col++)
                    for (int row = 0; row < 4; row++)
                        aesWork[col * 4 + row] = SubByte(block[((col + row) % 4) * 4 + row]);
                byte[] roundKey = round == 0 ? jKey : round == 1 ? iKey : round == 2 ? lKey : null;
                for (int col = 0; col < 16; col += 4)
                {
                    byte a = aesWork[col], b = aesWork[col + 1], c = aesWork[col + 2], d = aesWork[col + 3];
                    int sum = a ^ b ^ c ^ d;
                    block[col] = (byte)(a ^ sum ^ Multiply((byte)(a ^ b), 2));
                    block[col + 1] = (byte)(b ^ sum ^ Multiply((byte)(b ^ c), 2));
                    block[col + 2] = (byte)(c ^ sum ^ Multiply((byte)(c ^ d), 2));
                    block[col + 3] = (byte)(d ^ sum ^ Multiply((byte)(d ^ a), 2));
                }
                if (roundKey != null) Xor(block, roundKey);
            }
        }

        private byte[] DecryptTiny(byte[] key, byte[] encoded)
        {
            byte[] extracted = Extract(key);
            iKey = Bytes(16); jKey = Bytes(16); lKey = Bytes(16); aesWork = Bytes(16);
            Array.Copy(extracted, 0, iKey, 0, 16);
            Array.Copy(extracted, 16, jKey, 0, 16);
            Array.Copy(extracted, 32, lKey, 0, 16);
            twiceI = Multiple(iKey, 2); twiceJ = Multiple(jKey, 2);
            fourJ = Multiple(jKey, 4); sixL = Multiple(lKey, 6);
            byte[] delta = Bytes(16), buf = Bytes(16);
            // AEZ-Hash: tau=32 bits, empty nonce, one AD vector = version || salt.
            delta[15] = 32;
            byte[] threeJ = Bytes(16); Array.Copy(jKey, threeJ, 16); Xor(threeJ, twiceJ);
            AES4(delta, threeJ, twiceI, lKey);
            buf[0] = 0x80;
            AES4(buf, fourJ, iKey, null); Xor(delta, buf);
            Array.Clear(buf, 0, 16);
            buf[0] = encoded[0]; Array.Copy(encoded, 24, buf, 1, 5); buf[6] = 0x80;
            AES4(buf, Multiple(jKey, 5), iKey, null); Xor(delta, buf);

            // AEZ-Tiny for 23 bytes: 92-bit halves, 8 Feistel rounds in reverse.
            byte[] left = Bytes(16), right = Bytes(16), output = Bytes(23);
            Array.Copy(encoded, 1, left, 0, 12); Array.Copy(encoded, 12, right, 0, 12);
            for (int k = 0; k < 11; k++) right[k] = (byte)((right[k] << 4) | (right[k + 1] >> 4));
            right[11] <<= 4;
            for (int round = 7; round >= 1; round -= 2)
            {
                Array.Clear(buf, 0, 16); Array.Copy(right, buf, 12);
                buf[11] = (byte)((buf[11] & 0xf0) | 8); Xor(buf, delta); buf[15] ^= (byte)round;
                AES4(buf, null, twiceI, sixL); Xor(left, buf);
                Array.Clear(buf, 0, 16); Array.Copy(left, buf, 12);
                buf[11] = (byte)((buf[11] & 0xf0) | 8); Xor(buf, delta); buf[15] ^= (byte)(round - 1);
                AES4(buf, null, twiceI, sixL); Xor(right, buf);
            }
            Array.Copy(right, 0, output, 0, 11); Array.Copy(left, 0, output, 11, 12);
            for (int k = 22; k > 11; k--) output[k] = (byte)((output[k] >> 4) | (output[k - 1] << 4));
            output[11] = (byte)((left[0] >> 4) | (right[11] & 0xf0));
            return output;
        }
    }
}
