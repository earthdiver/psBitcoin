// Test-only independent affine secp256k1 verifier. Not production cryptography.
// No calls to the PowerShell wallet or transaction implementation.
using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

public static class TestCrypto {
    public static readonly BigInteger P = Number("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    public static readonly BigInteger N = Number("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    class Point {
        public BigInteger X, Y;
        public Point(BigInteger x, BigInteger y) { X=x; Y=y; }
    }
    static readonly Point G = new Point(Number("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), Number("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));
    public static byte[] Bytes(string hex) {
        if (hex.Length%2!=0) throw new ArgumentException("Odd hex");
        byte[] b=new byte[hex.Length/2];
        for(int i=0;i<b.Length;i++) b[i]=Convert.ToByte(hex.Substring(i*2,2),16);
        return b;
    }
    public static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant(); }
    public static BigInteger Number(string hex) {
        byte[] b=Bytes(hex); Array.Reverse(b); Array.Resize(ref b,b.Length+1); return new BigInteger(b);
    }
    static BigInteger Mod(BigInteger x, BigInteger m) { x%=m; return x.Sign<0?x+m:x; }
    static Point Add(Point a, Point b) {
        if(a==null) return b; if(b==null) return a;
        if(a.X==b.X && Mod(a.Y+b.Y,P)==0) return null;
        BigInteger numerator=a.X==b.X?3*a.X*a.X:b.Y-a.Y;
        BigInteger denominator=a.X==b.X?2*a.Y:b.X-a.X;
        BigInteger slope=Mod(numerator*BigInteger.ModPow(Mod(denominator,P),P-2,P),P);
        BigInteger x=Mod(slope*slope-a.X-b.X,P);
        return new Point(x,Mod(slope*(a.X-x)-a.Y,P));
    }
    static Point Mul(BigInteger k, Point a) {
        Point result=null; k=Mod(k,N);
        while(k>0) { if(!k.IsEven) result=Add(result,a); a=Add(a,a); k>>=1; }
        return result;
    }
    static Point Lift(BigInteger x) {
        if(x<0 || x>=P) return null;
        BigInteger c=Mod(x*x*x+7,P), y=BigInteger.ModPow(c,(P+1)/4,P);
        if(Mod(y*y,P)!=c) return null;
        return new Point(x,y.IsEven?y:P-y);
    }
    static Point Public(string key) {
        if(key.Length==66 && (key.StartsWith("02") || key.StartsWith("03"))) {
            Point q=Lift(Number(key.Substring(2)));
            if(q!=null && q.Y.IsEven!=key.StartsWith("02")) q.Y=P-q.Y;
            return q;
        }
        if(key.Length==130 && key.StartsWith("04")) {
            Point q=new Point(Number(key.Substring(2,64)),Number(key.Substring(66)));
            return q.X<P && q.Y<P && Mod(q.Y*q.Y-q.X*q.X*q.X-7,P)==0?q:null;
        }
        return null;
    }
    public static string Sha(string hex) { using(SHA256 h=SHA256.Create()) return Hex(h.ComputeHash(Bytes(hex))); }
    public static string DoubleSha(string hex) { return Sha(Sha(hex)); }
    public static string Tagged(string tag, string hex) {
        string t=Sha(Hex(Encoding.UTF8.GetBytes(tag))); return Sha(t+t+hex);
    }
    public static bool VerifyEcdsa(string digest, string signature, string publicKey) {
        try {
            byte[] b=Bytes(signature);
            if(b.Length<8 || b[0]!=48 || b[1]!=b.Length-2 || b[2]!=2) return false;
            int rlen=b[3], p=4+rlen;
            if(rlen==0 || p+2>b.Length || b[p]!=2 || b[p+1]==0 || p+2+b[p+1]!=b.Length) return false;
            if((b[4]&128)!=0 || (rlen>1 && b[4]==0 && (b[5]&128)==0)) return false;
            if((b[p+2]&128)!=0 || (b[p+1]>1 && b[p+2]==0 && (b[p+3]&128)==0)) return false;
            BigInteger r=Number(signature.Substring(8,rlen*2)), s=Number(signature.Substring((p+2)*2));
            if(r<=0 || r>=N || s<=0 || s>=N) return false;
            Point q=Public(publicKey); if(q==null) return false;
            BigInteger inverse=BigInteger.ModPow(s,N-2,N);
            Point point=Add(Mul(Number(digest)*inverse,G),Mul(r*inverse,q));
            return point!=null && point.X%N==r;
        } catch { return false; }
    }
    public static bool VerifySchnorr(string message, string signature, string xonly) {
        try {
            if(signature.Length!=128 || xonly.Length!=64) return false;
            Point q=Lift(Number(xonly)); if(q==null) return false;
            BigInteger r=Number(signature.Substring(0,64)),s=Number(signature.Substring(64));
            if(r>=P || s>=N) return false;
            BigInteger e=Number(Tagged("BIP0340/challenge",signature.Substring(0,64)+xonly+message))%N;
            Point point=Add(Mul(s,G),Mul(N-e,q));
            return point!=null && point.Y.IsEven && point.X==r;
        } catch { return false; }
    }
}
