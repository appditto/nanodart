import 'dart:typed_data';
import 'dart:math';
import 'dart:core';
import 'package:convert/convert.dart';
import 'package:fixnum_nanodart/fixnum.dart';
import 'package:pointycastle/digests/blake2b.dart';

/// A modified implementation of tweetnacl that uses blake2b instead of sha256

class KeyPair {
  Uint8List? _publicKey;
  Uint8List? _secretKey;

  KeyPair(publicKeyLength, secretKeyLength) {
    _publicKey = Uint8List(publicKeyLength);
    _secretKey = Uint8List(secretKeyLength);
  }

  Uint8List? get publicKey => _publicKey;

  Uint8List? get secretKey => _secretKey;
}

/// Signature algorithm, Implements ed25519.
class Signature {
  static final int signatureLength = 64;
  static final int publicKeyLength = 32;

  /// Signs the message using the secret key and returns a signed message.
  static Uint8List? sign(Uint8List message, Uint8List secretKey) {
    if (message == null) return null;

    return signLen(message, 0, message.length, secretKey);
  }

  static Uint8List? signLen(
      Uint8List message, final int moff, final int mlen, Uint8List secretKey) {
    // check message
    if (!(message != null && message.length >= (moff + mlen))) return null;

    // signed message
    Uint8List sm = Uint8List(mlen + signatureLength);

    TweetNaclFast.cryptoSign(sm, -1, message, moff, mlen, secretKey);

    return sm;
  }

  ///  Signs the message using the secret key and returns a signature.
  static Uint8List detached(Uint8List message, Uint8List secretKey) {
    Uint8List? signedMsg = sign(message, secretKey);
    Uint8List sig = Uint8List(signatureLength);
    for (int i = 0; i < sig.length; i++) sig[i] = signedMsg![i];
    return sig;
  }

  /// Verifies the signature for the message and
  /// returns true if verification succeeded or false if it failed.
  static bool detachedVerify(
      Uint8List message, Uint8List signature, Uint8List publicKey) {
    if (signature.length != signatureLength) return false;
    if (publicKey.length != publicKeyLength) return false;
    Uint8List sm = Uint8List(signatureLength + message.length);
    Uint8List m = Uint8List(signatureLength + message.length);
    for (int i = 0; i < signatureLength; i++) sm[i] = signature[i];
    for (int i = 0; i < message.length; i++)
      sm[i + signatureLength] = message[i];
    return (TweetNaclFast.cryptoSignOpen(m, -1, sm, 0, sm.length, publicKey) >=
        0);
  }
}

class TweetNaclFast {
  static final Uint8List zero =
      Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); //16
  static final Uint8List nine = Uint8List.fromList([
    9,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  ]); //32

  static final Uint64List gf0 = Uint64List.fromList(
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); //16
  static final Uint64List gf1 = Uint64List.fromList(
      [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); //16
  static final Uint64List one21665 = Uint64List.fromList(
      [0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); //16

  static final Uint64List D = Uint64List.fromList([
    0x78a3,
    0x1359,
    0x4dca,
    0x75eb,
    0xd8ab,
    0x4141,
    0x0a4d,
    0x0070,
    0xe898,
    0x7779,
    0x4079,
    0x8cc7,
    0xfe73,
    0x2b6f,
    0x6cee,
    0x5203
  ]);

  static final Uint64List d2 = Uint64List.fromList([
    0xf159,
    0x26b2,
    0x9b94,
    0xebd6,
    0xb156,
    0x8283,
    0x149a,
    0x00e0,
    0xd130,
    0xeef3,
    0x80f2,
    0x198e,
    0xfce7,
    0x56df,
    0xd9dc,
    0x2406
  ]);
  static final Uint64List x = Uint64List.fromList([
    0xd51a,
    0x8f25,
    0x2d60,
    0xc956,
    0xa7b2,
    0x9525,
    0xc760,
    0x692c,
    0xdc5c,
    0xfdd6,
    0xe231,
    0xc0a4,
    0x53fe,
    0xcd6e,
    0x36d3,
    0x2169
  ]);
  static final Uint64List y = Uint64List.fromList([
    0x6658,
    0x6666,
    0x6666,
    0x6666,
    0x6666,
    0x6666,
    0x6666,
    0x6666,
    0x6666,
    0x6666,
    0x6666,
    0x6666,
    0x6666,
    0x6666,
    0x6666,
    0x6666
  ]);
  static final Uint64List i = Uint64List.fromList([
    0xa0b0,
    0x4a0e,
    0x1b27,
    0xc4ee,
    0xe478,
    0xad2f,
    0x1806,
    0x2f43,
    0xd7a7,
    0x3dfb,
    0x0099,
    0x2b4d,
    0xdf0b,
    0x4fc1,
    0x2480,
    0x2b83
  ]);

  static int _vn(
      Uint8List x, final int xoff, Uint8List y, final int yoff, int n) {
    int i, d = 0;
    for (i = 0; i < n; i++) d |= (x[i + xoff] ^ y[i + yoff]) & 0xff;
    return (1 & (Int32(d - 1).shiftRightUnsigned(8).toInt())) - 1;
  }

  static int _cryptoVerify16(
      Uint8List x, final int xoff, Uint8List y, final int yoff) {
    return _vn(x, xoff, y, yoff, 16);
  }

  static int cryptoVerify16(Uint8List x, Uint8List y) {
    return _cryptoVerify16(x, 0, y, 0);
  }

  static int _cryptoVerify32(
      Uint8List x, final int xoff, Uint8List y, final int yoff) {
    return _vn(x, xoff, y, yoff, 32);
  }

  static int cryptoVerify32(Uint8List x, Uint8List y) {
    return _cryptoVerify32(x, 0, y, 0);
  }

  static void _coreSalsa20(Uint8List o, Uint8List p, Uint8List k, Uint8List c) {
    int j0 = c[0] & 0xff |
            (c[1] & 0xff) << 8 |
            (c[2] & 0xff) << 16 |
            (c[3] & 0xff) << 24,
        j1 = k[0] & 0xff |
            (k[1] & 0xff) << 8 |
            (k[2] & 0xff) << 16 |
            (k[3] & 0xff) << 24,
        j2 = k[4] & 0xff |
            (k[5] & 0xff) << 8 |
            (k[6] & 0xff) << 16 |
            (k[7] & 0xff) << 24,
        j3 = k[8] & 0xff |
            (k[9] & 0xff) << 8 |
            (k[10] & 0xff) << 16 |
            (k[11] & 0xff) << 24,
        j4 = k[12] & 0xff |
            (k[13] & 0xff) << 8 |
            (k[14] & 0xff) << 16 |
            (k[15] & 0xff) << 24,
        j5 = c[4] & 0xff |
            (c[5] & 0xff) << 8 |
            (c[6] & 0xff) << 16 |
            (c[7] & 0xff) << 24,
        j6 = p[0] & 0xff |
            (p[1] & 0xff) << 8 |
            (p[2] & 0xff) << 16 |
            (p[3] & 0xff) << 24,
        j7 = p[4] & 0xff |
            (p[5] & 0xff) << 8 |
            (p[6] & 0xff) << 16 |
            (p[7] & 0xff) << 24,
        j8 = p[8] & 0xff |
            (p[9] & 0xff) << 8 |
            (p[10] & 0xff) << 16 |
            (p[11] & 0xff) << 24,
        j9 = p[12] & 0xff |
            (p[13] & 0xff) << 8 |
            (p[14] & 0xff) << 16 |
            (p[15] & 0xff) << 24,
        j10 = c[8] & 0xff |
            (c[9] & 0xff) << 8 |
            (c[10] & 0xff) << 16 |
            (c[11] & 0xff) << 24,
        j11 = k[16] & 0xff |
            (k[17] & 0xff) << 8 |
            (k[18] & 0xff) << 16 |
            (k[19] & 0xff) << 24,
        j12 = k[20] & 0xff |
            (k[21] & 0xff) << 8 |
            (k[22] & 0xff) << 16 |
            (k[23] & 0xff) << 24,
        j13 = k[24] & 0xff |
            (k[25] & 0xff) << 8 |
            (k[26] & 0xff) << 16 |
            (k[27] & 0xff) << 24,
        j14 = k[28] & 0xff |
            (k[29] & 0xff) << 8 |
            (k[30] & 0xff) << 16 |
            (k[31] & 0xff) << 24,
        j15 = c[12] & 0xff |
            (c[13] & 0xff) << 8 |
            (c[14] & 0xff) << 16 |
            (c[15] & 0xff) << 24;

    Int32 x0 = Int32(j0),
        x1 = Int32(j1),
        x2 = Int32(j2),
        x3 = Int32(j3),
        x4 = Int32(j4),
        x5 = Int32(j5),
        x6 = Int32(j6),
        x7 = Int32(j7),
        x8 = Int32(j8),
        x9 = Int32(j9),
        x10 = Int32(j10),
        x11 = Int32(j11),
        x12 = Int32(j12),
        x13 = Int32(j13),
        x14 = Int32(j14),
        x15 = Int32(j15),
        u;

    for (int i = 0; i < 20; i += 2) {
      u = x0 + x12 | 0 as Int32;
      x4 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x4 + x0 | 0 as Int32;
      x8 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x8 + x4 | 0 as Int32;
      x12 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x12 + x8 | 0 as Int32;
      x0 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x5 + x1 | 0 as Int32;
      x9 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x9 + x5 | 0 as Int32;
      x13 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x13 + x9 | 0 as Int32;
      x1 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x1 + x13 | 0 as Int32;
      x5 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x10 + x6 | 0 as Int32;
      x14 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x14 + x10 | 0 as Int32;
      x2 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x2 + x14 | 0 as Int32;
      x6 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x6 + x2 | 0 as Int32;
      x10 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x15 + x11 | 0 as Int32;
      x3 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x3 + x15 | 0 as Int32;
      x7 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x7 + x3 | 0 as Int32;
      x11 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x11 + x7 | 0 as Int32;
      x15 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x0 + x3 | 0 as Int32;
      x1 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x1 + x0 | 0 as Int32;
      x2 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x2 + x1 | 0 as Int32;
      x3 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x3 + x2 | 0 as Int32;
      x0 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x5 + x4 | 0 as Int32;
      x6 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x6 + x5 | 0 as Int32;
      x7 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x7 + x6 | 0 as Int32;
      x4 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x4 + x7 | 0 as Int32;
      x5 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x10 + x9 | 0 as Int32;
      x11 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x11 + x10 | 0 as Int32;
      x8 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x8 + x11 | 0 as Int32;
      x9 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x9 + x8 | 0 as Int32;
      x10 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x15 + x14 | 0 as Int32;
      x12 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x12 + x15 | 0 as Int32;
      x13 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x13 + x12 | 0 as Int32;
      x14 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x14 + x13 | 0 as Int32;
      x15 ^= u << 18 | u.shiftRightUnsigned(32 - 18);
    }
    x0 = x0 + j0 | 0 as Int32;
    x1 = x1 + j1 | 0 as Int32;
    x2 = x2 + j2 | 0 as Int32;
    x3 = x3 + j3 | 0 as Int32;
    x4 = x4 + j4 | 0 as Int32;
    x5 = x5 + j5 | 0 as Int32;
    x6 = x6 + j6 | 0 as Int32;
    x7 = x7 + j7 | 0 as Int32;
    x8 = x8 + j8 | 0 as Int32;
    x9 = x9 + j9 | 0 as Int32;
    x10 = x10 + j10 | 0 as Int32;
    x11 = x11 + j11 | 0 as Int32;
    x12 = x12 + j12 | 0 as Int32;
    x13 = x13 + j13 | 0 as Int32;
    x14 = x14 + j14 | 0 as Int32;
    x15 = x15 + j15 | 0 as Int32;

    o[0] = (x0.shiftRightUnsigned(0) & 0xff).toInt();
    o[1] = (x0.shiftRightUnsigned(8) & 0xff).toInt();
    o[2] = (x0.shiftRightUnsigned(16) & 0xff).toInt();
    o[3] = (x0.shiftRightUnsigned(24) & 0xff).toInt();

    o[4] = (x1.shiftRightUnsigned(0) & 0xff).toInt();
    o[5] = (x1.shiftRightUnsigned(8) & 0xff).toInt();
    o[6] = (x1.shiftRightUnsigned(16) & 0xff).toInt();
    o[7] = (x1.shiftRightUnsigned(24) & 0xff).toInt();

    o[8] = (x2.shiftRightUnsigned(0) & 0xff).toInt();
    o[9] = (x2.shiftRightUnsigned(8) & 0xff).toInt();
    o[10] = (x2.shiftRightUnsigned(16) & 0xff).toInt();
    o[11] = (x2.shiftRightUnsigned(24) & 0xff).toInt();

    o[12] = (x3.shiftRightUnsigned(0) & 0xff).toInt();
    o[13] = (x3.shiftRightUnsigned(8) & 0xff).toInt();
    o[14] = (x3.shiftRightUnsigned(16) & 0xff).toInt();
    o[15] = (x3.shiftRightUnsigned(24) & 0xff).toInt();

    o[16] = (x4.shiftRightUnsigned(0) & 0xff).toInt();
    o[17] = (x4.shiftRightUnsigned(8) & 0xff).toInt();
    o[18] = (x4.shiftRightUnsigned(16) & 0xff).toInt();
    o[19] = (x4.shiftRightUnsigned(24) & 0xff).toInt();

    o[20] = (x5.shiftRightUnsigned(0) & 0xff).toInt();
    o[21] = (x5.shiftRightUnsigned(8) & 0xff).toInt();
    o[22] = (x5.shiftRightUnsigned(16) & 0xff).toInt();
    o[23] = (x5.shiftRightUnsigned(24) & 0xff).toInt();

    o[24] = (x6.shiftRightUnsigned(0) & 0xff).toInt();
    o[25] = (x6.shiftRightUnsigned(8) & 0xff).toInt();
    o[26] = (x6.shiftRightUnsigned(16) & 0xff).toInt();
    o[27] = (x6.shiftRightUnsigned(24) & 0xff).toInt();

    o[28] = (x7.shiftRightUnsigned(0) & 0xff).toInt();
    o[29] = (x7.shiftRightUnsigned(8) & 0xff).toInt();
    o[30] = (x7.shiftRightUnsigned(16) & 0xff).toInt();
    o[31] = (x7.shiftRightUnsigned(24) & 0xff).toInt();

    o[32] = (x8.shiftRightUnsigned(0) & 0xff).toInt();
    o[33] = (x8.shiftRightUnsigned(8) & 0xff).toInt();
    o[34] = (x8.shiftRightUnsigned(16) & 0xff).toInt();
    o[35] = (x8.shiftRightUnsigned(24) & 0xff).toInt();

    o[36] = (x9.shiftRightUnsigned(0) & 0xff).toInt();
    o[37] = (x9.shiftRightUnsigned(8) & 0xff).toInt();
    o[38] = (x9.shiftRightUnsigned(16) & 0xff).toInt();
    o[39] = (x9.shiftRightUnsigned(24) & 0xff).toInt();

    o[40] = (x10.shiftRightUnsigned(0) & 0xff).toInt();
    o[41] = (x10.shiftRightUnsigned(8) & 0xff).toInt();
    o[42] = (x10.shiftRightUnsigned(16) & 0xff).toInt();
    o[43] = (x10.shiftRightUnsigned(24) & 0xff).toInt();

    o[44] = (x11.shiftRightUnsigned(0) & 0xff).toInt();
    o[45] = (x11.shiftRightUnsigned(8) & 0xff).toInt();
    o[46] = (x11.shiftRightUnsigned(16) & 0xff).toInt();
    o[47] = (x11.shiftRightUnsigned(24) & 0xff).toInt();

    o[48] = (x12.shiftRightUnsigned(0) & 0xff).toInt();
    o[49] = (x12.shiftRightUnsigned(8) & 0xff).toInt();
    o[50] = (x12.shiftRightUnsigned(16) & 0xff).toInt();
    o[51] = (x12.shiftRightUnsigned(24) & 0xff).toInt();

    o[52] = (x13.shiftRightUnsigned(0) & 0xff).toInt();
    o[53] = (x13.shiftRightUnsigned(8) & 0xff).toInt();
    o[54] = (x13.shiftRightUnsigned(16) & 0xff).toInt();
    o[55] = (x13.shiftRightUnsigned(24) & 0xff).toInt();

    o[56] = (x14.shiftRightUnsigned(0) & 0xff).toInt();
    o[57] = (x14.shiftRightUnsigned(8) & 0xff).toInt();
    o[58] = (x14.shiftRightUnsigned(16) & 0xff).toInt();
    o[59] = (x14.shiftRightUnsigned(24) & 0xff).toInt();

    o[60] = (x15.shiftRightUnsigned(0) & 0xff).toInt();
    o[61] = (x15.shiftRightUnsigned(8) & 0xff).toInt();
    o[62] = (x15.shiftRightUnsigned(16) & 0xff).toInt();
    o[63] = (x15.shiftRightUnsigned(24) & 0xff).toInt();
  }

  static void _coreHsalsa20(
      Uint8List o, Uint8List p, Uint8List k, Uint8List c) {
    int j0 = c[0] & 0xff |
            (c[1] & 0xff) << 8 |
            (c[2] & 0xff) << 16 |
            (c[3] & 0xff) << 24,
        j1 = k[0] & 0xff |
            (k[1] & 0xff) << 8 |
            (k[2] & 0xff) << 16 |
            (k[3] & 0xff) << 24,
        j2 = k[4] & 0xff |
            (k[5] & 0xff) << 8 |
            (k[6] & 0xff) << 16 |
            (k[7] & 0xff) << 24,
        j3 = k[8] & 0xff |
            (k[9] & 0xff) << 8 |
            (k[10] & 0xff) << 16 |
            (k[11] & 0xff) << 24,
        j4 = k[12] & 0xff |
            (k[13] & 0xff) << 8 |
            (k[14] & 0xff) << 16 |
            (k[15] & 0xff) << 24,
        j5 = c[4] & 0xff |
            (c[5] & 0xff) << 8 |
            (c[6] & 0xff) << 16 |
            (c[7] & 0xff) << 24,
        j6 = p[0] & 0xff |
            (p[1] & 0xff) << 8 |
            (p[2] & 0xff) << 16 |
            (p[3] & 0xff) << 24,
        j7 = p[4] & 0xff |
            (p[5] & 0xff) << 8 |
            (p[6] & 0xff) << 16 |
            (p[7] & 0xff) << 24,
        j8 = p[8] & 0xff |
            (p[9] & 0xff) << 8 |
            (p[10] & 0xff) << 16 |
            (p[11] & 0xff) << 24,
        j9 = p[12] & 0xff |
            (p[13] & 0xff) << 8 |
            (p[14] & 0xff) << 16 |
            (p[15] & 0xff) << 24,
        j10 = c[8] & 0xff |
            (c[9] & 0xff) << 8 |
            (c[10] & 0xff) << 16 |
            (c[11] & 0xff) << 24,
        j11 = k[16] & 0xff |
            (k[17] & 0xff) << 8 |
            (k[18] & 0xff) << 16 |
            (k[19] & 0xff) << 24,
        j12 = k[20] & 0xff |
            (k[21] & 0xff) << 8 |
            (k[22] & 0xff) << 16 |
            (k[23] & 0xff) << 24,
        j13 = k[24] & 0xff |
            (k[25] & 0xff) << 8 |
            (k[26] & 0xff) << 16 |
            (k[27] & 0xff) << 24,
        j14 = k[28] & 0xff |
            (k[29] & 0xff) << 8 |
            (k[30] & 0xff) << 16 |
            (k[31] & 0xff) << 24,
        j15 = c[12] & 0xff |
            (c[13] & 0xff) << 8 |
            (c[14] & 0xff) << 16 |
            (c[15] & 0xff) << 24;

    Int32 x0 = Int32(j0),
        x1 = Int32(j1),
        x2 = Int32(j2),
        x3 = Int32(j3),
        x4 = Int32(j4),
        x5 = Int32(j5),
        x6 = Int32(j6),
        x7 = Int32(j7),
        x8 = Int32(j8),
        x9 = Int32(j9),
        x10 = Int32(j10),
        x11 = Int32(j11),
        x12 = Int32(j12),
        x13 = Int32(j13),
        x14 = Int32(j14),
        x15 = Int32(j15),
        u;

    for (int i = 0; i < 20; i += 2) {
      u = x0 + x12 | 0 as Int32;
      x4 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x4 + x0 | 0 as Int32;
      x8 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x8 + x4 | 0 as Int32;
      x12 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x12 + x8 | 0 as Int32;
      x0 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x5 + x1 | 0 as Int32;
      x9 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x9 + x5 | 0 as Int32;
      x13 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x13 + x9 | 0 as Int32;
      x1 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x1 + x13 | 0 as Int32;
      x5 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x10 + x6 | 0 as Int32;
      x14 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x14 + x10 | 0 as Int32;
      x2 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x2 + x14 | 0 as Int32;
      x6 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x6 + x2 | 0 as Int32;
      x10 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x15 + x11 | 0 as Int32;
      x3 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x3 + x15 | 0 as Int32;
      x7 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x7 + x3 | 0 as Int32;
      x11 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x11 + x7 | 0 as Int32;
      x15 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x0 + x3 | 0 as Int32;
      x1 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x1 + x0 | 0 as Int32;
      x2 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x2 + x1 | 0 as Int32;
      x3 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x3 + x2 | 0 as Int32;
      x0 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x5 + x4 | 0 as Int32;
      x6 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x6 + x5 | 0 as Int32;
      x7 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x7 + x6 | 0 as Int32;
      x4 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x4 + x7 | 0 as Int32;
      x5 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x10 + x9 | 0 as Int32;
      x11 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x11 + x10 | 0 as Int32;
      x8 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x8 + x11 | 0 as Int32;
      x9 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x9 + x8 | 0 as Int32;
      x10 ^= u << 18 | u.shiftRightUnsigned(32 - 18);

      u = x15 + x14 | 0 as Int32;
      x12 ^= u << 7 | u.shiftRightUnsigned(32 - 7);
      u = x12 + x15 | 0 as Int32;
      x13 ^= u << 9 | u.shiftRightUnsigned(32 - 9);
      u = x13 + x12 | 0 as Int32;
      x14 ^= u << 13 | u.shiftRightUnsigned(32 - 13);
      u = x14 + x13 | 0 as Int32;
      x15 ^= u << 18 | u.shiftRightUnsigned(32 - 18);
    }

    o[0] = (x0.shiftRightUnsigned(0) & 0xff).toInt();
    o[1] = (x0.shiftRightUnsigned(8) & 0xff).toInt();
    o[2] = (x0.shiftRightUnsigned(16) & 0xff).toInt();
    o[3] = (x0.shiftRightUnsigned(24) & 0xff).toInt();

    o[4] = (x5.shiftRightUnsigned(0) & 0xff).toInt();
    o[5] = (x5.shiftRightUnsigned(8) & 0xff).toInt();
    o[6] = (x5.shiftRightUnsigned(16) & 0xff).toInt();
    o[7] = (x5.shiftRightUnsigned(24) & 0xff).toInt();

    o[8] = (x10.shiftRightUnsigned(0) & 0xff).toInt();
    o[9] = (x10.shiftRightUnsigned(8) & 0xff).toInt();
    o[10] = (x10.shiftRightUnsigned(16) & 0xff).toInt();
    o[11] = (x10.shiftRightUnsigned(24) & 0xff).toInt();

    o[12] = (x15.shiftRightUnsigned(0) & 0xff).toInt();
    o[13] = (x15.shiftRightUnsigned(8) & 0xff).toInt();
    o[14] = (x15.shiftRightUnsigned(16) & 0xff).toInt();
    o[15] = (x15.shiftRightUnsigned(24) & 0xff).toInt();

    o[16] = (x6.shiftRightUnsigned(0) & 0xff).toInt();
    o[17] = (x6.shiftRightUnsigned(8) & 0xff).toInt();
    o[18] = (x6.shiftRightUnsigned(16) & 0xff).toInt();
    o[19] = (x6.shiftRightUnsigned(24) & 0xff).toInt();

    o[20] = (x7.shiftRightUnsigned(0) & 0xff).toInt();
    o[21] = (x7.shiftRightUnsigned(8) & 0xff).toInt();
    o[22] = (x7.shiftRightUnsigned(16) & 0xff).toInt();
    o[23] = (x7.shiftRightUnsigned(24) & 0xff).toInt();

    o[24] = (x8.shiftRightUnsigned(0) & 0xff).toInt();
    o[25] = (x8.shiftRightUnsigned(8) & 0xff).toInt();
    o[26] = (x8.shiftRightUnsigned(16) & 0xff).toInt();
    o[27] = (x8.shiftRightUnsigned(24) & 0xff).toInt();

    o[28] = (x9.shiftRightUnsigned(0) & 0xff).toInt();
    o[29] = (x9.shiftRightUnsigned(8) & 0xff).toInt();
    o[30] = (x9.shiftRightUnsigned(16) & 0xff).toInt();
    o[31] = (x9.shiftRightUnsigned(24) & 0xff).toInt();
  }

  static int cryptoCoreSalsa20(
      Uint8List out, Uint8List input, Uint8List k, Uint8List c) {
    ///core(out,in,k,c,0);
    _coreSalsa20(out, input, k, c);
    return 0;
  }

  static int cryptoCoreHsalsa20(
      Uint8List out, Uint8List input, Uint8List k, Uint8List c) {
    ///core(out,in,k,c,1);
    _coreHsalsa20(out, input, k, c);
    return 0;
  }

// "expand 32-byte k"
  static final Uint8List _sigma = Uint8List.fromList([
    101,
    120,
    112,
    97,
    110,
    100,
    32,
    51,
    50,
    45,
    98,
    121,
    116,
    101,
    32,
    107
  ]);

  static int _cryptoStreamSalsa20Xor(Uint8List c, int cpos, Uint8List m,
      int mpos, int b, Uint8List n, Uint8List k) {
    Uint8List z = Uint8List(16), x = Uint8List(64);
    int i;
    Int32 u;
    for (i = 0; i < 16; i++) z[i] = 0;
    for (i = 0; i < 8; i++) z[i] = n[i];
    while (b >= 64) {
      cryptoCoreSalsa20(x, z, k, _sigma);
      for (i = 0; i < 64; i++)
        c[cpos + i] = ((m[mpos + i] ^ x[i]) & 0xff).toInt();
      u = Int32(1);
      for (i = 8; i < 16; i++) {
        u = u + (z[i] & 0xff) | 0 as Int32;
        z[i] = (u & 0xff).toInt();
        u = u.shiftRightUnsigned(8);
      }
      b -= 64;
      cpos += 64;
      mpos += 64;
    }
    if (b > 0) {
      cryptoCoreSalsa20(x, z, k, _sigma);
      for (i = 0; i < b; i++)
        c[cpos + i] = ((m[mpos + i] ^ x[i]) & 0xff).toInt();
    }

    return 0;
  }

  static int cryptoStreamSalsa20(
      Uint8List c, int cpos, int b, Uint8List n, Uint8List k) {
    Uint8List z = Uint8List(16), x = Uint8List(64);
    int i;
    Int32 u;
    for (i = 0; i < 16; i++) z[i] = 0;
    for (i = 0; i < 8; i++) z[i] = n[i];
    while (b >= 64) {
      cryptoCoreSalsa20(x, z, k, _sigma);
      for (i = 0; i < 64; i++) c[cpos + i] = x[i];
      u = Int32(1);
      for (i = 8; i < 16; i++) {
        u = u + (z[i] & 0xff) | 0 as Int32;
        z[i] = (u & 0xff).toInt();
        u = u.shiftRightUnsigned(8);
      }
      b -= 64;
      cpos += 64;
    }
    if (b > 0) {
      cryptoCoreSalsa20(x, z, k, _sigma);
      for (i = 0; i < b; i++) c[cpos + i] = x[i];
    }

    return 0;
  }

  static int cryptoStream(
      Uint8List c, int cpos, int d, Uint8List n, Uint8List k) {
    Uint8List s = Uint8List(32);
    cryptoCoreHsalsa20(s, n, k, _sigma);
    Uint8List sn = Uint8List(8);
    for (int i = 0; i < 8; i++) sn[i] = n[i + 16];
    return cryptoStreamSalsa20(c, cpos, d, sn, s);
  }

  static int cryptoStreamXor(Uint8List c, int cpos, Uint8List m, int mpos,
      int d, Uint8List n, Uint8List k) {
    Uint8List s = Uint8List(32);

    cryptoCoreHsalsa20(s, n, k, _sigma);
    Uint8List sn = Uint8List(8);
    for (int i = 0; i < 8; i++) sn[i] = n[i + 16];
    return _cryptoStreamSalsa20Xor(c, cpos, m, mpos, d, sn, s);
  }

  static int _cryptoOnetimeauth(Uint8List out, final int outpos, Uint8List m,
      final int mpos, int n, Uint8List k) {
    Poly1305 s = Poly1305(k);
    s.update(m, mpos, n);
    s.finish(out, outpos);
    return 0;
  }

  int cryptoOnetimeauth(Uint8List out, Uint8List m, int n, Uint8List k) {
    return _cryptoOnetimeauth(out, 0, m, 0, n, k);
  }

  static int _cryptoOnetimeauthVerify(Uint8List h, final int hoff, Uint8List m,
      final int moff, int /*long*/ n, Uint8List k) {
    Uint8List x = Uint8List(16);
    _cryptoOnetimeauth(x, 0, m, moff, n, k);
    return _cryptoVerify16(h, hoff, x, 0);
  }

  int cryptoOnetimeauthVerifyLen(Uint8List h, Uint8List m, int n, Uint8List k) {
    return _cryptoOnetimeauthVerify(h, 0, m, 0, n, k);
  }

  int cryptoOnetimeauthVerify(Uint8List h, Uint8List m, Uint8List k) {
    return cryptoOnetimeauthVerifyLen(h, m, m != null ? m.length : 0, k);
  }

  static int cryptoSecretbox(
      Uint8List c, Uint8List m, int d, Uint8List n, Uint8List k) {
    if (d < 32) return -1;
    cryptoStreamXor(c, 0, m, 0, d, n, k);
    _cryptoOnetimeauth(c, 16, c, 32, d - 32, c);

    ///for (i = 0; i < 16; i++) c[i] = 0;
    return 0;
  }

  static int cryptoSecretboxOpen(
      Uint8List m, Uint8List c, int d, Uint8List n, Uint8List k) {
    Uint8List x = Uint8List(32);
    if (d < 32) return -1;
    cryptoStream(x, 0, 32, n, k);
    if (_cryptoOnetimeauthVerify(c, 16, c, 32, d - 32, x) != 0) return -1;
    cryptoStreamXor(m, 0, c, 0, d, n, k);

    ///for (i = 0; i < 32; i++) m[i] = 0;
    return 0;
  }

  static void _set25519(Uint64List? r, Uint64List a) {
    int i;
    for (i = 0; i < 16; i++) r![i] = a[i];
  }

  static void _car25519(Uint64List o) {
    int c;
    int i;
    for (i = 0; i < 16; i++) {
      o[i] += 65536;
      c = (o[i] / 65536).floor();
      o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + 37 * (c - 1) * (i == 15 ? 1 : 0);
      o[i] -= (c * 65536);
    }
  }

  static void _sel25519(Uint64List p, Uint64List q, int b) {
    _sel25519Off(p, 0, q, 0, b);
  }

  static void _sel25519Off(
      Uint64List? p, final int poff, Uint64List? q, final int qoff, int b) {
    int t, c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
      t = c & (p![i + poff] ^ q![i + qoff]);
      p[i + poff] ^= t;
      q[i + qoff] ^= t;
    }
  }

  static void _pack25519(Uint8List o, Uint64List? n, final int noff) {
    int i, j, b;
    Uint64List m = Uint64List(16), t = Uint64List(16);
    for (i = 0; i < 16; i++) t[i] = n![i + noff];
    _car25519(t);
    _car25519(t);
    _car25519(t);
    for (j = 0; j < 2; j++) {
      m[0] = t[0] - 0xffed;
      for (i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
        m[i - 1] &= 0xffff;
      }
      m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
      b = (m[15] >> 16) & 1;
      m[14] &= 0xffff;
      _sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
      o[2 * i] = t[i] & 0xff;
      o[2 * i + 1] = t[i] >> 8;
    }
  }

  static int _neq25519(Uint64List a, Uint64List b) {
    return _neq25519Off(a, 0, b, 0);
  }

  static int _neq25519Off(
      Uint64List a, final int aoff, Uint64List b, final int boff) {
    Uint8List c = Uint8List(32), d = Uint8List(32);
    _pack25519(c, a, aoff);
    _pack25519(d, b, boff);
    return _cryptoVerify32(c, 0, d, 0);
  }

  static int _par25519(Uint64List? a) {
    return _par25519Off(a, 0);
  }

  static int _par25519Off(Uint64List? a, final int aoff) {
    Uint8List d = Uint8List(32);
    _pack25519(d, a, aoff);
    return (d[0] & 1);
  }

  static void unpack25519(Uint64List o, Uint8List n) {
    for (int i = 0; i < 16; i++)
      o[i] = (n[2 * i] & 0xff) + (((n[2 * i + 1] << 8) & 0xffff));
    o[15] &= 0x7fff;
  }

  static void _a(Uint64List o, Uint64List? a, Uint64List b) {
    _aOff(o, 0, a, 0, b, 0);
  }

  static void _aOff(Uint64List o, final int ooff, Uint64List? a, final int aoff,
      Uint64List? b, final int boff) {
    int i;
    for (i = 0; i < 16; i++) o[i + ooff] = a![i + aoff] + b![i + boff];
  }

  static void _z(Uint64List? o, Uint64List a, Uint64List? b) {
    _zOff(o, 0, a, 0, b, 0);
  }

  static void _zOff(Uint64List? o, final int ooff, Uint64List? a,
      final int aoff, Uint64List? b, final int boff) {
    int i;
    for (i = 0; i < 16; i++) o![i + ooff] = a![i + aoff] - b![i + boff];
  }

  static void _m(Uint64List o, Uint64List a, Uint64List b) {
    _mOff(o, 0, a, 0, b, 0);
  }

  static void _mOff(Uint64List o, final int ooff, Uint64List a, final int aoff,
      Uint64List b, final int boff) {
    int v,
        c,
        t0 = 0,
        t1 = 0,
        t2 = 0,
        t3 = 0,
        t4 = 0,
        t5 = 0,
        t6 = 0,
        t7 = 0,
        t8 = 0,
        t9 = 0,
        t10 = 0,
        t11 = 0,
        t12 = 0,
        t13 = 0,
        t14 = 0,
        t15 = 0,
        t16 = 0,
        t17 = 0,
        t18 = 0,
        t19 = 0,
        t20 = 0,
        t21 = 0,
        t22 = 0,
        t23 = 0,
        t24 = 0,
        t25 = 0,
        t26 = 0,
        t27 = 0,
        t28 = 0,
        t29 = 0,
        t30 = 0,
        b0 = b[0 + boff],
        b1 = b[1 + boff],
        b2 = b[2 + boff],
        b3 = b[3 + boff],
        b4 = b[4 + boff],
        b5 = b[5 + boff],
        b6 = b[6 + boff],
        b7 = b[7 + boff],
        b8 = b[8 + boff],
        b9 = b[9 + boff],
        b10 = b[10 + boff],
        b11 = b[11 + boff],
        b12 = b[12 + boff],
        b13 = b[13 + boff],
        b14 = b[14 + boff],
        b15 = b[15 + boff];

    v = a[0 + aoff];
    t0 += v * b0;
    t1 += v * b1;
    t2 += v * b2;
    t3 += v * b3;
    t4 += v * b4;
    t5 += v * b5;
    t6 += v * b6;
    t7 += v * b7;
    t8 += v * b8;
    t9 += v * b9;
    t10 += v * b10;
    t11 += v * b11;
    t12 += v * b12;
    t13 += v * b13;
    t14 += v * b14;
    t15 += v * b15;
    v = a[1 + aoff];
    t1 += v * b0;
    t2 += v * b1;
    t3 += v * b2;
    t4 += v * b3;
    t5 += v * b4;
    t6 += v * b5;
    t7 += v * b6;
    t8 += v * b7;
    t9 += v * b8;
    t10 += v * b9;
    t11 += v * b10;
    t12 += v * b11;
    t13 += v * b12;
    t14 += v * b13;
    t15 += v * b14;
    t16 += v * b15;
    v = a[2 + aoff];
    t2 += v * b0;
    t3 += v * b1;
    t4 += v * b2;
    t5 += v * b3;
    t6 += v * b4;
    t7 += v * b5;
    t8 += v * b6;
    t9 += v * b7;
    t10 += v * b8;
    t11 += v * b9;
    t12 += v * b10;
    t13 += v * b11;
    t14 += v * b12;
    t15 += v * b13;
    t16 += v * b14;
    t17 += v * b15;
    v = a[3 + aoff];
    t3 += v * b0;
    t4 += v * b1;
    t5 += v * b2;
    t6 += v * b3;
    t7 += v * b4;
    t8 += v * b5;
    t9 += v * b6;
    t10 += v * b7;
    t11 += v * b8;
    t12 += v * b9;
    t13 += v * b10;
    t14 += v * b11;
    t15 += v * b12;
    t16 += v * b13;
    t17 += v * b14;
    t18 += v * b15;
    v = a[4 + aoff];
    t4 += v * b0;
    t5 += v * b1;
    t6 += v * b2;
    t7 += v * b3;
    t8 += v * b4;
    t9 += v * b5;
    t10 += v * b6;
    t11 += v * b7;
    t12 += v * b8;
    t13 += v * b9;
    t14 += v * b10;
    t15 += v * b11;
    t16 += v * b12;
    t17 += v * b13;
    t18 += v * b14;
    t19 += v * b15;
    v = a[5 + aoff];
    t5 += v * b0;
    t6 += v * b1;
    t7 += v * b2;
    t8 += v * b3;
    t9 += v * b4;
    t10 += v * b5;
    t11 += v * b6;
    t12 += v * b7;
    t13 += v * b8;
    t14 += v * b9;
    t15 += v * b10;
    t16 += v * b11;
    t17 += v * b12;
    t18 += v * b13;
    t19 += v * b14;
    t20 += v * b15;
    v = a[6 + aoff];
    t6 += v * b0;
    t7 += v * b1;
    t8 += v * b2;
    t9 += v * b3;
    t10 += v * b4;
    t11 += v * b5;
    t12 += v * b6;
    t13 += v * b7;
    t14 += v * b8;
    t15 += v * b9;
    t16 += v * b10;
    t17 += v * b11;
    t18 += v * b12;
    t19 += v * b13;
    t20 += v * b14;
    t21 += v * b15;
    v = a[7 + aoff];
    t7 += v * b0;
    t8 += v * b1;
    t9 += v * b2;
    t10 += v * b3;
    t11 += v * b4;
    t12 += v * b5;
    t13 += v * b6;
    t14 += v * b7;
    t15 += v * b8;
    t16 += v * b9;
    t17 += v * b10;
    t18 += v * b11;
    t19 += v * b12;
    t20 += v * b13;
    t21 += v * b14;
    t22 += v * b15;
    v = a[8 + aoff];
    t8 += v * b0;
    t9 += v * b1;
    t10 += v * b2;
    t11 += v * b3;
    t12 += v * b4;
    t13 += v * b5;
    t14 += v * b6;
    t15 += v * b7;
    t16 += v * b8;
    t17 += v * b9;
    t18 += v * b10;
    t19 += v * b11;
    t20 += v * b12;
    t21 += v * b13;
    t22 += v * b14;
    t23 += v * b15;
    v = a[9 + aoff];
    t9 += v * b0;
    t10 += v * b1;
    t11 += v * b2;
    t12 += v * b3;
    t13 += v * b4;
    t14 += v * b5;
    t15 += v * b6;
    t16 += v * b7;
    t17 += v * b8;
    t18 += v * b9;
    t19 += v * b10;
    t20 += v * b11;
    t21 += v * b12;
    t22 += v * b13;
    t23 += v * b14;
    t24 += v * b15;
    v = a[10 + aoff];
    t10 += v * b0;
    t11 += v * b1;
    t12 += v * b2;
    t13 += v * b3;
    t14 += v * b4;
    t15 += v * b5;
    t16 += v * b6;
    t17 += v * b7;
    t18 += v * b8;
    t19 += v * b9;
    t20 += v * b10;
    t21 += v * b11;
    t22 += v * b12;
    t23 += v * b13;
    t24 += v * b14;
    t25 += v * b15;
    v = a[11 + aoff];
    t11 += v * b0;
    t12 += v * b1;
    t13 += v * b2;
    t14 += v * b3;
    t15 += v * b4;
    t16 += v * b5;
    t17 += v * b6;
    t18 += v * b7;
    t19 += v * b8;
    t20 += v * b9;
    t21 += v * b10;
    t22 += v * b11;
    t23 += v * b12;
    t24 += v * b13;
    t25 += v * b14;
    t26 += v * b15;
    v = a[12 + aoff];
    t12 += v * b0;
    t13 += v * b1;
    t14 += v * b2;
    t15 += v * b3;
    t16 += v * b4;
    t17 += v * b5;
    t18 += v * b6;
    t19 += v * b7;
    t20 += v * b8;
    t21 += v * b9;
    t22 += v * b10;
    t23 += v * b11;
    t24 += v * b12;
    t25 += v * b13;
    t26 += v * b14;
    t27 += v * b15;
    v = a[13 + aoff];
    t13 += v * b0;
    t14 += v * b1;
    t15 += v * b2;
    t16 += v * b3;
    t17 += v * b4;
    t18 += v * b5;
    t19 += v * b6;
    t20 += v * b7;
    t21 += v * b8;
    t22 += v * b9;
    t23 += v * b10;
    t24 += v * b11;
    t25 += v * b12;
    t26 += v * b13;
    t27 += v * b14;
    t28 += v * b15;
    v = a[14 + aoff];
    t14 += v * b0;
    t15 += v * b1;
    t16 += v * b2;
    t17 += v * b3;
    t18 += v * b4;
    t19 += v * b5;
    t20 += v * b6;
    t21 += v * b7;
    t22 += v * b8;
    t23 += v * b9;
    t24 += v * b10;
    t25 += v * b11;
    t26 += v * b12;
    t27 += v * b13;
    t28 += v * b14;
    t29 += v * b15;
    v = a[15 + aoff];
    t15 += v * b0;
    t16 += v * b1;
    t17 += v * b2;
    t18 += v * b3;
    t19 += v * b4;
    t20 += v * b5;
    t21 += v * b6;
    t22 += v * b7;
    t23 += v * b8;
    t24 += v * b9;
    t25 += v * b10;
    t26 += v * b11;
    t27 += v * b12;
    t28 += v * b13;
    t29 += v * b14;
    t30 += v * b15;

    t0 += 38 * t16;
    t1 += 38 * t17;
    t2 += 38 * t18;
    t3 += 38 * t19;
    t4 += 38 * t20;
    t5 += 38 * t21;
    t6 += 38 * t22;
    t7 += 38 * t23;
    t8 += 38 * t24;
    t9 += 38 * t25;
    t10 += 38 * t26;
    t11 += 38 * t27;
    t12 += 38 * t28;
    t13 += 38 * t29;
    t14 += 38 * t30;
// t15 left as is

// first car
    c = 1;
    v = t0 + c + 65535;
    c = v >> 16;
    t0 = v - c * 65536;
    v = t1 + c + 65535;
    c = v >> 16;
    t1 = v - c * 65536;
    v = t2 + c + 65535;
    c = v >> 16;
    t2 = v - c * 65536;
    v = t3 + c + 65535;
    c = v >> 16;
    t3 = v - c * 65536;
    v = t4 + c + 65535;
    c = v >> 16;
    t4 = v - c * 65536;
    v = t5 + c + 65535;
    c = v >> 16;
    t5 = v - c * 65536;
    v = t6 + c + 65535;
    c = v >> 16;
    t6 = v - c * 65536;
    v = t7 + c + 65535;
    c = v >> 16;
    t7 = v - c * 65536;
    v = t8 + c + 65535;
    c = v >> 16;
    t8 = v - c * 65536;
    v = t9 + c + 65535;
    c = v >> 16;
    t9 = v - c * 65536;
    v = t10 + c + 65535;
    c = v >> 16;
    t10 = v - c * 65536;
    v = t11 + c + 65535;
    c = v >> 16;
    t11 = v - c * 65536;
    v = t12 + c + 65535;
    c = v >> 16;
    t12 = v - c * 65536;
    v = t13 + c + 65535;
    c = v >> 16;
    t13 = v - c * 65536;
    v = t14 + c + 65535;
    c = v >> 16;
    t14 = v - c * 65536;
    v = t15 + c + 65535;
    c = v >> 16;
    t15 = v - c * 65536;
    t0 += c - 1 + 37 * (c - 1);

// second car
    c = 1;
    v = t0 + c + 65535;
    c = v >> 16;
    t0 = v - c * 65536;
    v = t1 + c + 65535;
    c = v >> 16;
    t1 = v - c * 65536;
    v = t2 + c + 65535;
    c = v >> 16;
    t2 = v - c * 65536;
    v = t3 + c + 65535;
    c = v >> 16;
    t3 = v - c * 65536;
    v = t4 + c + 65535;
    c = v >> 16;
    t4 = v - c * 65536;
    v = t5 + c + 65535;
    c = v >> 16;
    t5 = v - c * 65536;
    v = t6 + c + 65535;
    c = v >> 16;
    t6 = v - c * 65536;
    v = t7 + c + 65535;
    c = v >> 16;
    t7 = v - c * 65536;
    v = t8 + c + 65535;
    c = v >> 16;
    t8 = v - c * 65536;
    v = t9 + c + 65535;
    c = v >> 16;
    t9 = v - c * 65536;
    v = t10 + c + 65535;
    c = v >> 16;
    t10 = v - c * 65536;
    v = t11 + c + 65535;
    c = v >> 16;
    t11 = v - c * 65536;
    v = t12 + c + 65535;
    c = v >> 16;
    t12 = v - c * 65536;
    v = t13 + c + 65535;
    c = v >> 16;
    t13 = v - c * 65536;
    v = t14 + c + 65535;
    c = v >> 16;
    t14 = v - c * 65536;
    v = t15 + c + 65535;
    c = v >> 16;
    t15 = v - c * 65536;
    t0 += c - 1 + 37 * (c - 1);

    o[0 + ooff] = t0;
    o[1 + ooff] = t1;
    o[2 + ooff] = t2;
    o[3 + ooff] = t3;
    o[4 + ooff] = t4;
    o[5 + ooff] = t5;
    o[6 + ooff] = t6;
    o[7 + ooff] = t7;
    o[8 + ooff] = t8;
    o[9 + ooff] = t9;
    o[10 + ooff] = t10;
    o[11 + ooff] = t11;
    o[12 + ooff] = t12;
    o[13 + ooff] = t13;
    o[14 + ooff] = t14;
    o[15 + ooff] = t15;
  }

  static void _s(Uint64List o, Uint64List a) {
    _sOff(o, 0, a, 0);
  }

  static void _sOff(
      Uint64List o, final int ooff, Uint64List a, final int aoff) {
    _mOff(o, ooff, a, aoff, a, aoff);
  }

  static void _inv25519(
      Uint64List o, final int ooff, Uint64List? i, final int ioff) {
    Uint64List c = Uint64List(16);
    int a;
    for (a = 0; a < 16; a++) c[a] = i![a + ioff];
    for (a = 253; a >= 0; a--) {
      _sOff(c, 0, c, 0);
      if (a != 2 && a != 4) _mOff(c, 0, c, 0, i!, ioff);
    }
    for (a = 0; a < 16; a++) o[a + ooff] = c[a];
  }

  static void _pow2523(Uint64List o, Uint64List i) {
    Uint64List c = Uint64List(16);
    int a;

    for (a = 0; a < 16; a++) c[a] = i[a];

    for (a = 250; a >= 0; a--) {
      _sOff(c, 0, c, 0);
      if (a != 1) _mOff(c, 0, c, 0, i, 0);
    }

    for (a = 0; a < 16; a++) o[a] = c[a];
  }

  static int cryptoScalarmult(Uint8List q, Uint8List n, Uint8List p) {
    Uint8List z = Uint8List(32);
    Uint64List x = Uint64List(80);
    int r, i;
    Uint64List a = Uint64List(16),
        b = Uint64List(16),
        c = Uint64List(16),
        d = Uint64List(16),
        e = Uint64List(16),
        f = Uint64List(16);
    for (i = 0; i < 31; i++) z[i] = n[i];
    z[31] = (n[31] & 127) | 64;
    z[0] &= 248;
    unpack25519(x, p);
    for (i = 0; i < 16; i++) {
      b[i] = x[i];
      d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
      r = (Int32(z[Int32(i).shiftRightUnsigned(3).toInt()])
                  .shiftRightUnsigned(i & 7))
              .toInt() &
          1;
      _sel25519(a, b, r);
      _sel25519(c, d, r);
      _a(e, a, c);
      _z(a, a, c);
      _a(c, b, d);
      _z(b, b, d);
      _s(d, e);
      _s(f, a);
      _m(a, c, a);
      _m(c, b, e);
      _a(e, a, c);
      _z(a, a, c);
      _s(b, a);
      _z(c, d, f);
      _m(a, c, one21665);
      _a(a, a, d);
      _m(c, c, a);
      _m(a, d, f);
      _m(d, b, x);
      _s(b, e);
      _sel25519(a, b, r);
      _sel25519(c, d, r);
    }
    for (i = 0; i < 16; i++) {
      x[i + 16] = a[i];
      x[i + 32] = c[i];
      x[i + 48] = b[i];
      x[i + 64] = d[i];
    }
    _inv25519(x, 32, x, 32);
    _mOff(x, 16, x, 16, x, 32);
    _pack25519(q, x, 16);

    return 0;
  }

  static int cryptoScalarmultBase(Uint8List q, Uint8List n) {
    return cryptoScalarmult(q, n, nine);
  }

  static int cryptoBoxKeypair(Uint8List y, Uint8List x) {
    randombytesArrayLen(x, 32);
    return cryptoScalarmultBase(y, x);
  }

  static int cryptoBoxBeforenm(Uint8List k, Uint8List y, Uint8List x) {
    Uint8List s = Uint8List(32);
    cryptoScalarmult(s, x, y);

/*String dbgt = "";
		for (int dbg = 0; dbg < s.length; dbg ++) dbgt += " "+s[dbg];
		Log.d(TAG, "cryptoBoxBeforenm -> "+dbgt);

	    dbgt = "";
		for (int dbg = 0; dbg < x.length; dbg ++) dbgt += " "+x[dbg];
		Log.d(TAG, "cryptoBoxBeforenm, x -> "+dbgt);
	    dbgt = "";
		for (int dbg = 0; dbg < y.length; dbg ++) dbgt += " "+y[dbg];
		Log.d(TAG, "cryptoBoxBeforenm, y -> "+dbgt);
		*/

    return cryptoCoreHsalsa20(k, zero, s, _sigma);
  }

  static int cryptoBoxAfternm(
      Uint8List c, Uint8List m, int /*long*/ d, Uint8List n, Uint8List k) {
    return cryptoSecretbox(c, m, d, n, k);
  }

  static int cryptoBoxOpenAfternm(
      Uint8List m, Uint8List c, int /*long*/ d, Uint8List n, Uint8List k) {
    return cryptoSecretboxOpen(m, c, d, n, k);
  }

  int cryptoBox(Uint8List c, Uint8List m, int /*long*/ d, Uint8List n,
      Uint8List y, Uint8List x) {
    Uint8List k = Uint8List(32);

    ///L/og.d(TAG, "cryptoBox start ...");

    cryptoBoxBeforenm(k, y, x);
    return cryptoBoxAfternm(c, m, d, n, k);
  }

  int cryptoBoxOpen(Uint8List m, Uint8List c, int /*long*/ d, Uint8List n,
      Uint8List y, Uint8List x) {
    Uint8List k = Uint8List(32);
    cryptoBoxBeforenm(k, y, x);
    return cryptoBoxOpenAfternm(m, c, d, n, k);
  }

  // TBD 64bits of n
  ///int cryptoHash(Uint8List out, Uint8List m, long n)
  static int cryptoHashOff(Uint8List out, Uint8List m, final int moff, int n) {
    Uint8List input = Uint8List(n);
    for (int i = 0; i < n; ++i) {
      input[i] = m[i];
    }
    Blake2bDigest blake2b = Blake2bDigest(digestSize: n);
    blake2b.update(input, 0, input.length);
    blake2b.doFinal(out, moff);

    return 0;
  }

  static int cryptoHash(Uint8List out, Uint8List m) {
    return cryptoHashOff(out, m, 0, m != null ? m.length : 0);
  }

// gf: long[16]
  ///private static void add(gf p[4],gf q[4])
  static void _add(List<Uint64List?> p, List<Uint64List?> q) {
    Uint64List a = Uint64List(16);
    Uint64List b = Uint64List(16);
    Uint64List c = Uint64List(16);
    Uint64List d = Uint64List(16);
    Uint64List t = Uint64List(16);
    Uint64List e = Uint64List(16);
    Uint64List f = Uint64List(16);
    Uint64List g = Uint64List(16);
    Uint64List h = Uint64List(16);

    Uint64List p0 = p[0]!;
    Uint64List p1 = p[1]!;
    Uint64List p2 = p[2]!;
    Uint64List p3 = p[3]!;

    Uint64List? q0 = q[0];
    Uint64List? q1 = q[1];
    Uint64List q2 = q[2]!;
    Uint64List q3 = q[3]!;

    _zOff(a, 0, p1, 0, p0, 0);
    _zOff(t, 0, q1, 0, q0, 0);
    _mOff(a, 0, a, 0, t, 0);
    _aOff(b, 0, p0, 0, p1, 0);
    _aOff(t, 0, q0, 0, q1, 0);
    _mOff(b, 0, b, 0, t, 0);
    _mOff(c, 0, p3, 0, q3, 0);
    _mOff(c, 0, c, 0, d2, 0);
    _mOff(d, 0, p2, 0, q2, 0);

    _aOff(d, 0, d, 0, d, 0);
    _zOff(e, 0, b, 0, a, 0);
    _zOff(f, 0, d, 0, c, 0);
    _aOff(g, 0, d, 0, c, 0);
    _aOff(h, 0, b, 0, a, 0);

    _mOff(p0, 0, e, 0, f, 0);
    _mOff(p1, 0, h, 0, g, 0);
    _mOff(p2, 0, g, 0, f, 0);
    _mOff(p3, 0, e, 0, h, 0);
  }

  static void _cswap(List<Uint64List?> p, List<Uint64List?> q, int b) {
    int i;

    for (i = 0; i < 4; i++) _sel25519Off(p[i], 0, q[i], 0, b);
  }

  static void _pack(Uint8List r, List<Uint64List?> p) {
    Uint64List tx = Uint64List(16);
    Uint64List ty = Uint64List(16);
    Uint64List zi = Uint64List(16);

    _inv25519(zi, 0, p[2], 0);
    _mOff(tx, 0, p[0]!, 0, zi, 0);
    _mOff(ty, 0, p[1]!, 0, zi, 0);

    _pack25519(r, ty, 0);

    r[31] ^= _par25519Off(tx, 0) << 7;
  }

  static void _scalarmult(
      List<Uint64List?> p, List<Uint64List?> q, Uint8List s, final int soff) {
    int i;

    _set25519(p[0], gf0);
    _set25519(p[1], gf1);
    _set25519(p[2], gf1);
    _set25519(p[3], gf0);

    for (i = 255; i >= 0; --i) {
      int b = ((Int32(s[(i / 8 + soff).toInt()]).shiftRightUnsigned(i & 7))
              .toInt() &
          1);

      _cswap(p, q, b);
      _add(q, p);
      _add(p, p);
      _cswap(p, q, b);
    }
  }

  static void _scalarbase(List<Uint64List?> p, Uint8List s, final int soff) {
    List<Uint64List?> q = List<Uint64List?>.filled(4, Uint64List(0));

    q[0] = Uint64List(16);
    q[1] = Uint64List(16);
    q[2] = Uint64List(16);
    q[3] = Uint64List(16);

    _set25519(q[0], x);
    _set25519(q[1], y);
    _set25519(q[2], gf1);
    _mOff(q[3]!, 0, x, 0, y, 0);
    _scalarmult(p, q, s, soff);
  }

  static int cryptoSignKeypair(Uint8List pk, Uint8List sk, bool seeded) {
    Uint8List d = Uint8List(64);
    List<Uint64List?> p = List<Uint64List?>.filled(4, Uint64List(0));

    p[0] = Uint64List(16);
    p[1] = Uint64List(16);
    p[2] = Uint64List(16);
    p[3] = Uint64List(16);

    int i;

    if (!seeded) randombytesArrayLen(sk, 32);
    cryptoHashOff(d, sk, 0, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    _scalarbase(p, d, 0);
    _pack(pk, p);

    for (i = 0; i < 32; i++) sk[i + 32] = pk[i];
    return 0;
  }

  static final Uint64List L = Uint64List.fromList([
    0xed,
    0xd3,
    0xf5,
    0x5c,
    0x1a,
    0x63,
    0x12,
    0x58,
    0xd6,
    0x9c,
    0xf7,
    0xa2,
    0xde,
    0xf9,
    0xde,
    0x14,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x10
  ]);

  static void _modL(Uint8List r, final int roff, Uint64List x) {
    int carry;
    int i, j;

    for (i = 63; i >= 32; --i) {
      carry = 0;
      for (j = i - 32; j < i - 12; ++j) {
        x[j] += carry - 16 * x[i] * L[j - (i - 32)];
        carry = (x[j] + 128) >> 8;
        x[j] -= carry << 8;
      }
      x[j] += carry;
      x[i] = 0;
    }
    carry = 0;

    for (j = 0; j < 32; j++) {
      x[j] += carry - (x[31] >> 4) * L[j];
      carry = x[j] >> 8;
      x[j] &= 255;
    }

    for (j = 0; j < 32; j++) x[j] -= carry * L[j];

    for (i = 0; i < 32; i++) {
      x[i + 1] += x[i] >> 8;
      r[i + roff] = (x[i] & 255);
    }
  }

  static void _reduce(Uint8List r) {
    Uint64List x = Uint64List(64);
    int i;

    for (i = 0; i < 64; i++) x[i] = (r[i] & 0xff).toInt();

    for (i = 0; i < 64; i++) r[i] = 0;

    _modL(r, 0, x);
  }

  static int cryptoSign(Uint8List sm, int dummy, Uint8List m, final int moff,
      int /*long*/ n, Uint8List sk) {
    Uint8List d = Uint8List(64), h = Uint8List(64), r = Uint8List(64);

    int i, j;

    Uint64List x = Uint64List(64);
    List<Uint64List?> p = List<Uint64List?>.filled(4, Uint64List(0));

    p[0] = Uint64List(16);
    p[1] = Uint64List(16);
    p[2] = Uint64List(16);
    p[3] = Uint64List(16);

    Uint8List pk = Nano.pkFromSecret(sk);

    Blake2bDigest blake2b = Blake2bDigest(digestSize: 64);
    blake2b.update(sk, 0, sk.length);
    blake2b.doFinal(d, 0);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    int smlen = n + 64;
    for (i = 0; i < n; i++) sm[64 + i] = m[i + moff];
    for (i = 0; i < 32; i++) sm[32 + i] = d[32 + i];

    blake2b = Blake2bDigest(digestSize: 64);
    blake2b.update(sm.sublist(32), 0, sm.sublist(32).length);
    blake2b.doFinal(r, 0);

    _reduce(r);
    _scalarbase(p, r, 0);
    _pack(sm, p);

    for (i = 32; i < 64; i++) sm[i] = pk[i - 32];

    blake2b = Blake2bDigest(digestSize: 64);
    blake2b.update(sm, 0, sm.length);
    blake2b.doFinal(h, 0);

    _reduce(h);

    for (i = 0; i < 64; i++) x[i] = 0;
    for (i = 0; i < 32; i++) x[i] = r[i];
    for (i = 0; i < 32; i++) {
      for (j = 0; j < 32; j++) {
        x[i + j] += h[i] * d[j];
      }
    }
    _modL(sm, 32, x);

    return smlen;
  }

  static int _unpackneg(List<Uint64List?> r, Uint8List p) {
    Uint64List t = Uint64List(16);
    Uint64List chk = Uint64List(16);
    Uint64List num = Uint64List(16);
    Uint64List den = Uint64List(16);
    Uint64List den2 = Uint64List(16);
    Uint64List den4 = Uint64List(16);
    Uint64List den6 = Uint64List(16);

    _set25519(r[2], gf1);
    unpack25519(r[1]!, p);
    _s(num, r[1]!);
    _m(den, num, D);
    _z(num, num, r[2]);
    _a(den, r[2], den);

    _s(den2, den);
    _s(den4, den2);
    _m(den6, den4, den2);
    _m(t, den6, num);
    _m(t, t, den);

    _pow2523(t, t);
    _m(t, t, num);
    _m(t, t, den);
    _m(t, t, den);
    _m(r[0]!, t, den);

    _s(chk, r[0]!);
    _m(chk, chk, den);
    if (_neq25519(chk, num) != 0) _m(r[0]!, r[0]!, i);

    _s(chk, r[0]!);
    _m(chk, chk, den);
    if (_neq25519(chk, num) != 0) return -1;

    if (_par25519(r[0]) == (Int32(p[31] & 0xFF).shiftRightUnsigned(7).toInt()))
      _z(r[0], gf0, r[0]);

    _m(r[3]!, r[0]!, r[1]!);

    return 0;
  }

  /// TBD 64bits of mlen
  ///int cryptoSignOpen(Uint8Listm,long *mlen,Uint8Listsm,long n,Uint8Listpk)
  static int cryptoSignOpen(Uint8List m, int dummy /* *mlen not used*/,
      Uint8List sm, final int smoff, int /*long*/ n, Uint8List pk) {
    int i;
    Uint8List t = Uint8List(32), h = Uint8List(64);
    List<Uint64List?> p = List<Uint64List?>.filled(4, Uint64List(0));

    p[0] = Uint64List(16);
    p[1] = Uint64List(16);
    p[2] = Uint64List(16);
    p[3] = Uint64List(16);

    List<Uint64List?> q = List<Uint64List?>.filled(4, Uint64List(0));
    q[0] = Uint64List(16);
    q[1] = Uint64List(16);
    q[2] = Uint64List(16);
    q[3] = Uint64List(16);

    ///*mlen = -1;

    if (n < 64) return -1;

    if (_unpackneg(q, pk) != 0) return -1;

    for (i = 0; i < n; i++) m[i] = sm[i + smoff];

    for (i = 0; i < 32; i++) m[i + 32] = pk[i];

    cryptoHashOff(h, m, 0, n);

    _reduce(h);
    _scalarmult(p, q, h, 0);

    _scalarbase(q, sm, 32 + smoff);
    _add(p, q);
    _pack(t, p);

    n -= 64;
    if (_cryptoVerify32(sm, smoff, t, 0) != 0) {
// optimizing it
      ///for (i = 0; i < n; i ++) m[i] = 0;
      return -1;
    }

// TBD optimizing ...
    ///for (i = 0; i < n; i ++) m[i] = sm[i + 64 + smoff];
    ///*mlen = n;

    return 0;
  }

  static Random jrandom = Random.secure();

  static Uint8List randombytesArray(Uint8List x) {
    return randombytesArrayLen(x, x.length);
  }

  static Uint8List randombytes(int len) {
    return randombytesArray(Uint8List(len));
  }

  static Uint8List randombytesArrayLen(Uint8List x, int len) {
    int ret = len % 4;
    Int64 rnd;
    for (int i = 0; i < len - ret; i += 4) {
      rnd = Int64(jrandom.nextInt(1 << 32));
      x[i + 0] = (rnd.shiftRightUnsigned(0).toInt());
      x[i + 1] = (rnd.shiftRightUnsigned(8).toInt());
      x[i + 2] = (rnd.shiftRightUnsigned(16).toInt());
      x[i + 3] = (rnd.shiftRightUnsigned(24).toInt());
    }
    if (ret > 0) {
      rnd = Int64(jrandom.nextInt(1 << 32));
      for (int i = len - ret; i < len; i++)
        x[i] = (rnd.shiftRightUnsigned(8 * i).toInt());
    }
    return x;
  }

  static String hexEncodeToString(Uint8List raw) {
    return hex.encode(raw).toUpperCase();
  }

  static List<int> hexDecode(String s) {
    return hex.decode(s);
  }
}

/*
 * Port of Andrew Moon's Poly1305-donna-16. Public domain.
 * https://github.com/floodyberry/poly1305-donna
 */
class Poly1305 {
  Uint8List? _buffer;
  late List<Int32> _r;
  late List<Int32> _h;
  late Int32List _pad;
  int _leftover = 0;
  int? _fin;

  Poly1305(Uint8List key) {
    this._buffer = Uint8List(16);
    this._r = List<Int32>.filled(10, Int32(0));
    this._h = List<Int32>.filled(10, Int32(0));
    this._pad = Int32List(8);
    this._leftover = 0;
    this._fin = 0;

    Int32 t0, t1, t2, t3, t4, t5, t6, t7;

    t0 = Int32(key[0] & 0xff | (key[1] & 0xff) << 8);
    this._r[0] = (t0) & 0x1fff;
    t1 = Int32(key[2] & 0xff | (key[3] & 0xff) << 8);
    this._r[1] = ((t0.shiftRightUnsigned(13)) | (t1 << 3)) & 0x1fff;
    t2 = Int32(key[4] & 0xff | (key[5] & 0xff) << 8);
    this._r[2] = ((t1.shiftRightUnsigned(10)) | (t2 << 6)) & 0x1f03;
    t3 = Int32(key[6] & 0xff | (key[7] & 0xff) << 8);
    this._r[3] = ((t2.shiftRightUnsigned(7)) | (t3 << 9)) & 0x1fff;
    t4 = Int32(key[8] & 0xff | (key[9] & 0xff) << 8);
    this._r[4] = ((t3.shiftRightUnsigned(4)) | (t4 << 12)) & 0x00ff;
    this._r[5] = ((t4.shiftRightUnsigned(1))) & 0x1ffe;
    t5 = Int32(key[10] & 0xff | (key[11] & 0xff) << 8);
    this._r[6] = ((t4.shiftRightUnsigned(14)) | (t5 << 2)) & 0x1fff;
    t6 = Int32(key[12] & 0xff | (key[13] & 0xff) << 8);
    this._r[7] = ((t5.shiftRightUnsigned(11)) | (t6 << 5)) & 0x1f81;
    t7 = Int32(key[14] & 0xff | (key[15] & 0xff) << 8);
    this._r[8] = ((t6.shiftRightUnsigned(8)) | (t7 << 8)) & 0x1fff;
    this._r[9] = ((t7.shiftRightUnsigned(5))) & 0x007f;

    this._pad[0] = key[16] & 0xff | (key[17] & 0xff) << 8;
    this._pad[1] = key[18] & 0xff | (key[19] & 0xff) << 8;
    this._pad[2] = key[20] & 0xff | (key[21] & 0xff) << 8;
    this._pad[3] = key[22] & 0xff | (key[23] & 0xff) << 8;
    this._pad[4] = key[24] & 0xff | (key[25] & 0xff) << 8;
    this._pad[5] = key[26] & 0xff | (key[27] & 0xff) << 8;
    this._pad[6] = key[28] & 0xff | (key[29] & 0xff) << 8;
    this._pad[7] = key[30] & 0xff | (key[31] & 0xff) << 8;
  }

  Poly1305 blocks(Uint8List? m, int mpos, int bytes) {
    int hibit = this._fin != 0 ? 0 : (1 << 11);
    Int32 t0, t1, t2, t3, t4, t5, t6, t7, c;
    Int32 d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;

    Int32 h0 = this._h[0],
        h1 = this._h[1],
        h2 = this._h[2],
        h3 = this._h[3],
        h4 = this._h[4],
        h5 = this._h[5],
        h6 = this._h[6],
        h7 = this._h[7],
        h8 = this._h[8],
        h9 = this._h[9];

    int r0 = this._r[0].toInt(),
        r1 = this._r[1].toInt(),
        r2 = this._r[2].toInt(),
        r3 = this._r[3].toInt(),
        r4 = this._r[4].toInt(),
        r5 = this._r[5].toInt(),
        r6 = this._r[6].toInt(),
        r7 = this._r[7].toInt(),
        r8 = this._r[8].toInt(),
        r9 = this._r[9].toInt();

    while (bytes >= 16) {
      t0 = Int32(m![mpos + 0] & 0xff | (m[mpos + 1] & 0xff) << 8);
      h0 += (t0).toInt() & 0x1fff;
      t1 = Int32(m[mpos + 2] & 0xff | (m[mpos + 3] & 0xff) << 8);
      h1 += ((t0.shiftRightUnsigned(13)) | (t1 << 3)).toInt() & 0x1fff;
      t2 = Int32(m[mpos + 4] & 0xff | (m[mpos + 5] & 0xff) << 8);
      h2 += ((t1.shiftRightUnsigned(10)) | (t2 << 6)).toInt() & 0x1fff;
      t3 = Int32(m[mpos + 6] & 0xff | (m[mpos + 7] & 0xff) << 8);
      h3 += ((t2.shiftRightUnsigned(7)) | (t3 << 9)).toInt() & 0x1fff;
      t4 = Int32(m[mpos + 8] & 0xff | (m[mpos + 9] & 0xff) << 8);
      h4 += ((t3.shiftRightUnsigned(4)) | (t4 << 12)).toInt() & 0x1fff;
      h5 += ((t4.shiftRightUnsigned(1))).toInt() & 0x1fff;
      t5 = Int32(m[mpos + 10] & 0xff | (m[mpos + 11] & 0xff) << 8);
      h6 += ((t4.shiftRightUnsigned(14)) | (t5 << 2)).toInt() & 0x1fff;
      t6 = Int32(m[mpos + 12] & 0xff | (m[mpos + 13] & 0xff) << 8);
      h7 += ((t5.shiftRightUnsigned(11)) | (t6 << 5)).toInt() & 0x1fff;
      t7 = Int32(m[mpos + 14] & 0xff | (m[mpos + 15] & 0xff) << 8);
      h8 += ((t6.shiftRightUnsigned(8)) | (t7 << 8)).toInt() & 0x1fff;
      h9 += ((t7.shiftRightUnsigned(5))).toInt() | hibit;

      c = Int32(0);

      d0 = c;
      d0 += h0 * r0;
      d0 += h1 * (5 * r9);
      d0 += h2 * (5 * r8);
      d0 += h3 * (5 * r7);
      d0 += h4 * (5 * r6);
      c = (d0.shiftRightUnsigned(13));
      d0 &= 0x1fff;
      d0 += h5 * (5 * r5);
      d0 += h6 * (5 * r4);
      d0 += h7 * (5 * r3);
      d0 += h8 * (5 * r2);
      d0 += h9 * (5 * r1);
      c += (d0.shiftRightUnsigned(13));
      d0 &= 0x1fff;

      d1 = c;
      d1 += h0 * r1;
      d1 += h1 * r0;
      d1 += h2 * (5 * r9);
      d1 += h3 * (5 * r8);
      d1 += h4 * (5 * r7);
      c = (d1.shiftRightUnsigned(13));
      d1 &= 0x1fff;
      d1 += h5 * (5 * r6);
      d1 += h6 * (5 * r5);
      d1 += h7 * (5 * r4);
      d1 += h8 * (5 * r3);
      d1 += h9 * (5 * r2);
      c += (d1.shiftRightUnsigned(13));
      d1 &= 0x1fff;

      d2 = c;
      d2 += h0 * r2;
      d2 += h1 * r1;
      d2 += h2 * r0;
      d2 += h3 * (5 * r9);
      d2 += h4 * (5 * r8);
      c = (d2.shiftRightUnsigned(13));
      d2 &= 0x1fff;
      d2 += h5 * (5 * r7);
      d2 += h6 * (5 * r6);
      d2 += h7 * (5 * r5);
      d2 += h8 * (5 * r4);
      d2 += h9 * (5 * r3);
      c += (d2.shiftRightUnsigned(13));
      d2 &= 0x1fff;

      d3 = c;
      d3 += h0 * r3;
      d3 += h1 * r2;
      d3 += h2 * r1;
      d3 += h3 * r0;
      d3 += h4 * (5 * r9);
      c = (d3.shiftRightUnsigned(13));
      d3 &= 0x1fff;
      d3 += h5 * (5 * r8);
      d3 += h6 * (5 * r7);
      d3 += h7 * (5 * r6);
      d3 += h8 * (5 * r5);
      d3 += h9 * (5 * r4);
      c += (d3.shiftRightUnsigned(13));
      d3 &= 0x1fff;

      d4 = c;
      d4 += h0 * r4;
      d4 += h1 * r3;
      d4 += h2 * r2;
      d4 += h3 * r1;
      d4 += h4 * r0;
      c = (d4.shiftRightUnsigned(13));
      d4 &= 0x1fff;
      d4 += h5 * (5 * r9);
      d4 += h6 * (5 * r8);
      d4 += h7 * (5 * r7);
      d4 += h8 * (5 * r6);
      d4 += h9 * (5 * r5);
      c += (d4.shiftRightUnsigned(13));
      d4 &= 0x1fff;

      d5 = c;
      d5 += h0 * r5;
      d5 += h1 * r4;
      d5 += h2 * r3;
      d5 += h3 * r2;
      d5 += h4 * r1;
      c = (d5.shiftRightUnsigned(13));
      d5 &= 0x1fff;
      d5 += h5 * r0;
      d5 += h6 * (5 * r9);
      d5 += h7 * (5 * r8);
      d5 += h8 * (5 * r7);
      d5 += h9 * (5 * r6);
      c += (d5.shiftRightUnsigned(13));
      d5 &= 0x1fff;

      d6 = c;
      d6 += h0 * r6;
      d6 += h1 * r5;
      d6 += h2 * r4;
      d6 += h3 * r3;
      d6 += h4 * r2;
      c = (d6.shiftRightUnsigned(13));
      d6 &= 0x1fff;
      d6 += h5 * r1;
      d6 += h6 * r0;
      d6 += h7 * (5 * r9);
      d6 += h8 * (5 * r8);
      d6 += h9 * (5 * r7);
      c += (d6.shiftRightUnsigned(13));
      d6 &= 0x1fff;

      d7 = c;
      d7 += h0 * r7;
      d7 += h1 * r6;
      d7 += h2 * r5;
      d7 += h3 * r4;
      d7 += h4 * r3;
      c = (d7.shiftRightUnsigned(13));
      d7 &= 0x1fff;
      d7 += h5 * r2;
      d7 += h6 * r1;
      d7 += h7 * r0;
      d7 += h8 * (5 * r9);
      d7 += h9 * (5 * r8);
      c += (d7.shiftRightUnsigned(13));
      d7 &= 0x1fff;

      d8 = c;
      d8 += h0 * r8;
      d8 += h1 * r7;
      d8 += h2 * r6;
      d8 += h3 * r5;
      d8 += h4 * r4;
      c = (d8.shiftRightUnsigned(13));
      d8 &= 0x1fff;
      d8 += h5 * r3;
      d8 += h6 * r2;
      d8 += h7 * r1;
      d8 += h8 * r0;
      d8 += h9 * (5 * r9);
      c += (d8.shiftRightUnsigned(13));
      d8 &= 0x1fff;

      d9 = c;
      d9 += h0 * r9;
      d9 += h1 * r8;
      d9 += h2 * r7;
      d9 += h3 * r6;
      d9 += h4 * r5;
      c = (d9.shiftRightUnsigned(13));
      d9 &= 0x1fff;
      d9 += h5 * r4;
      d9 += h6 * r3;
      d9 += h7 * r2;
      d9 += h8 * r1;
      d9 += h9 * r0;
      c += (d9.shiftRightUnsigned(13));
      d9 &= 0x1fff;

      c = (((c << 2) + c)) | 0 as Int32;
      c = (c + d0) | 0 as Int32;
      d0 = c & 0x1fff;
      c = (c.shiftRightUnsigned(13));
      d1 += c;

      h0 = d0;
      h1 = d1;
      h2 = d2;
      h3 = d3;
      h4 = d4;
      h5 = d5;
      h6 = d6;
      h7 = d7;
      h8 = d8;
      h9 = d9;

      mpos += 16;
      bytes -= 16;
    }
    this._h[0] = h0;
    this._h[1] = h1;
    this._h[2] = h2;
    this._h[3] = h3;
    this._h[4] = h4;
    this._h[5] = h5;
    this._h[6] = h6;
    this._h[7] = h7;
    this._h[8] = h8;
    this._h[9] = h9;

    return this;
  }

  Poly1305 finish(Uint8List mac, int macpos) {
    List<Int32> g = List<Int32>.filled(10, Int32(0));
    int i;
    Int32 c, mask, f;

    if (this._leftover != 0) {
      i = this._leftover;
      this._buffer![i++] = 1;
      for (; i < 16; i++) this._buffer![i] = 0;
      this._fin = 1;
      this.blocks(this._buffer, 0, 16);
    }

    c = this._h[1].shiftRightUnsigned(13);
    this._h[1] &= 0x1fff;
    for (i = 2; i < 10; i++) {
      this._h[i] += c;
      c = this._h[i].shiftRightUnsigned(13);
      this._h[i] &= 0x1fff;
    }
    this._h[0] += (c * 5);
    c = this._h[0].shiftRightUnsigned(13);
    this._h[0] &= 0x1fff;
    this._h[1] += c;
    c = this._h[1].shiftRightUnsigned(13);
    this._h[1] &= 0x1fff;
    this._h[2] += c;

    g[0] = this._h[0] + 5 as Int32;
    c = g[0].shiftRightUnsigned(13);
    g[0] &= 0x1fff;
    for (i = 1; i < 10; i++) {
      g[i] = this._h[i] + c as Int32;
      c = g[i].shiftRightUnsigned(13);
      g[i] &= 0x1fff;
    }
    g[9] -= (1 << 13);
    g[9] &= 0xffff;

    /*
                        backport from tweetnacl-fast.js https://github.com/dchest/tweetnacl-js/releases/tag/v0.14.3
                        <<<
                        "The issue was not properly detecting if st->h was >= 2^130 - 5,
                        coupled with [testing mistake] not catching the failure.
                        The chance of the bug affecting anything in the real world is essentially zero luckily,
                        but it's good to have it fixed."
                        >>>
                        */
    ///change mask = (g[9] >>> ((2 * 8) - 1)) - 1; to as
    mask = (c ^ 1) - 1 as Int32;
    mask &= 0xffff;
    ///////////////////////////////////////

    for (i = 0; i < 10; i++) g[i] &= mask;
    mask = ~mask;
    for (i = 0; i < 10; i++) this._h[i] = (this._h[i] & mask) | g[i];

    this._h[0] = ((this._h[0]) | (this._h[1] << 13)) & 0xffff;
    this._h[1] =
        ((this._h[1].shiftRightUnsigned(3)) | (this._h[2] << 10)) & 0xffff;
    this._h[2] =
        ((this._h[2].shiftRightUnsigned(6)) | (this._h[3] << 7)) & 0xffff;
    this._h[3] =
        ((this._h[3].shiftRightUnsigned(9)) | (this._h[4] << 4)) & 0xffff;
    this._h[4] = ((this._h[4].shiftRightUnsigned(12)) |
            (this._h[5] << 1) |
            (this._h[6] << 14)) &
        0xffff;
    this._h[5] =
        ((this._h[6].shiftRightUnsigned(2)) | (this._h[7] << 11)) & 0xffff;
    this._h[6] =
        ((this._h[7].shiftRightUnsigned(5)) | (this._h[8] << 8)) & 0xffff;
    this._h[7] =
        ((this._h[8].shiftRightUnsigned(8)) | (this._h[9] << 5)) & 0xffff;

    f = this._h[0] + this._pad[0] as Int32;
    this._h[0] = f & 0xffff;
    for (i = 1; i < 8; i++) {
      f = (((this._h[i] + this._pad[i]) | 0) + (f.shiftRightUnsigned(16))) | 0
          as Int32;
      this._h[i] = f & 0xffff;
    }

    mac[macpos + 0] = ((this._h[0].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 1] = ((this._h[0].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 2] = ((this._h[1].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 3] = ((this._h[1].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 4] = ((this._h[2].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 5] = ((this._h[2].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 6] = ((this._h[3].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 7] = ((this._h[3].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 8] = ((this._h[4].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 9] = ((this._h[4].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 10] = ((this._h[5].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 11] = ((this._h[5].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 12] = ((this._h[6].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 13] = ((this._h[6].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 14] = ((this._h[7].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 15] = ((this._h[7].shiftRightUnsigned(8)) & 0xff).toInt();

    return this;
  }

  Poly1305 update(Uint8List m, int mpos, int bytes) {
    int i, want;

    if (this._leftover != 0) {
      want = (16 - this._leftover);
      if (want > bytes) want = bytes;
      for (i = 0; i < want; i++)
        this._buffer![this._leftover + i] = m[mpos + i];
      bytes -= want;
      mpos += want;
      this._leftover += want;
      if (this._leftover < 16) return this;
      this.blocks(_buffer, 0, 16);
      this._leftover = 0;
    }

    if (bytes >= 16) {
      want = bytes - (bytes % 16);
      this.blocks(m, mpos, want);
      mpos += want;
      bytes -= want;
    }

    if (bytes != 0) {
      for (i = 0; i < bytes; i++)
        this._buffer![this._leftover + i] = m[mpos + i];
      this._leftover += bytes;
    }

    return this;
  }
}

class Nano {
  static Uint8List pkFromSecret(Uint8List secretKey) {
    Uint8List d = Uint8List(64);
    List<Uint64List?> p = List<Uint64List?>.filled(4, Uint64List(0));

    p[0] = Uint64List(16);
    p[1] = Uint64List(16);
    p[2] = Uint64List(16);
    p[3] = Uint64List(16);
    Uint8List pk = Uint8List(32);
    Blake2bDigest blake2b = Blake2bDigest(digestSize: 64);
    blake2b.update(secretKey, 0, secretKey.length);
    blake2b.doFinal(d, 0);

    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    TweetNaclFast._scalarbase(p, d, 0);
    TweetNaclFast._pack(pk, p);
    return pk;
  }
}
