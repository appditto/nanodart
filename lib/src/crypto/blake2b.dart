import 'dart:typed_data';

import 'package:pointycastle/digests/blake2b.dart';

class Blake2b {
  static const int DIGEST_256 = 256 ~/ 8;

  static Uint8List digest256(List<Uint8List> bytes) {
    return digest(DIGEST_256, bytes);
  }

  static Uint8List digest(int digestSize, List<Uint8List> byteArrays) {
    Uint8List output = Uint8List(digestSize);
    Blake2bDigest blake2b = Blake2bDigest(digestSize: digestSize);
    byteArrays.forEach(
        (byteArray) => byteArray.forEach((byte) => blake2b.updateByte(byte)));
    blake2b.doFinal(output, 0);
    return output;
  }
}