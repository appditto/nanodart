import 'package:nanodart/src/crypto/tweetnacl_blake2b.dart';
import 'package:nanodart/src/util.dart';

class NanoSignatures {
  static String signBlock(String hash, String privKey) {
    return NanoHelpers.byteToHex(Signature.detached(
            NanoHelpers.hexToBytes(hash), NanoHelpers.hexToBytes(privKey)))
        .toUpperCase();
  }
}