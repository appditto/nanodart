import 'dart:typed_data';

import 'package:nanodart/src/crypto/tweetnacl_blake2b.dart';
import 'package:nanodart/src/ffi/ed25519_blake2b.dart' as ed;
import 'package:nanodart/src/util.dart';

class NanoSignatures {
  static String signBlock(String hash, String privKey) {
    return NanoHelpers.byteToHex(Signature.detached(
            NanoHelpers.hexToBytes(hash), NanoHelpers.hexToBytes(privKey)))
        .toUpperCase();
  }

/*
  static String signBlock(String hash, String privKey) {
    return NanoHelpers.byteToHex(
      Ed25519Blake2b().signMessage(
        NanoHelpers.hexToBytes(hash),
        NanoHelpers.hexToBytes(privKey)
      )
    );
  }*/

  static bool validateSig(String hash, Uint8List pubKey, Uint8List signature) {
    return ed.Ed25519Blake2b().verifySignature(
      NanoHelpers.hexToBytes(hash),
      pubKey,
      signature
    );
  }
}