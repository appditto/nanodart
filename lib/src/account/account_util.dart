import "dart:typed_data" show Uint8List;

import 'package:nanodart/src/account/account_coder.dart';
import 'package:nanodart/src/account/account_type.dart';
import 'package:nanodart/src/crypto/blake2b.dart';
import 'package:nanodart/src/util.dart';

class NanoAccounts {
  static NanoAccountEncodes encoder = NanoAccountEncodes();

  static String createAccount(int accountType, String publicKey) {
    assert(accountType == NanoAccountType.BANANO ||
        accountType == NanoAccountType.NANO);
    String binaryPubkey = NanoHelpers.hexToBinary(publicKey).padLeft(260, "0");
    String encodedChecksum = calculatedEncodedChecksum(publicKey);
    String encodedPubkey = encoder.encode(binaryPubkey);
    return NanoAccountType.getPrefix(accountType) +
        encodedPubkey +
        encodedChecksum;
  }

  static String? findAccountInString(int accountType, String account) {
    assert(accountType == NanoAccountType.BANANO ||
        accountType == NanoAccountType.NANO);
    assert(account != null);
    // Ensure regex match
    RegExp regEx = RegExp(NanoAccountType.getRegex(accountType));
    return regEx.stringMatch(account);
  }

  static bool isValid(int accountType, String account) {
    assert(accountType == NanoAccountType.BANANO ||
        accountType == NanoAccountType.NANO);
    assert(account != null);
    if (account == null) {
      return false;
    }
    // Ensure regex match
    RegExp regEx = RegExp(NanoAccountType.getRegex(accountType));
    if (!regEx.hasMatch(account)) {
      return false;
    }
    String expectedChecksum = account.substring(account.length - 8);
    String encodedChecksum;
    try {
      encodedChecksum = calculatedEncodedChecksum(extractPublicKey(account));
    } catch (e) {
      return false;
    }
    return expectedChecksum == encodedChecksum;
  }

  static String extractEncodedPublicKey(String account) {
    return account.startsWith("nano_")
        ? account.substring(5, 57)
        : account.substring(4, 56);
  }

  static String extractPublicKey(String account) {
    assert(account != null);
    String encodedPublicKey = extractEncodedPublicKey(account);
    String binaryPublicKey = encoder.decode(encodedPublicKey).substring(4);
    String hexPublicKey =
        NanoHelpers.binaryToHex(binaryPublicKey).padLeft(64, "0");
    return hexPublicKey;
  }

  static String calculatedEncodedChecksum(String publicKey) {
    Uint8List checksum = NanoHelpers.reverse(
        Blake2b.digest(5, [NanoHelpers.hexToBytes(publicKey)]));
    String binaryChecksum =
        NanoHelpers.hexToBinary(NanoHelpers.byteToHex(checksum))
            .padLeft(40, "0");
    return encoder.encode(binaryChecksum);
  }
}