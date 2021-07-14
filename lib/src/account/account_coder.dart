import 'dart:collection';

/// Tools to encode and decode accounts to/from bytes
class NanoAccountEncodes {
  // Characters mapped to binary
  HashMap<String, String> characterTable = HashMap();
  HashMap<String, String> binaryTable = HashMap();

  NanoAccountEncodes() {
    // Possible characters an account may contain
    List<String> accountMap = "13456789abcdefghijkmnopqrstuwxyz".split('');
    for (int i = 0; i < accountMap.length; i++) {
      String binary = i.toRadixString(2).padLeft(5, "0");
      characterTable[binary] = accountMap[i];
      binaryTable[accountMap[i]] = binary;
    }
  }

  String? getBinary(String character) {
    return binaryTable[character];
  }

  String? getCharacter(String binary) {
    return characterTable[binary];
  }

  String decode(String encoded) {
    String decoded = "";
    for (int i = 0; i < encoded.length; i++) {
      decoded += getBinary(encoded[i])!;
    }
    return decoded;
  }

  String encode(String decoded) {
    String encoded = "";
    for (int i = 0; i < decoded.length; i += 5) {
      encoded += getCharacter(decoded.substring(i, i + 5))!;
    }
    return encoded;
  }
}