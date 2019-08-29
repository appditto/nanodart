import 'package:bip39/bip39.dart' as bip39;
import 'package:bip39/src/wordlists/english.dart' as bip39words;

import 'package:nanodart/src/keys/seeds.dart';

class NanoMnemomics {
  /// Converts a nano seed to a 24-word mnemonic word list
  static List<String> seedToMnemonic(String seed) {
    if (!NanoSeeds.isValidSeed(seed)) {
      throw Exception('Invalid Seed');
    }
    String words = bip39.entropyToMnemonic(seed);
    return words.split(' ');
  }

  /// Convert a 24-word mnemonic word list to a nano seed
  static String mnemonicListToSeed(List<String> words) {
    if (words.length != 24) {
      throw Exception('Expected a 24-word list, got a ${words.length} list');
    }
    return bip39.mnemonicToEntropy(words.join(' ')).toUpperCase();
  }

  /// Validate a mnemonic word list
  static bool validateMnemonic(List<String> words) {
    return bip39.validateMnemonic(words.join(' '));
  }

  /// Validate a specific menmonic word
  static bool isValidWord(String word) {
    return bip39words.WORDLIST.contains(word);
  }
}