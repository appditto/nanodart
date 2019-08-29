import 'dart:typed_data';

import 'package:nanodart/nanodart.dart';

main() {
  // Generating a random seed
  String seed = NanoSeeds.generateSeed(); 
  // Getting private key at index-0 of this seed
  String privateKey = NanoKeys.seedToPrivate(seed, 0);
  // Getting public key from this private key
  String pubKey = NanoKeys.createPublicKey(privateKey);
  // Getting address (nano_, ban_) from this pubkey
  String address = NanoAccounts.createAccount(NanoAccountType.NANO, pubKey);
  // Validating address
  NanoAccounts.isValid(NanoAccountType.NANO, address);

  // Creating a block
  int accountType = NanoAccountType.NANO;
  String account = 'xrb_3igf8hd4sjshoibbbkeitmgkp1o6ug4xads43j6e4gqkj5xk5o83j8ja9php';
  String previous = '0';
  String representative = 'xrb_3p1asma84n8k84joneka776q4egm5wwru3suho9wjsfyuem8j95b3c78nw8j';
  BigInt balance = BigInt.parse('1');
  String link = '1EF0AD02257987B48030CC8D38511D3B2511672F33AF115AD09E18A86A8355A8';
  String calculatedHash = NanoBlocks.computeStateHash(accountType, account, previous, representative, balance, link);
  // Signing a block
  NanoSignatures.signBlock(calculatedHash, privateKey);

  // Encrypting and decrypting a seed
  Uint8List encrypted = NanoCrypt.encrypt(seed, 'thisisastrongpassword');
  // String representation:
  String encryptedSeedHex = NanoHelpers.byteToHex(encrypted);
  // Decrypting (if incorrect password, will throw an exception)
  Uint8List decrypted = NanoCrypt.decrypt(NanoHelpers.hexToBytes(encryptedSeedHex), 'thisisastrongpassword');
}
