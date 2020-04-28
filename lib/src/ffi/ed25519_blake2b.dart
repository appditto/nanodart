import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

class Ed25519Blake2b {
  DynamicLibrary _dylib;

  Ed25519Blake2b() {
      String path = './libed25519_blake2b.so';
      if (Platform.isMacOS) path = './libed25519_blake2b.dylib';
      if (Platform.isWindows) path = r'libed25519_blake2b.dll';

      // Open library
      _dylib = DynamicLibrary.open(path);
  }
}