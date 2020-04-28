import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as p;

// C publickey function - unsigned char* publickey(unsigned char *sk);
typedef publickey_func = Pointer<Uint8> Function(Pointer<Uint8> sk);
typedef Publickey = Pointer<Uint8> Function(Pointer<Uint8> sk);

class Ed25519Blake2b {
  DynamicLibrary _dylib;
  var pubkeyFunc;

  Ed25519Blake2b() {
    String root = p.join(Directory.current.path, "lib", "src", "ffi", "c");
    String path = p.join(root, 'libed25519_blake2b.so');
    if (Platform.isMacOS) path = p.join(root, 'libed25519_blake2b.dylib');
    if (Platform.isWindows) path = p.join(root, 'libed25519_blake2b.dll');

    // Open library
    _dylib = DynamicLibrary.open(path);

    // Publickey
    final pkPointer = _dylib.lookup<NativeFunction<publickey_func>>('dart_publickey');
    pubkeyFunc = pkPointer.asFunction<Publickey>();
  }

  Pointer<Uint8> _bytesToPointer(Uint8List bytes) {
    final length = bytes.lengthInBytes;
    final result = allocate<Uint8>(count: length);

    for (var i = 0; i < length; ++i) {
      result[i] = bytes[i];
    }

    return result;
  }

  Uint8List getPubkey(Uint8List secretKey) {
    final pointer = _bytesToPointer(secretKey);
    Pointer<Uint8> result = pubkeyFunc(pointer);
    free(pointer);
    return result.asTypedList(32);
  }
}