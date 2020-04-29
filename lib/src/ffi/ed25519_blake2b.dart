import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as p;

import '../../nanodart.dart';

// C publickey function - unsigned char* dart_publickey(unsigned char *sk, unsigned char *pk);
typedef publickey_func = Void Function(Pointer<Uint8> sk, Pointer<Uint8> pk);
typedef Publickey = void Function(Pointer<Uint8> sk, Pointer<Uint8> pk);

// C privatekey function - unsigned char* dart_privatekey(unsigned char *sk, unsigned char *seed, int index);
typedef privatekey_func = Pointer<Uint8> Function(Pointer<Uint8> sk, Pointer<Uint8> seed, Uint32 index);
typedef Privatekey = Pointer<Uint8> Function(Pointer<Uint8> sk, Pointer<Uint8> seed, int index);

class Ed25519Blake2b {
  DynamicLibrary _dylib;
  var pubkeyFunc;
  var privkeyFunc;

  Ed25519Blake2b() {
    String root = p.join(Directory.current.path, "lib", "src", "ffi", "c");
    String path = p.join(root, 'libed25519_blake2b.so');
    if (Platform.isMacOS) path = p.join(root, 'libed25519_blake2b.dylib');
    if (Platform.isWindows) path = p.join(root, 'libed25519_blake2b.dll');

    // Open library
    _dylib = DynamicLibrary.open(path);

    // Publickey
    final pubkeyPointer = _dylib.lookup<NativeFunction<publickey_func>>('dart_publickey');
    pubkeyFunc = pubkeyPointer.asFunction<Publickey>();
    // Privatekey
    final privkeyPointer = _dylib.lookup<NativeFunction<privatekey_func>>('dart_privatekey');
    privkeyFunc = privkeyPointer.asFunction<Privatekey>();
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
    final result = allocate<Uint8>(count: 32);
    pubkeyFunc(pointer, result);
    free(pointer);
    return result.asTypedList(32);
  }

  Uint8List derivePrivkey(Uint8List seed, int index) {
    final seedPointer = _bytesToPointer(seed);
    final result = allocate<Uint8>(count: 32);
    privkeyFunc(result, seedPointer, index);
    free(seedPointer);
    return result.asTypedList(32);    
  }
}