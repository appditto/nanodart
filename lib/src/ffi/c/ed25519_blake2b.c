#include "ed25519-donna/ed25519.h"
#include "ed25519-donna/blake2b.h"

void dart_privatekey(ed25519_secret_key sk, unsigned char* seed, uint32_t index) {
  blake2b_state b2b;

  // Convert index into a 4-character byte array
  unsigned char indexBytes[4];
  indexBytes[0] = (index >> 24) & 0xFF;
  indexBytes[1] = (index >> 16) & 0xFF;
  indexBytes[2] = (index >> 8) & 0xFF;
  indexBytes[3] = index & 0xFF;

  blake2b_Init(&b2b, 32);
  blake2b_Update(&b2b, seed, sizeof(seed));
  blake2b_Update(&b2b, indexBytes, sizeof(indexBytes));
  blake2b_Final(&b2b, sk, 32);
}

void dart_publickey(unsigned char* sk, ed25519_public_key pk) {
  ed25519_publickey(sk, pk);
}

/*
static PyObject *signature(PyObject *self, PyObject *args) {
  const unsigned char *m, *randr, *sk, *pk;
  int i, j, k, l;
  ed25519_signature sig;

  if (!PyArg_ParseTuple(args, "y#y#y#y#", &m, &i, &randr, &j, &sk, &k, &pk, &l))
    return NULL;
  ed25519_sign(m, i, randr, sk, pk, sig);
  return Py_BuildValue("y#", &sig, 64);
}

static PyObject *checkvalid(PyObject *self, PyObject *args) {
  const unsigned char *sig, *m, *pk;
  int i, j, k;

  if (!PyArg_ParseTuple(args, "y#y#y#", &sig, &i, &m, &j, &pk, &k)) return NULL;
  return Py_BuildValue("i", ed25519_sign_open(m, j, pk, sig));
}*/