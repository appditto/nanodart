#include "ed25519-donna/ed25519.h"

ed25519_public_key* dart_publickey(unsigned char* sk) {
  static ed25519_public_key pk;

  ed25519_publickey(sk, pk);
  return &pk;
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