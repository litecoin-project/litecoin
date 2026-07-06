#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <crypto/scrypt.h>

static PyObject* scrypt_getpowhash(PyObject* self, PyObject* args)
{
    const char* input;
    char output[32];
    Py_ssize_t inputlen;

    if (!PyArg_ParseTuple(args, "y#", &input, &inputlen)) return nullptr;
    if (inputlen != 80) return nullptr;
    Py_BEGIN_ALLOW_THREADS;
    scrypt_1024_1_1_256(input, output);
    Py_END_ALLOW_THREADS;
    return Py_BuildValue("y#", output, sizeof(output));
}

static PyMethodDef ScryptMethods[] = {
    {"getPoWHash", scrypt_getpowhash, METH_VARARGS,
     "Returns the proof of work hash using scrypt"},
    {nullptr, nullptr, 0, nullptr}
};

static struct PyModuleDef scryptmodule = {
    PyModuleDef_HEAD_INIT,
    "litecoin_scrypt",
    nullptr,
    -1,
    ScryptMethods
};

PyMODINIT_FUNC PyInit_litecoin_scrypt(void)
{
    return PyModule_Create(&scryptmodule);
}
