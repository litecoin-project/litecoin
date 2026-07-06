from setuptools import Extension, setup

setup(
    ext_modules=[
        Extension(
            name="litecoin_scrypt",
            sources=["scryptmodule.cpp", "../../../src/crypto/scrypt.cpp"],
            include_dirs=["../../../src", "/opt/homebrew/include"],
            library_dirs=["/opt/homebrew/lib"],
            libraries=["crypto"]
        )
    ]
)
