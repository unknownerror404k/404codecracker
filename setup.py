from setuptools import setup

setup(
    name="code404cracker",
    version="3.1.0",
    author="ERROR 404",
    author_email="unknownerror404k@gmail.com",
    description="404 Code Cracker - CTF Swiss Army Knife with 70+ tools",
    long_description="Auto-detect and decode/encode 40+ encoding types, crack ciphers, "
                     "analyze images for steganography, extract forensic data, generate "
                     "QR codes and barcodes, and more. Dark hacker-themed GUI with 11 tabs.",
    url="https://github.com/unknownerror404k/404codecracker",
    py_modules=["code404cracker"],
    install_requires=[
        "Pillow>=9.0.0",
        "pyzbar>=0.1.9",
        "PyYAML>=6.0",
        "qrcode>=7.0",
        "python-barcode>=0.14.0",
    ],
    entry_points={
        "console_scripts": [
            "404codecracker=code404cracker:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    python_requires=">=3.8",
)
