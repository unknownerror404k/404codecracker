from setuptools import setup

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="code404cracker",
    version="1.1.0",
    author="ERROR 404",
    author_email="unknownerror404k@gmail.com",
    description="Auto-detect and decode encoded/encrypted text - CTF Swiss Army Knife",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/unknownerror404k/404codecracker",
    py_modules=["code404cracker"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.10",
    install_requires=[
        "Pillow>=9.0.0",
        "pyzbar>=0.1.9",
        "qrcode>=7.3.1",
    ],
    entry_points={
        "console_scripts": [
            "404codecracker=code404cracker:main",
        ],
    },
)
