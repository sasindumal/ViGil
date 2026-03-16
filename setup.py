"""
UIR Package Setup
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="uir",
    version="0.1.0",
    author="ViGiL Project",
    description="Unified Instruction Representation for Heterogeneous Malware Analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "pefile>=2023.2.7",
        "python-magic-bin>=0.4.14",
        "py7zr>=0.20.8",
        "rarfile>=4.1",
        "pycdlib>=1.14.0",
        "oletools>=0.60.1",
        "torch>=2.0.0",
        "networkx>=3.0",
        "tqdm>=4.65.0",
        "pydantic>=2.0.0",
        "numpy>=1.24.0",
        "scikit-learn>=1.3.0",
        "pylnk3>=0.4.2",
    ],
    extras_require={
        "gpu": ["torch-geometric>=2.4.0", "orjson>=3.9.0"],
        "m4": ["msgpack>=1.0.5", "orjson>=3.9.0"],
        "fast": ["orjson>=3.9.0", "msgpack>=1.0.5"],
        "dev": ["pytest", "black", "flake8"],
    },
    entry_points={
        "console_scripts": [
            "uir=uir.pipeline.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
