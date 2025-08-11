"""
GainForest Archival Pipeline Setup Configuration
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="gainforest-archival-pipeline",
    version="1.0.0",
    author="GainForest Team",
    description="Immutable Proof of Impact Storage System for GainForest Ecocerts",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/gainforest/archival-pipeline",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "gainforest-archive=src.main:cli",
        ],
    },
    include_package_data=True,
)
