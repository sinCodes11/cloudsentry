"""Setup script for CloudSentry."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="cloudsentry",
    version="1.0.0",
    author="Daniel Gregg Jr",
    author_email="dlgregg11@gmail.com",
    description="OCI Security Posture Monitor - CSPM for Oracle Cloud Infrastructure",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sinCodes11/cloudsentry",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.9",
    install_requires=[
        "oci>=2.120.0",
        "sqlalchemy>=2.0.0",
        "psycopg2-binary>=2.9.9",
        "click>=8.1.0",
        "pyyaml>=6.0.1",
        "python-dotenv>=1.0.0",
        "requests>=2.31.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cloudsentry=main:cli",
        ],
    },
)
