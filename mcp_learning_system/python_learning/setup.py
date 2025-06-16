"""
Setup configuration for MCP Learning System Python package
"""
from setuptools import setup, find_packages
from setuptools_rust import Binding, RustExtension

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mcp-learning",
    version="1.0.0",
    author="MCP Development Team",
    author_email="mcp@example.com",
    description="Machine Learning Integration Layer for MCP System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mcp/learning-system",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Rust",
    ],
    python_requires=">=3.8",
    install_requires=[
        "numpy>=1.21.0",
        "scikit-learn>=1.0.0",
        "torch>=2.0.0",
        "pandas>=1.3.0",
        "msgpack>=1.0.0",
        "asyncio>=3.4.3",
        "aiofiles>=0.8.0",
        "prometheus-client>=0.12.0",
        "structlog>=21.5.0",
        "tenacity>=8.0.0",
        "pyarrow>=6.0.0",
        "fastapi>=0.68.0",
        "uvloop>=0.16.0",
        "redis>=4.0.0",
        "aiokafka>=0.7.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-asyncio>=0.18.0",
            "pytest-cov>=3.0.0",
            "black>=21.0",
            "flake8>=4.0.0",
            "mypy>=0.910",
            "isort>=5.9.0",
        ],
        "ml": [
            "tensorflow>=2.10.0",
            "lightgbm>=3.3.0",
            "xgboost>=1.7.0",
            "statsmodels>=0.13.0",
        ],
    },
    rust_extensions=[
        RustExtension(
            "mcp_learning.rust_core",
            binding=Binding.PyO3,
            path="../rust_core/Cargo.toml",
        ),
    ],
    zip_safe=False,
    include_package_data=True,
    package_data={
        "mcp_learning": ["py.typed"],
    },
)