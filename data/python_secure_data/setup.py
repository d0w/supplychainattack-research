from setuptools import setup, find_packages

setup(
    name="data-processor",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",  # Updated to latest version
        "pyyaml>=6.0.1",     # Updated to latest version
        "cryptography>=42.0.2",  # Updated to latest version
    ],
    author="Example Author",
    author_email="author@example.com",
    description="A secure data processing utility",
    keywords="data, processing, analytics, security",
    url="https://github.com/example/data-processor",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
)