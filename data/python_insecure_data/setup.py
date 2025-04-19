from setuptools import setup, find_packages

setup(
    name="data-processor",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "pyyaml>=5.4.0",
        "cryptography>=3.4.7",
    ],
    author="Example Author",
    author_email="author@example.com",
    description="A data processing utility",
    keywords="data, processing, analytics",
    url="https://github.com/example/data-processor",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
    ],
    python_requires=">=3.6",
)