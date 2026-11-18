from setuptools import setup, find_packages

setup(
    name="slop-sentinel",
    version="1.0.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "antislop=antislop.cli:main",
            "slop-sentinel=antislop.cli:main",
        ],
    },
)
