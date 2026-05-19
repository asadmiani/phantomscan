from setuptools import setup, find_packages

setup(
    name="phantomscan",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "rich",
        "textual",
        "psutil",
        "requests"
    ],
    entry_points={
        "console_scripts": [
            "phantomscan=phantomscan.main:run"
        ]
    }
)
