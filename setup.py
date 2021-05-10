from setuptools import setup, find_packages

setup(
    name="cvedb",
    description="Yet another CVE database",
    license="LGPL-3.0-or-later",
    url="https://github.com/trailofbits/cvedb",
    author="Trail of Bits",
    version="0.0.4",
    packages=find_packages(exclude=["test"]),
    python_requires=">=3.6",
    install_requires=[
        "cvss>=2.2",
        # dataclasses were added in Python 3.7, so use this backport for earlier versions of Python
        "dataclasses",
        "python-dateutil>=2.8.1",
        "tqdm>=4.48.0"
    ],
    package_data={
        "cvedb": ["data/*.json.gz", "data/*.meta"]
    },
    extras_require={
        "dev": ["flake8", "pytest", "rstr~=2.2.6", "twine"]
    },
    entry_points={
        "console_scripts": [
            "cvedb = cvedb.__main__:main"
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Utilities"
    ]
)
