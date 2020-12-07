from setuptools import setup

setup(
    name="log_checker",
    version="0.0.1",
    packages=["logchecker"],
    url="https://github.com/Lifars/log-checker",
    license="",
    author="Lifars",
    author_email="",
    description="extracts observables from logs and checks them in YETI",
    install_requires=[
        "argparse",
        "configparser",
        "python-evtx",
    ],
    entry_points={
            'console_scripts': ['logchecker=logchecker.__main__:main']
        },
)
