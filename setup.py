from setuptools import setup

setup(
    name="log_checker",
    version="0.9",
    packages=["logchecker"],
    url="https://github.com/Lifars/log-checker",
    license="",
    author="Lifars",
    author_email="",
    description="extracts observables from logs and checks them in YETI",
    dependency_links=[
        "git+https://github.com/yeti-platform/pyeti#egg=pyeti",
    ],
    install_requires=[
        "argparse",
        "configparser==4.0.2",
        "pytest",
        "python-evtx",
        "pyeti",
    ],
    entry_points={"console_scripts": ["logchecker=logchecker:main"]},
)
