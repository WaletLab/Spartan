from setuptools import setup, find_packages

setup(
    name="Spartan",
    version='v0.0.4',
    description='TCP/IP port scanner written in python',
    url="https://github.org/dannyx-hub/Spartan",
    author="dannyx-hub",
    author_email="daro322.dp@gmail.com",
    license=" GPL-3.0 license",
    install_requires=['tabulate','art'],
    packages=find_packages(),
    entry_points={
    'console_scripts': [
        'spartan=Spartan.main:app',
    ],
},

)