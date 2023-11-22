from setuptools import setup, find_packages
print(find_packages())
setup(
    name="cyberspartan",
    version='v0.1.0',
    description='TCP/IP port scanner written in python',
    url="https://github.org/dannyx-hub/Spartan",
    author="dannyx-hub",
    author_email="daro322.dp@gmail.com",
    license=" GPL-3.0 license",
    install_requires=['tabulate', 'art'],
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'lib': ['nmap-services'],
    },
    entry_points={
        'console_scripts': [
            'cyberspartan=Spartan.spartan:app',
        ],
    },

)
