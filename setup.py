from setuptools import setup, find_packages
setup(
    name="cyberspartan",
    version='v0.1.1',
    description='TCP/IP port scanner written in python',
    long_description="""
CyberSpartan
============

TCP/IP Port Scanner
-------------------

CyberSpartan is a Python-based TCP/IP port scanner designed for network security assessments. It provides a user-friendly interface and powerful scanning capabilities.

Features
--------

- Fast and efficient TCP/IP port scanning.
- Support for custom port ranges.
- Integration with Nmap services for enhanced scanning.

Installation
------------

You can install CyberSpartan using pip:

.. code-block:: bash

    pip install cyberspartan

Usage
-----

To run CyberSpartan, use the following command:

.. code-block:: bash

    cyberspartan

For more details and options, refer to the documentation on GitHub: https://github.org/dannyx-hub/Spartan

License
-------

CyberSpartan is licensed under the GPL-3.0 license.

Author
------

- Name: dannyx-hub
- Email: daro322.dp@gmail.com

Contributing
------------

We welcome contributions! Please fork the repository and submit pull requests.

Bug Reports
-----------

If you encounter any issues or bugs, please report them on GitHub: https://github.org/dannyx-hub/Spartan/issues
""",
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
