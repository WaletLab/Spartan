[![PyPI Downloads](https://static.pepy.tech/badge/spartan-scan)](https://pepy.tech/projects/spartan-scan)
# Spartan

## What is this project?
Spartan is a versatile and powerful port scanner written in Python. It allows users to quickly and efficiently scan network ports. Spartan was designed so that users can easily write custom scripts to enhance the scanner's capabilities, tailoring it to their specific needs.
## Installation

### Installing from PyPI
You can install Spartan from PyPI:
```sh
pip install spartan-scan
```
### Installing from repository
You can also install Spartan directly from the repository:
1. Clone the repository from GitHub
```
git clone https://github.com/WaletLab/Spartan.git
```
2. Navigate to the project directory
```
cd Spartan
```
3. Install the package using `pip`
```
pip install .
```

## Usage
To use Spartan, simply run the following command in your terminal:
```
# spartan [OPTIONS] COMMAND [ARGS]...
```
> Spartan requires root privileges to perform certain operations. Please run it as root or use `sudo` to ensure it has the necessary permissions. 
### Port scan

#### Available scan modes:
- TCP SYN scan 
```
# spartan syn [ARGS]...
```
- TCP FIN scan 
```
# spartan fin [ARGS]...
```
- TCP NULL scan
```
# spartan null [ARGS]...
```
- TCP XMAS scan
```
# spartan xmas [ARGS]...
```
- UDP scan
```
# spartan udp [ARGS]...
```
#### Examples
Perform a TCP SYN scan on a target host, targeting the most commonly used TCP ports by default.
```
# spartan syn --host 1.2.3.4
```

Perform a UDP scan on a target host, targeting all possible ports.
```
# spartan udp --host 1.2.3.4 --port a
```
> Please note that scanning all possible ports can be extremely time-consuming and may encounter disruptions due to firewalls and other unforeseen circumstances. Please consider these factors when initiating such extensive scans. 

Perform a TCP SYN scan on a target host, targeting only first 1024 ports and setting a custom retry timeout of 2 miliseconds.
```
# spartan syn --host 1.2.3.4 --port 1:1024 --retry-timeout 2
```

Perform a TCP SYN scan on a target host and save results to .csv file.
```
# spartan syn --host 1.2.3.4 --output
```

Perform a UDP scan on a target host without displaying banner.
```
# spartan --basic udp --host 1.2.3.4
```
> Note: --basic flag goes before scan mode!

Spartan is also capable of handling domain names.
```
# spartan syn --host waletlab.com
```

For more details please refer to `--help`
```
# spartan --help
```
```
# spartan <scan mode> --help
```
### Scripts
Spartan provides the flexibility to extend its functionality through custom python scripts. Users can leverage global variables `host` and `result` within their scripts to interact with scan results and customize behavior as needed.
#### Global variables
- `host` - Represents the target host IP address
- **`result`**: Holds the scan results, which is a dictionary where the keys are port numbers (integers) and the values are `PortResult` objects. 
  `PortResult` attributes:
	- **`port`**: Integer representing the port number.
	- **`status`**: String indicating the status of the port (e.g., "OPEN", "CLOSED").
	- **`detail`**: Additional details about the port status.

#### Default scripts
Spartan comes with a set of default scripts out of the box. You can easily list them using the following command:
```
# spartan scripts
```
These default scripts provide useful functionalities and examples that you can leverage directly or use as references when writing your own custom scripts.

#### Using scripts
To use a default script, simply append the `--script` flag followed by the name of the script when executing Spartan:
```
# spartan syn --host 1.2.3.4 --script ssl_info.py
```

To use your own scripts, please follow the `--script` flag with the full path to a script file:
```
# spartan syn --host 1.2.3.4 --script /path/to/your_script.py
```



## Contributing
We welcome contributions from the community! Here’s how you can help:
### Reporting Bugs
If you find a bug, please report it by opening an issue in the [Issues](https://github.com/WaletLab/Spartan/issues) section. Before reporting, please check if the bug has already been reported.
### Suggesting Enhancements
Have a feature request or enhancement idea? Please open an issue with the tag `enhancement`. Be sure to include as much detail as possible.
### Submitting Pull Requests

1. **Fork the Repository**: Click the "Fork" button at the top right of the repository page.
2. **Clone Your Fork** and create a new branch for your changes.
3. **Make Changes** and commit them with clear messages.
4. **Push to Your Fork** and open a pull request.

For detailed instructions, refer to [GitHub's guide on contributing to projects](https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project).
## License
Spartan is licensed under the GPL-3.0 license. See the [LICENSE](https://github.com/WaletLab/Spartan/blob/master/Spartan/LICENSE) file for more details.

## Disclaimer
This tool is intended for **legal and ethical use only**. We do not condone or take any responsibility for any illegal activities carried out with this tool.

## Contact
For any questions or feedback, please open an issue or contact the maintainers at [kontakt\@waletlab.com](mailto:kontakt\@waletlab.com).
