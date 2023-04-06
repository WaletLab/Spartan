class color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    ITALIC = '\x1B[3m'
    STOP_ITALIC = '\x1B[0m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def find_pattern(pattern, value):
    import re
    x = re.search(pattern, value)
    if x:
        return x
    else:
        return None


