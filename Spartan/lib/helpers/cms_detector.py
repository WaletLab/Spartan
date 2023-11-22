import re


class detector:

    def __init__(self, response):
        self.response = response
        self.data = {}

    def check_wordpress(self):
        if b'wp-content' in self.response:
            print("sprawdzam wordpressa")
            self.data['wordpress'] = True
            pattern = r'\/wp-content\/plugins\/([^/]+)'
            plugins = re.findall(pattern, self.response.decode())
            self.data['plugins'] = plugins

    def check_joomla(self):
        if "joomla" in self.response.decode():
            self.data['joomla'] = True
            plugin_pattern = r'<h4 class="plugindesc-headline">(.+?)</h4>'
            plugins = re.findall(plugin_pattern, self.response.decode())
            self.data['plugins'] = plugins

    def run(self):
        self.check_wordpress()
        self.check_joomla()
        return self.data
