
from io import StringIO
import sys
import traceback

class ScriptExecute():
    def __init__(self,path,host=None,result=None):
        self.path = path
        self.result = result
        self.host = host
    def execute(self):
        try:
            with open(self.path, "r") as scriptfile:
                lines = scriptfile.read()
                locals = {"result":self.result,
                          "host": self.host}
                stream = StringIO()
                sys.stdout = stream
                compiled_code = compile(lines, '<string>', 'exec')
                sys.stdout = sys.__stdout__
                exec(compiled_code, locals)
                output = stream.getvalue()
                return output
        except Exception:
            print(traceback.format_exc())
