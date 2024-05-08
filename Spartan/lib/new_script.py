
import os
import importlib


class ScriptExec:
    def __init__(self, name, host, result, path=None):
        self.globals = {"host": host, "result": result}
        self.path = path
        self.name = name

    def find_script_file(self):
        try:
            if self.path:
                script_path = f"{self.path}/{self.name}"
            else:
                script_path = os.path.join(
                    os.path.dirname(__file__), "scripts", self.name)

            spec = importlib.util.spec_from_file_location(
                self.name, script_path)
            return spec
        except FileNotFoundError:
            return False

    def run_exec(self):
        spec = self.find_script_file()
        if spec:
            module = importlib.util.module_from_spec(spec)
            for var_name, var_value in self.globals.items():
                setattr(module, var_name, var_value)
            spec.loader.exec_module(module)


if __name__ == "__main__":
    host = "45.33.32.156"
    result = {}
    s = ScriptExec("test.py", host, result,
                   path="/Users/dannyx/PycharmProjects/Spartan/Spartan/scripts")
    s.run_exec()
