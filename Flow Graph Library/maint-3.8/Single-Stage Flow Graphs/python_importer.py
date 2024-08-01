import sys

# Used for importing Python2/Python3 scripts in the Dashboard. Do not delete.
def getPythonArguments(python_module):
    return __import__(python_module).getArguments()

if __name__ == "__main__":
    get_python_module = str(sys.argv[1])
    print(getPythonArguments(get_python_module))
