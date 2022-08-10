import sys

# Used for importing Python3 scripts in the Dashboard. Do not delete.
def getPython3Arguments(python3_module):
    return __import__(python3_module).getArguments()

if __name__ == "__main__":
    get_python3_module = str(sys.argv[1])
    print(getPython3Arguments(get_python3_module))
