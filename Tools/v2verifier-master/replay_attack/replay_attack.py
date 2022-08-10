from ReplayAttacker import ReplayAttacker
import sys
if __name__ == "__main__":

    replayer = ReplayAttacker(int(sys.argv[1]))
    replayer.run()
