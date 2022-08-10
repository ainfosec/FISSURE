import argparse
import sys

from txrx import Remote, Local

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Run a V2V security experiment using V2Verifier.")
    parser.add_argument("perspective",
                        help="choice of perspective",
                        choices=["local", "remote"]
                        )
    parser.add_argument("-g",
                        "--with-gui",
                        help="enables GUI support for the 'local' perspective. Has no effect for "
                            "remote perspective",
                        action='store_true')
    parser.add_argument("technology",
                        help="choice of DSRC or C-V2X technology stack",
                        choices=["dsrc", "cv2x"])
    parser.add_argument("--device",
                        help="choice of Cohda or SDR for C-V2X",
                        choices=["cohda", "sdr"],
                        required=("cv2x" in sys.argv))

    args = parser.parse_args()    

    if args.perspective == "local":
        if args.with_gui:
            print("Running local perspective with GUI enabled...")
            if args.device == "cohda":
                program = Local.run_local(with_gui=True, tech=args.technology, cohda=True)
            else:
                program = Local.run_local(with_gui=True, tech=args.technology)
        else:
            print("Running local perspective in console mode...")
            if args.device == "cohda":
                program = Local.run_local(tech=args.technology, cohda=True)
            else:
                program = Local.run_local(tech=args.technology)

    elif args.perspective == "remote":
        program = Remote.run_remote()
