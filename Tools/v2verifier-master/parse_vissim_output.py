import argparse
import re
import os

def writeDataToFiles(vehiclePaths: dict) -> None:
    """Write vehicle paths loaded from PTV Vissim export into V2Verifier config

    Parameters:
        vehiclePaths (dict): dictionary of coordinates keyed on vehicleID

    Returns:
        None

    """

    if not os.getcwd().endswith("v2verifier"):
        print("Error - script must be run from within the",
            "V2Verifier project directory")
        exit()
        
    if not os.path.isdir(os.path.join(os.getcwd(), "coords", "vissim")):
        os.mkdir(os.path.join(os.getcwd(), "coords", "vissim"))

    for vehicle in vehiclePaths:
        try:
            with open(os.path.join(os.getcwd(), "coords", "vissim", 
                ("vissim_" + vehicle)), 'w') as outFile:
                for coordinatePair in vehiclePaths[vehicle]:
                    outFile.write(coordinatePair + "\n")
        except:
            print("Error writing output file")
            exit()
        
def printVehicleInfo(id: str, x: str, y: str, speed: str, angle: str) -> None:
    """Show information about a vehicle
    
    Parameters:
        id (str): vehicle ID number
        x (str): x-coordinate of location
        y (str): y-coordinate of location
        speed (str): speed in kilometers per hour
        angle (str): heading angle in degrees
    
    Returns:
        None

    """
    
    print("Vehicle", id, "is at (", x + "," + y, ") moving at", speed, "km/hr",
        "on bearing", angle)

def parse_file(inFilePath: str) -> dict:
    """Parse a PTV Vissim simulation export file
    
    Parameters:
        inFilePath (str): File path to the PTV Vissim output file

    Returns:
        dict: a dictionary of x,y coordinate lists keyed on vehicleID
    """

    try:
        dataFile = open(inFilePath, 'r', errors="ignore")
    except FileNotFoundError:
        print("Could not find the file \"" + inFilePath + "\". Check the path",
            "and try again")
        exit()
    except:
        print("Error opening", inFilePath + ". Exiting.")
        exit()

    data = dataFile.readlines()
    
    startsWithNumber = re.compile("[0-9].*")

    vehiclePaths = {}

    for line in data:
        if startsWithNumber.match(line):
            # remove the leading time step
            line = (line.split(";", maxsplit=1)[1])
            # split vehicleID off the front from the rest of the data
            vehicleID, vehicleData = line.split(";", maxsplit=1)

            x, y, speed, angle = vehicleData.split(";")

            if vehicleID in vehiclePaths:
                vehiclePaths[vehicleID].append(x + "," + str((-1)*int(y)))
            else:
                vehiclePaths[vehicleID] = [x + "," + str((-1)*int(y))]

    vehiclePaths = dict(sorted(vehiclePaths.items(), key=lambda item: item[0]))

    return vehiclePaths

if __name__=="__main__":
    parser = argparse.ArgumentParser(
        description="Convert PTV Vissim output to V2Verifier format"
        )

    parser.add_argument("infile", help="path to PTV exported .FZP file")
    args = parser.parse_args()

    vehiclePaths = parse_file(args.infile)
    writeDataToFiles(vehiclePaths)
