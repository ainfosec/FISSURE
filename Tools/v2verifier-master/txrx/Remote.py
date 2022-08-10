import yaml

from multiprocessing import Process
from vehicle.RemoteVehicle import RemoteVehicle


def run_remote():

    with open("init.yml", "r") as confFile:
        config = yaml.load(confFile, Loader=yaml.FullLoader)

    remote_vehicles = []

    # prepare the message queues for all vehicles
    try:
        for i in range(0, config["remoteConfig"]["numberOfVehicles"]):
            rv = RemoteVehicle(config["remoteConfig"]["traceFiles"][i], i)
            remote_vehicles.append(rv)

    except IndexError:
        print("Error starting vehicles. Ensure you have entered enough trace files and BSM file paths "
              "in \"init.yml\" to match the number of vehicles specified in that file.")

    # list to hold all spawned processes
    vehicle_processes = []

    # start transmitting packets for all legitimate vehicles
    for rv in remote_vehicles:
        vehicle = Process(target=rv.start)
        vehicle_processes.append(vehicle)
        vehicle.start()
        print("Started legitimate vehicle")

    for vehicle in vehicle_processes:
        vehicle.join()
