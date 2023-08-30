# import random
# import matplotlib.pyplot as plt
# from matplotlib.ticker import MaxNLocator
# from adjustText import adjust_text
# import struct
# import pickle
# from collections import defaultdict
import csv
import binascii
import uuid


def load_csv_file(file_path):
    data_dict = {}  # Dictionary to store GUIDs as keys and names as values

    with open(file_path, 'r', newline='') as csvfile:
        csv_reader = csv.reader(csvfile)
        next(csv_reader)  # Skip the header row (GUID, Name)
        
        for row in csv_reader:
            guid, name = row
            data_dict[guid] = name

    return data_dict

GUIDS = load_csv_file("guids.csv")

NAME_SIZE_IDX = 0x22
DATA_SIZE_IDX = 0x26
NAME_IDX = 0x3A

# function_calls = []
with open('150_open_protocol.bin', 'rb') as file:
    data = file.read()
vars = data.split(b'\xAA\x55')
for var in vars:
    n_size = int.from_bytes(
            var[NAME_SIZE_IDX:NAME_SIZE_IDX+4], byteorder='little')
    d_size = var[DATA_SIZE_IDX:DATA_SIZE_IDX+4]
    name = var[NAME_IDX:NAME_IDX+n_size]
    data = var[NAME_IDX+n_size:]
    try:
        name_dec = name.decode('utf-16')
        if 'OpenProtocol-' in name_dec:
            # print(name_dec)
            # print(data, len(data))
            # name_vals = name_dec.split('-')
            # data_dec = data.decode('utf-8')
            # print(data)
            # print(data_dec)
            # print(type(data))
            # is_after = '1' if len(name_vals[3]) < 3 and name_vals[3][0] == '1' else '0'
            # if 'OFileOpen' in name_dec:
                # is_after = '1'
            reordered_bytes = data[3::-1] + data[5:3:-1] + data[7:5:-1] + data[8:]
    
            # Create a UUID object from the bytes and format it with hyphens
            uuid_format = str(uuid.UUID(bytes=reordered_bytes))

            # print(uuid_format.upper())
            print(GUIDS[uuid_format.upper()], uuid_format.upper())



                    # print(name.decode("utf-16"))
                # print(data_dec)
                # print("-"*50)
                # calls = name_vals[2]
                # print("calls",calls)
                # if int(calls) > 300:
                        # print("HERE")
                        # continue
                # function_calls.append(
                        # (name_vals[1], name_vals[2], data_dec, is_after))
    except:
        pass
    # print(function_calls)
        # )
    # )
