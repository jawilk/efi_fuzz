import random
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from adjustText import adjust_text
# import struct
# import pickle
from collections import defaultdict

NAME_SIZE_IDX = 0x22
DATA_SIZE_IDX = 0x26
NAME_IDX = 0x3A

function_calls = []
with open('nvram_dump_uefitool_3.bin', 'rb') as file:
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
        if 'Fat' in name_dec:
            if 'OFileOpen' in name_dec:
                continue
            name_vals = name_dec.split('-')
            is_after = '1' if len(name_vals[3]) < 3 and name_vals[3][0] == '1' else '0'
            # if 'OFileOpen' in name_dec:
                # is_after = '1'

            data_dec = data.decode('utf-16')

            if 'DriverBindingStart' in name_dec or 'FatEntryPoint' in name_dec or 'FatOpenVolume' in name_dec or 'DriverBindingStop' in name_dec:
                data_dec = ''
            # print(name.decode("utf-16"))
            # print(data_dec)
            # print("-"*50)
            function_calls.append(
                (name_vals[1], name_vals[2], data_dec, is_after))
    except:
        pass
print(function_calls)

# nodes = []
# with open("nvram.pickle", 'r') as file:
#     nvram_vars = pickle.load(file)
#     for var in nvram_vars:
#         name = None
#         is_after_boot_service_exit = struct.unpack('?', file.read(1))[0]
#         call_count = struct.unpack('Q', file.read(8))[0]
#         input = None
#         nodes.append((name, is_after_boot_service_exit, call_count, input))

# Function call data with timestamps and file paths
# function_calls = [
#     ("FatOpenEx", 1, "EFI/UBUNTU", False),
#     ("FatOpenEx", 2, "EFI/UBUNTU", False),
#     ("FatOpenEx", 3, "EFI/UBUNTU", False),
#     ("FatOpenEx", 4, "EFI/UBUNTU", True),
#     ("FatOpenEx", 5, "EFI/UBUNTU", True),
#     ("FatOpenEx", 6, "EFI/UBUNTU", True),
#     ("FatOpenEx", 7, "EFI/UBUNTU", True),
#     ("functionB", 2, "EFI/UBUNTU", False),
#     ("functionC", 1, "EFI/UBUNTU", False),
#     ("functionD", 1, "EFI/UBUNTU", True),
#     ("functionA", 4, "EFI/UBUNTU", True),
# ]

function_groups = defaultdict(list)
for name, call_count, input, is_exit in function_calls:
    function_groups[name].append((call_count, input, is_exit))

sorted_function_groups = sorted(
    function_groups.items(), key=lambda x: min([c for c, _, _ in x[1]]))

function_y_coordinates = {function_name: i for i,
                          (function_name, _) in enumerate(sorted_function_groups)}

# Extract function names, timestamps, and IsExit values for plotting
function_names = []
call_counts = []
inputs = []
# is_exit_values = []
point_colors = []
for name, group in sorted_function_groups:
    for call_count, input, is_exit in group:
        function_names.append(name)
        call_counts.append(call_count)
        inputs.append(input)
        # is_exit_values.append(is_exit)
        point_colors.append('red' if is_exit == '1' else 'blue')


# Create a scatter plot of function calls over time
plt.scatter(call_counts, [function_y_coordinates[name] for name in function_names],
            c=point_colors, marker='o', s=10)
for x, y, input in zip(call_counts, [function_y_coordinates[name] for name in function_names], inputs):
    offset = random.choice([x for x in range(-30, 31) if x < -10 or x > 5])
    plt.annotate(input, xy=(x, y), xytext=(0, offset), textcoords='offset points', fontsize=8)


plt.yticks(range(len(sorted_function_groups)), [name for name, _ in sorted_function_groups])
plt.xlabel("Number of Calls")
# plt.ylabel("Function Name")
plt.title("Function Calls Timeline")
plt.grid(True)
ax = plt.gca()
ax.xaxis.set_major_locator(MaxNLocator(integer=True))

legend_elements = [
    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='blue', markersize=10, label='Before ExitBootServices'),
    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=10, label='After ExitBootServices'),
]
plt.legend(handles=legend_elements)

# Add colorbar to represent IsExit values
# cbar = plt.colorbar()
# cbar.set_label("IsExit")

# Show the plot
plt.show()