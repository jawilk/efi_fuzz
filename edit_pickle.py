import pickle

new_entry = {'FaultType': b'\x05'}


# Open the pickle file for reading
with open('nvram.pickle', 'rb') as file:
    # Load the data from the pickle file
    data = pickle.load(file)

data.update(new_entry)

# Open the pickle file for writing and save the updated data
with open('nvram.pickle', 'wb') as file:
    pickle.dump(data, file)


# Print the loaded data
print(data)
