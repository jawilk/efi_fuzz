import uefi_firmware
from uefi_firmware.uefi import FirmwareVolume

# path = "../images/modules/lenovo_sec_disabled_17_06_23_exit_boot_hook_fat_open.rom"
path = "crawler_images/Gigabyte_B450_AORUS_ELITE__rev__1_x_/B450AEF5.rom"
# 2nd is Asrock MouseDriver
mouse_guid = ["2D2E62AA-9ECF-43B7-8219-94E7FC713DFE".lower(), "C7A7030C-C3D8-45EE-BED9-5D9E76762953".lower()]

with open(path, "rb") as fw:
    file_content = fw.read()
    parser = uefi_firmware.AutoParser(file_content)
    if parser.type() == "unknown":
        fvh_index = file_content.find(b"_FVH")
        # if fvh_index < 0:
            # return self._unsupported()
        parser = uefi_firmware.AutoParser(file_content[fvh_index - 40 :])
        # if parser.type() is "unknown":
            # return self._unsupported()
    firmware = parser.parse()
    print(dir(firmware))
    g = "8C8CE578-8A3D-4F1C-9935-896185C32DD3"
    d = None
    for i in firmware.objs:
        # print(dir(i))
        # for j in i.objs:
            # print(j)
        if type(i) is FirmwareVolume:
            for j in i.iterate_objects():
                # for k in j.iterate_objects():
                    # print(k)
                for k in j['_self'].iterate_objects():
                    for l in k['_self'].iterate_objects():
                        print(l['guid'])
                        for m in l['_self'].iterate_objects():
                            print(m['guid'])
                            for n in m['_self'].iterate_objects():
                                print(n['guid'])
                                for o in n['_self'].iterate_objects():
                                    print(o['guid'])
                                    # print(o.keys())
                                    for p in o['_self'].iterate_objects():
                                        print(p['guid'])
                                        for q in p['_self'].iterate_objects():
                                            if q['guid'] in mouse_guid:
                                                for file in q['objects']:
                                                    if file['attrs']['type_name'] == 'PE32 image':
                                                        # print(file)
                                                        # print(dir(file))
                                                        print(dir(file['_self']))
                                                        d = file['_self'].data
                                                    
with open('image.efi', "wb") as f:
    f.write(d)
