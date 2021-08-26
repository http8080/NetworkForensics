import pyshark
import nest_asyncio


def tftp_data():
    opcode = {
        "RRQ": "0001",
        "WRQ": "0002",
        "DATA_Block": "0003",
        "ACK_Block": "0004",
        "ERROR_Block": "0005"
    }

    mode = {
        "Octet": "6f63746574"
    }

    data = ""
    file_name = "str(index.data.data)[4:-14]"
    ACK_list = []

    for index in packet:
        if str(index).find("UDP") != -1:
            try:
                if str(index.data.data)[0:4] == opcode["RRQ"]:
                    print(f"RRQ : {index.data.data}")
                elif str(index.data.data)[0:4] == opcode["WRQ"] and str(index.data.data)[0:4].find(mode["Octet"]):
                    print(f"WRQ [Octet] : {bytes.fromhex(str(index.data.data)[4:-14])}")
                    file_name = bytes.fromhex(str(index.data.data)[4:-14])
                elif str(index.data.data)[0:4] == opcode["DATA_Block"]:
                    print(f"DATA_Block [ {str(index.data.data)[4:8]} ] : {str(index.data.data)[8:]}")
                    data += str(index.data.data)[8:]
                elif str(index.data.data)[0:4] == opcode["ACK_Block"]:
                    print(f"ACK_Block [ {str(index.data.data)[4:8]} ]")
                    ACK_list.append(str(index.data.data)[:8])
                elif str(index.data.data)[0:4] == opcode["ERROR_Block"]:
                    print(f"ERROR_Block [ {index.data.data} ] ")
            
            except:
                pass

    data += str(ACK_list.pop())
    print(file_name)
    print(data)

    with open(f"{file_name}", "wb") as file:
        file.write(bytes.fromhex(data))


packet = pyshark.FileCapture("garbagefile.pcapng")

tftp_data()

packet.close()
packet.eventloop.stop()
