import time
from PyQt5.QtWidgets import QTableWidgetItem
from PyQt5 import QtGui
from PyQt5.QtCore import Qt


# show table to user
class PacketTable:
    header = ["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
    proto_color = {"Ethernet": "#ffcdd2", "IP": "#e1bee7", "TCP": "#bbdefb", "UDP": "#b2dfdb", "ARP": "#f0f4c3",
                   "ICMP": "#d7ccc8", "DNS": "#cfd8dc", "HTTP": "#d1c4e9", "IPv6": "#f8bbd0"}

    def __init__(self, tableWidget):
        self.tableWidget = tableWidget
        self.packets = []
        self.headerPackets = []
        self.treePackets = []
        self.current_filter_protocol = "All"

    def add_real_time_Packet(self, packet, headerPacket, treePacket):
        protocol = headerPacket[4]

        # filter packets
        if self.current_filter_protocol != "All" and protocol != self.current_filter_protocol:
            return  # do not add this packet

        rowPosition = self.tableWidget.rowCount()
        self.tableWidget.insertRow(rowPosition)
        self.tableWidget.setRowHeight(rowPosition, 40)

        # update headerPacket list to dictionary
        headerPacketDict = dict(zip(PacketTable.header, headerPacket))

        # update values
        headerPacketDict["No"] = rowPosition + 1
        headerPacketDict["Time"] = time.strftime("%H:%M:%S", time.localtime(packet.time))
        headerPacketDict["Length"] = len(packet)

        color = self.proto_color.get(protocol, "#FFFFFF")

        # add data to table
        for col, key in enumerate(PacketTable.header):
            value = headerPacketDict.get(key, "")
            item = QTableWidgetItem(str(value))
            item.setTextAlignment(Qt.AlignCenter)
            item.setBackground(QtGui.QColor(color))
            self.tableWidget.setItem(rowPosition, col, item)

        self.packets.append(packet)
        self.headerPackets.append(headerPacketDict)  # Store as a dictionary
        self.treePackets.append(treePacket)

    def add_file_Packet(self, packet, headerPacket, treePacket):
        rowPosition = self.tableWidget.rowCount()
        self.tableWidget.insertRow(rowPosition)
        self.tableWidget.setRowHeight(rowPosition, 40)

        # real time packet is a dict
        headerPacket["No"] = rowPosition + 1
        headerPacket["Time"] = time.strftime("%H:%M:%S", time.localtime(packet.time))
        headerPacket["Length"] = len(packet)

        protocol = headerPacket.get("Protocol", "")
        color = self.proto_color.get(protocol, "#FFFFFF")

        for col, key in enumerate(PacketTable.header):
            value = headerPacket.get(key, "")
            item = QTableWidgetItem(str(value))
            item.setTextAlignment(Qt.AlignCenter)
            item.setBackground(QtGui.QColor(color))
            self.tableWidget.setItem(rowPosition, col, item)

        self.packets.append(packet)
        self.headerPackets.append(headerPacket)
        self.treePackets.append(treePacket)

    def clear(self):
        self.packets.clear()
        self.headerPackets.clear()
        self.treePackets.clear()
        self.tableWidget.setRowCount(0)

    def getPacket(self, index):
        try:
            packet = self.packets[index]
            treePacket = self.treePackets[index]
            return packet, treePacket
        except Exception as e:
            print(f"Error in getPacket at index {index}: {e}")
            return None, None

    def filter_packets(self):
        for row in range(self.tableWidget.rowCount()):
            protocol = self.headerPackets[row].get("Protocol", "")
            if self.current_filter_protocol == "All" or protocol == self.current_filter_protocol:
                self.tableWidget.showRow(row)
            else:
                self.tableWidget.hideRow(row)

    def update_filter_protocol(self, protocol):
        self.current_filter_protocol = protocol
        self.filter_packets()