import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QThread
from ui import SnifferWindow
from table import PacketTable
from packet import PacketCapturer

# the entry point of the program
def main():
    app = QApplication(sys.argv)
    sniffer_window = SnifferWindow()

    # instantiate the capturer, parser and packet table
    capturer = PacketCapturer()
    parser = sniffer_window.get_packet_parser()
    packet_table = PacketTable(sniffer_window.packet_table)
    sniffer_window.setPacketManager(packet_table)  # send the packet table to the sniffer window

    # create a thread for capturer
    capture_thread = QThread()
    capture_thread.start()
    capturer.moveToThread(capture_thread)
    capturer.captureSignal.connect(parser.handle)  # parse the packet after capture
    parser.parseSignal.connect(packet_table.add_real_time_Packet)  # update the packet table after parse

    # connect to two buttons
    sniffer_window.startSignal.connect(capturer.start)
    sniffer_window.stopSignal.connect(capturer.stop)

    sniffer_window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
