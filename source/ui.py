import scapy.plist
from PyQt5.QtWidgets import (QMainWindow, QTextEdit, QTreeWidget, QTreeWidgetItem,
                             QTableWidget, QVBoxLayout, QSplitter,
                             QWidget, QToolBar, QPushButton, QComboBox, QFileDialog, )
from PyQt5.QtGui import QIcon

from table import *
from packet import *


# window for the sniffer
class SnifferWindow(QMainWindow):
    startSignal = pyqtSignal(str)
    stopSignal = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.initUI()
        self.populate_interfaces()
        self.packet_parser = PacketParser(PacketTable.header, self.interface_select.currentText())
        self.packet_capturer = PacketCapturer()
        if sys.platform == "win32":  # taskbar icon
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("sniffer")

    def initUI(self):
        self.setWindowTitle('Sniffer    ©️copyright wytili 2023')
        self.setWindowIcon(QIcon('assets/logo.svg'))
        self.setGeometry(300, 300, 1200, 900)
        self.create_central_widget()  # show packets in table

        # note: toolbar has to be created after central widget, so that tools can connect to the table
        self.create_toolbar()  # toolbar below menu

    def create_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)

        # dropdown menu for selecting interface
        self.interface_select = QComboBox()
        self.interface_select.setFixedSize(600, 33)
        self.interface_select.setStyleSheet("QComboBox { font-size: 20px; }")

        # buttons
        self.capture_btn = QPushButton()  # capture button
        self.capture_btn.setToolTip('capture')
        self.capture_btn.setIcon(QIcon('assets/green_play_icon.svg'))
        self.capture_btn.clicked.connect(self.on_capture_click)
        self.stop_btn = QPushButton()  # stop button
        self.stop_btn.setToolTip('stop')
        self.stop_btn.setIcon(QIcon('assets/grey_stop_icon.svg'))
        self.stop_btn.setEnabled(False)  # not enabled until capture starts
        self.stop_btn.clicked.connect(self.on_stop_click)
        self.delete_btn = QPushButton()  # delete button
        self.delete_btn.setToolTip('delete')
        self.delete_btn.setIcon(QIcon('assets/delete_icon.svg'))
        self.export_btn = QPushButton()  # export button
        self.export_btn.setToolTip('export')
        self.export_btn.setIcon(QIcon('assets/export_icon.png'))
        self.export_btn.clicked.connect(self.on_export_click)
        self.import_btn = QPushButton()  # import button
        self.import_btn.setToolTip('import')
        self.import_btn.setIcon(QIcon('assets/import_icon.png'))
        self.import_btn.clicked.connect(self.on_import_click)

        # filter
        self.protocol_select = QComboBox()
        self.protocol_select.setFixedSize(150, 33)
        self.protocol_select.setStyleSheet("QComboBox { font-size: 20px; }")
        self.protocol_select.addItem("All")
        self.protocol_select.addItems(PacketTable.proto_color.keys())  # add protocols to dropdown
        self.protocol_select.currentIndexChanged.connect(self.filter_packets)
        # self.filter_btn = QPushButton()  # filter button
        # self.filter_btn.setToolTip('filter')
        # self.filter_btn.setIcon(QIcon('assets/filter_icon.png'))
        # self.filter_btn.clicked.connect(self.filter_packets)

        # add widgets to toolbar
        toolbar.addWidget(self.interface_select)
        toolbar.addWidget(self.capture_btn)
        toolbar.addWidget(self.stop_btn)
        toolbar.addWidget(self.delete_btn)
        toolbar.addWidget(self.export_btn)
        toolbar.addWidget(self.import_btn)
        toolbar.addWidget(self.protocol_select)
        # toolbar.addWidget(self.filter_btn)

    def create_central_widget(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()

        # table for showing packets
        self.packet_table = QTableWidget()
        self.setupPacketTable()
        self.packet_table.itemClicked.connect(self.on_table_item_click)

        # split into two parts
        self.splitter = QSplitter(Qt.Horizontal)
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderHidden(True)

        self.packet_detail = QTextEdit()
        self.packet_detail.setReadOnly(True)

        # add widgets to splitter
        self.splitter.addWidget(self.tree_widget)
        self.splitter.addWidget(self.packet_detail)

        # add splitter to layout
        layout.addWidget(self.packet_table)
        layout.addWidget(self.splitter)
        central_widget.setLayout(layout)

    def setupPacketTable(self):
        # style for table header
        style_sheet = """
        QHeaderView::section {
            background-color: #f0f0f0; 
            height: 40px;             
            color: #262626;       
            font-weight: bold;
        }
        """
        self.packet_table.setFixedHeight(400)
        self.packet_table.setColumnCount(7)
        self.packet_table.setColumnWidth(0, 80)
        self.packet_table.setColumnWidth(1, 110)
        self.packet_table.setColumnWidth(2, 196)
        self.packet_table.setColumnWidth(3, 196)
        self.packet_table.setColumnWidth(4, 90)
        self.packet_table.setColumnWidth(5, 90)
        self.packet_table.setColumnWidth(6, 410)
        self.packet_table.horizontalHeader().setStyleSheet(style_sheet)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.packet_table.setHorizontalHeaderLabels(
            ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)

    # show packet detail when a row is selected
    def on_table_item_click(self):
        try:
            row = self.packet_table.currentRow()
            packet, treePacket = self.packet_manager.getPacket(row)
            if packet is None or treePacket is None:
                print("No packet or treePacket data available")
                return

            self.tree_widget.clear()
            self.packet_detail.clear()

            for layer, fields in treePacket.items():
                layer_item = QTreeWidgetItem(self.tree_widget, [layer])
                for field, value in fields.items():
                    QTreeWidgetItem(layer_item, [f'{field}:  {value}'])

            self.packet_detail.setText(hexdump(packet, True))

        except Exception as e:
            print(f"Error in on_table_item_click: {e}")

    def setPacketManager(self, packet_manager):
        self.packet_manager = packet_manager
        self.delete_btn.clicked.connect(self.packet_manager.clear)
        self.delete_btn.clicked.connect(self.tree_widget.clear)
        self.delete_btn.clicked.connect(self.packet_detail.clear)
        self.packet_table.itemClicked.connect(self.on_table_item_click)

    # add interfaces to the interface select dropdown
    def populate_interfaces(self):
        ifaces = get_network_ifaces()
        for iface in ifaces:
            self.interface_select.addItem(iface)

    def filter_packets(self):
        selected_protocol = self.protocol_select.currentText()
        self.packet_manager.update_filter_protocol(selected_protocol)

    # click handler for the capture button
    def on_capture_click(self):
        self.packet_manager.clear()
        self.startSignal.emit(self.interface_select.currentText())
        self.capture_btn.setIcon(QIcon('assets/grey_play_icon.svg'))
        self.capture_btn.setEnabled(False)
        self.stop_btn.setIcon(QIcon('assets/red_stop_icon.svg'))
        self.packet_parser.setInterface(self.interface_select.currentText())
        self.stop_btn.setEnabled(True)  # enable stop if capture starts
        self.interface_select.setEnabled(False)  # disable interface select if capturing
        self.export_btn.setEnabled(False)   # disable export if capturing
        self.import_btn.setEnabled(False)  # disable import if capturing

    # click handler for the stop button
    def on_stop_click(self):
        self.stopSignal.emit()
        self.capture_btn.setIcon(QIcon('assets/green_play_icon.svg'))
        self.capture_btn.setEnabled(True)
        self.stop_btn.setIcon(QIcon('assets/grey_stop_icon.svg'))
        self.stop_btn.setEnabled(False)
        self.interface_select.setEnabled(True)
        self.import_btn.setEnabled(True)
        self.export_btn.setEnabled(True)

    def on_export_click(self):
        if not self.packet_manager.packets:
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Save to Pcap File", "", "Pcap (*.pcap)")
        if filename:
            self.save_packets_pcap(filename)

    def on_import_click(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open Pcap File", "", "Pcap (*.pcap)")
        if filename:
            self.load_and_parse_packets(filename)

    def save_packets_pcap(self, filename):
        packets = scapy.plist.PacketList(self.packet_manager.packets)
        wrpcap(filename, packets)

    def load_and_parse_packets(self, filepath):
        try:
            packets = rdpcap(filepath)
            self.packet_manager.clear()
            for packet in packets:
                headerPacket, treePacket = self.packet_parser.parse(packet)
                self.packet_manager.add_file_Packet(packet, headerPacket, treePacket)
        except Exception as e:
            print(f"Error loading and parsing PCAP file: {e}")
            import traceback
            traceback.print_exc()

    def get_packet_parser(self):
        return self.packet_parser
