from scapy.utils import RawPcapReader
from scapy.all import PcapReader, Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import scapy.contrib.modbus as mb
from scapy.fields import (
    ConditionalField,
    Emph,
)
from scapy.config import conf, _version_checker
from scapy.base_classes import BasePacket, Gen, SetGen, Packet_metaclass

import pprint
import pandas as pd
import os

import requests
from pathlib import Path
from zipfile import ZipFile
import json
from tqdm import tqdm
import scapy
import py7zr

# todo finish this with namelist walk to find pcaps

from utils import get_all_data, get_training_data

data_dir = Path("datasets")
data_files = {
        1: {"filename": "capture1_v2.zip", "url": "https://github.com/tjcruz-dei/ICS_PCAPS/releases/download/MODBUSTCP%231/captures1_v2.zip", "sizeMB":639},
        2: {"filename": "capture2.zip", "url": "https://github.com/tjcruz-dei/ICS_PCAPS/releases/download/MODBUSTCP%231/captures2.zip", "sizeMB": 186},
        3: {"filename": "capture3.zip", "url": "https://github.com/tjcruz-dei/ICS_PCAPS/releases/download/MODBUSTCP%231/captures3.zip", "sizeMB": 214},
}

def download(url, outfile, dataset_number=1):
    response = requests.get(url, stream=True)
    if (response.status_code != 200):
        raise Exception("Error downloading data - status code: {}, url: {}".format(response.status_code, url))
    total_size = int(response.headers["Content-Length"])
    downloaded = 0  # keep track of size downloaded so far
    chunkSize = 1024
    bars = total_size // chunkSize
    with open(outfile, "wb") as f:
        for chunk in tqdm(response.iter_content(chunk_size=chunkSize), total=bars, unit="KB",
                          desc="Dataset {}/3".format(dataset_number), leave=True):
            f.write(chunk)
            downloaded += chunkSize

for dataset_number, values in data_files.items():
    download(values["url"], values["filename"], dataset_number=dataset_number)

raise Exception

def unzip(zipfilename, outfolder):
    archive = py7zr.SevenZipFile(zipfilename, mode='r')
    archive.extractall(path="/outfolder/")
    archive.close()

# def get_dataset(dataset_number=1):
#     if not data_dir.exists():
#         data_dir.mkdir()
#
#     if (data_dir / data_files[dataset_number]["filename"]).exists():
#         raise NotImplementedError
#     else:
#         archive_file = data_dir / data_files[dataset_number]["filename"].replace("pcap", "zip")
#         # download
#         if not archive_file.exists():
#             # todo check hash
#             download(data_files[dataset_number]["url"], archive_file, dataset_number)
#         # # unzip
#         # archive = ZipFile(archive_file, "r")
#         # print(archive.namelist())
#         # #pcap_data = archive.open(archive.namelist())
#         # print(pcap_data)
#         # raise Exception

#download("http://www.ece.uah.edu/~thm0009/icsdatasets/multiclass.7z", "power3class.7z")

# ['captures1_v2/', '__MACOSX/._captures1_v2', 'captures1_v2/modbusQuery2Flooding/', '__MACOSX/captures1_v2/._modbusQuery2Flooding', 'captures1_v2/.DS_Store', '__MACOSX/captures1_v2/._.DS_Store', 'captures1_v2/modbusQueryFlooding/', '__MACOSX/captures1_v2/._modbusQueryFlooding', 'captures1_v2/mitm/', '__MACOSX/captures1_v2/._mitm', 'captures1_v2/tcpSYNFloodDDoS/', '__MACOSX/captures1_v2/._tcpSYNFloodDDoS', 'captures1_v2/clean/', '__MACOSX/captures1_v2/._clean', 'captures1_v2/pingFloodDDoS/', '__MACOSX/captures1_v2/._pingFloodDDoS', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding1m-1h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding1m-1h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding5m-6h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding5m-6h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding5m-0,5h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding5m-0,5h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding30m-6h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding30m-6h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding-1m-12h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding-1m-12h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding-30m-12h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding-30m-12h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding15m-1h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding15m-1h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding30m-1h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding30m-1h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding5m-1h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding5m-1h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding1m-6h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding1m-6h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding-15m-12h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding-15m-12h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding15m-0,5h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding15m-0,5h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding1m-0,5h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding1m-0,5h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding15m-6h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding15m-6h_1.pcap', 'captures1_v2/modbusQuery2Flooding/eth2dump-modbusQuery2Flooding-5m-12h_1.pcap', '__MACOSX/captures1_v2/modbusQuery2Flooding/._eth2dump-modbusQuery2Flooding-5m-12h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding15m-1h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding15m-1h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding5m-6h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding5m-6h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding1m-1h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding1m-1h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding1m-0,5h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding1m-0,5h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding30m-6h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding30m-6h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding-30m-12h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding-30m-12h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding-5m-12h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding-5m-12h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding5m-0,5h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding5m-0,5h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding15m-6h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding15m-6h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding1m-6h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding1m-6h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding5m-1h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding5m-1h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding-15m-12h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding-15m-12h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding15m-0,5h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding15m-0,5h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding30m-1h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding30m-1h_1.pcap', 'captures1_v2/modbusQueryFlooding/eth2dump-modbusQueryFlooding-1m-12h_1.pcap', '__MACOSX/captures1_v2/modbusQueryFlooding/._eth2dump-modbusQueryFlooding-1m-12h_1.pcap', 'captures1_v2/mitm/eth2dump-mitm-change-15m-1h_1.pcap', '__MACOSX/captures1_v2/mitm/._eth2dump-mitm-change-15m-1h_1.pcap', 'captures1_v2/mitm/.DS_Store', '__MACOSX/captures1_v2/mitm/._.DS_Store', 'captures1_v2/mitm/eth2dump-mitm-change-1m-1h_1.pcap', '__MACOSX/captures1_v2/mitm/._eth2dump-mitm-change-1m-1h_1.pcap', 'captures1_v2/mitm/eth2dump-mitm-change-5m-6h_1.pcap', '__MACOSX/captures1_v2/mitm/._eth2dump-mitm-change-5m-6h_1.pcap', 'captures1_v2/mitm/eth2dump-mitm-change-1m-0,5h_1.pcap', '__MACOSX/captures1_v2/mitm/._eth2dump-mitm-change-1m-0,5h_1.pcap', 'captures1_v2/mitm/eth2dump-mitm-change-30m-6h_1.pcap', '__MACOSX/captures1_v2/mitm/._eth2dump-mitm-change-30m-6h_1.pcap', 'captures1_v2/mitm/eth2dump-mitm-change-15m-6h_1.pcap', '__MACOSX/captures1_v2/mitm/._eth2dump-mitm-change-15m-6h_1.pcap', 'captures1_v2/mitm/eth2dump-mitm-change-5m-0,5h_1.pcap', '__MACOSX/captures1_v2/mitm/._eth2dump-mitm-change-5m-0,5h_1.pcap', 'captures1_v2/mitm/eth2dump-mitm-change-5m-1h_1.pcap', '__MACOSX/captures1_v2/mitm/._eth2dump-mitm-change-5m-1h_1.pcap', 'captures1_v2/mitm/eth2dump-mitm-change-1m-6h_1.pcap', '__MACOSX/captures1_v2/mitm/._eth2dump-mitm-change-1m-6h_1.pcap', 'captures1_v2/mitm/eth2dump-mitm-change-30m-1h_1.pcap', '__MACOSX/captures1_v2/mitm/._eth2dump-mitm-change-30m-1h_1.pcap', 'captures1_v2/mitm/eth2dump-mitm-change-15m-0,5h_1.pcap', '__MACOSX/captures1_v2/mitm/._eth2dump-mitm-change-15m-0,5h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-6h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS15m-6h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS1m-0,5h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS1m-0,5h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS5m-6h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS5m-6h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS1m-1h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS1m-1h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-5m-12h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS-5m-12h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-0,5h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS15m-0,5h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-15m-12h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS-15m-12h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS30m-1h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS30m-1h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS1m-6h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS1m-6h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS5m-1h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS5m-1h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-30m-12h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS-30m-12h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS15m-1h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS15m-1h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS-1m-12h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS-1m-12h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS5m-0,5h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS5m-0,5h_1.pcap', 'captures1_v2/tcpSYNFloodDDoS/eth2dump-tcpSYNFloodDDoS30m-6h_1.pcap', '__MACOSX/captures1_v2/tcpSYNFloodDDoS/._eth2dump-tcpSYNFloodDDoS30m-6h_1.pcap', 'captures1_v2/clean/eth2dump-clean-6h_1.pcap', '__MACOSX/captures1_v2/clean/._eth2dump-clean-6h_1.pcap', 'captures1_v2/clean/eth2dump-clean-0,5h_1.pcap', '__MACOSX/captures1_v2/clean/._eth2dump-clean-0,5h_1.pcap', 'captures1_v2/clean/eth2dump-clean-1h_1.pcap', '__MACOSX/captures1_v2/clean/._eth2dump-clean-1h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS5m-0,5h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS5m-0,5h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS30m-6h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS30m-6h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS15m-0,5h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS15m-0,5h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS5m-6h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS5m-6h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS1m-1h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS1m-1h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS15m-1h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS15m-1h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS-1m-12h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS-1m-12h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS-15m-12h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS-15m-12h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS30m-1h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS30m-1h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS-30m-12h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS-30m-12h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS1m-6h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS1m-6h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS5m-1h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS5m-1h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS1m-0,5h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS1m-0,5h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS15m-6h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS15m-6h_1.pcap', 'captures1_v2/pingFloodDDoS/eth2dump-pingFloodDDoS-5m-12h_1.pcap', '__MACOSX/captures1_v2/pingFloodDDoS/._eth2dump-pingFloodDDoS-5m-12h_1.pcap']


class Model():
    def __init__(self, config):
        self.call_model = config["algorithm"]
        self.name = config["model_name"]
        self.features = config["features"]
        self.problem = config["problem"]


    def prep_data(self, data):
        x = data[self.features]
        if self.problem == "anomaly":
            y = x
        else:
            y = data["malicious"]
        return x, y

    def train(self, data):
        x, y = self.prep_data(data)
        ## todo anomaly choose threshold


def pkt_as_dict(pkt, indent=3, lvl="",
                      label_lvl="",
                      first_call=True):
    # based on scapy show() method
    # returns: dict of pkt attributes normally printed by show()
    if first_call is True:
        ret = {}
    else:
        ret = first_call

    # ret = "%s%s %s %s \n" % (label_lvl,
    #                        ct.punct("###["),
    #                        ct.layer_name(self.name),
    #                        ct.punct("]###"))
    for f in pkt.fields_desc:
        if isinstance(f, ConditionalField) and not f._evalcond(pkt):
            continue

        fvalue = pkt.getfieldval(f.name)
        if isinstance(fvalue, Packet) or (f.islist and f.holds_packets and isinstance(fvalue, list)):  # noqa: E501
            key = "{}_{}".format(label_lvl + lvl, f.name)
            fvalue_gen = SetGen(
                fvalue,
                _iterpacket=0
            )  # type: SetGen[Packet]
            for fvalue in fvalue_gen:
                ret[key] = pkt_as_dict(fvalue, indent=indent, label_lvl=label_lvl + lvl + "   |",
                                          first_call=ret)  # noqa: E501
        else:
            key = "{}_{}_{}".format(pkt.name, label_lvl + lvl, f.name)
            if isinstance(fvalue, str):
                fvalue = fvalue.replace("\n", "\n" + " " * (len(label_lvl) +  # noqa: E501
                                                              len(lvl) +
                                                              len(f.name) +
                                                              4))
            ret[key] = fvalue
    if pkt.payload:
        pkt_as_dict(pkt.payload,
            indent=indent,
            lvl=lvl,# + (" " * indent * pkt.show_indent),
            label_lvl=label_lvl,
            first_call=ret
        )

    return ret

from sklearn.ensemble import RandomForestClassifier


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))
    count = 0
    df = []
    #for pkt, (pkt_data, pkt_metadata,) in zip(PcapReader(file_name),RawPcapReader(file_name)):
    for pkt in PcapReader(file_name):
        data = pkt_as_dict(pkt)
        data["bytes"] = str(pkt)

        count += 1
        df.append(data)
    df = pd.DataFrame(df)
    df["attack_type"] = file_name.split("/")[-2]
    df["filename"] = file_name.split("/")[-1]
    df["capturename"] = file_name.split("/")[-3]
    df.to_csv("datasets/{}".format("_".join(file_name.split("/")[1:])).replace("pcap", "csv"), index=False)
    print('{} contains {} packets'.format(file_name, count))


# for cap in os.listdir("datasets"):
#     if "." in cap:
#         continue
#     for folder in os.listdir(os.path.join("datasets", cap)):
#         if os.path.isdir(os.path.join("datasets", cap, folder)):
#             for file in os.listdir(os.path.join("datasets", cap, folder)):
#                 try:
#                     process_pcap(os.path.join("datasets", cap, folder, file))
#                 except Exception as e:
#                     print(folder, cap, file, e)

cap_names = ["captures1_v2", "captures2", "captures3"]

data = pd.read_csv("datasets/power3class/data1.csv")
print(len(data))
print(data.columns.values)
for c in data.columns.values:
    print(c, data[c].unique()[:3])
raise Exception
#
for i, c in enumerate(cap_names):
    print(c)
    df = []
    for file in os.listdir("datasets"):
        if (".csv" in file) and (c in file):
           df.append(pd.read_csv(os.path.join("datasets", file)))
    df = pd.concat(df)
    df.to_csv(c + ".csv", index=False)