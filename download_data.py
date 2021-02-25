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

import pandas as pd
import requests
import zipfile
from tqdm import tqdm
from pathlib import Path

data_files = {
    "captures1_v2.zip": {
        "url": "https://github.com/tjcruz-dei/ICS_PCAPS/releases/download/MODBUSTCP%231/captures1_v2.zip"
    },
    "captures2.zip": {
        "url": "https://github.com/tjcruz-dei/ICS_PCAPS/releases/download/MODBUSTCP%231/captures2.zip"
    },
    "captures3.zip": {
        "url": "https://github.com/tjcruz-dei/ICS_PCAPS/releases/download/MODBUSTCP%231/captures3.zip"
    },
}

def download(url, outfile, dataset_number=1):
    response = requests.get(url, stream=True)
    if (response.status_code != 200):
        raise Exception("Error downloading data - status code: {}, url: {}".format(response.status_code, url))
    total_size = int(response.headers["Content-Length"])
    downloaded = 0  # keep track of size downloaded so far
    chunkSize = 1024
    bars = total_size // chunkSize
    with open(str(outfile), "wb") as f:
        for chunk in tqdm(response.iter_content(chunk_size=chunkSize), total=bars, unit="KB",
                          desc="Dataset {}/3".format(dataset_number), leave=True):
            f.write(chunk)
            downloaded += chunkSize

def pkt_as_dict(pkt, indent=3, lvl="",
                      label_lvl="",
                      first_call=True):
    # based on scapy show() method
    # returns: dict of pkt attributes normally printed by show() plus time
    if first_call is True:
        ret = {}
    else:
        ret = first_call

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

    ret["time"] = float(pkt.time)
    return ret


def pcap_to_df(file_name):
    file_name = str(file_name)
    print('Opening {} ...'.format(file_name))
    df = []
    for i, pkt in enumerate(PcapReader(file_name)):
        data = pkt_as_dict(pkt)
        data["bytes"] = str(pkt)
        data["packet_id"] = i + 1
        df.append(data)
    df = pd.DataFrame(df)
    df["attack_type"] = file_name.split("/")[-2]
    df["filename"] = file_name.split("/")[-1]
    df["capturename"] = file_name.split("/")[-3]
    df["time_delta"] = df["time"].diff()
    data_dir = file_name.split("/")[0]
    csv_file = Path(data_dir) / file_name.replace(data_dir, "").replace("pcap", "csv").replace("/", "_")
    df.to_csv(csv_file, index=False)
    print("done parsing {}".format(file_name))
    return df, csv_file


def download_and_label_data(labels, data_dir):
    dfs = []
    for folder in labels["folder"].unique():

        zipfilename = data_dir / (folder + ".zip")

        try:
            archive = zipfile.ZipFile(zipfilename)
        except (FileNotFoundError, zipfile.BadZipfile):
            download(data_files[folder + ".zip"]["url"], zipfilename)
            archive = zipfile.ZipFile(zipfilename)

        for pcap_filename in labels[labels["folder"] == folder]["relevant_files"].unique():

            archive.extract(str(Path(*pcap_filename.parts[1:])), data_dir)  # remove top level of posix path (data_dir)
            df, csv_filename = pcap_to_df(pcap_filename)

            # label_data
            df["malicious"] = 0
            df["attack_type"] = "clean"
            attack = labels[(labels["folder"] == folder) & (labels["relevant_files"] == pcap_filename) & (labels["malicious"] == 1)]
            assert len(attack) <= 1, attack # should only be one or zero attack periods for this code to work
            if len(attack):
                start, end = attack[["start_packet", "end_packet"]].values.flatten()
                df.loc[(df["packet_id"] >= start) & (df["packet_id"] < end), "malicious"] = 1
                df[df["malicious"] == 1, "attack_type"] = attack["attack"].values[0]
            df.to_csv(csv_filename)
            dfs.append(df)

    df = pd.concat(dfs)
    df.to_csv(data_dir/"dataset.csv", index=False)


