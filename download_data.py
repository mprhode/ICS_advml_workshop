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

keep_features = ["Ethernet__type", "IP__src", "IP__dst", "IP__ihl", "IP__tos", "IP__len", "IP__id", "IP__ttl", "IP__flags",
                 "IP__frag",
                 "IP__proto", "IP__chksum", "TCP__sport", "TCP__flags",
                 "TCP__dport", "TCP__seq", "TCP__ack", "TCP__dataofs",
                 "TCP__reserved", "TCP__options", "TCP__chksum"
                 "TCP__window", "TCP__chksum", "ModbusADU__transId",
                 "ModbusADU__protoId", "ModbusADU__len", "ModbusADU__unitId", "time", "UDP__sport", "UDP__dport", "UDP__len",
                 "UDP__chksum", "IPv6__version", "IPv6__fl", "IPv6__plen", "IPv6__nh", "IPv6__hlim",
                 "IPv6 Extension Header - Hop-by-Hop Options Header__nh", "BOOTP__hlen", "BOOTP__xid", "BOOTP__secs",
                 "ICMPv6 Neighbor Discovery - Neighbor Solicitation__type", "ICMPv6 Neighbor Discovery - Neighbor Solicitation__cksum",
                 "ICMPv6 Neighbor Discovery - Router Solicitation__type", "ICMPv6 Neighbor Discovery - Router Solicitation__cksum",
                 "ICMP__type", "ICMP__chksum", "ICMP__id", "ICMP__seq", "DHCPv6 Solicit Message__msgtype", "DHCPv6 Solicit Message__trid",
                 "DHCP6 Elapsed Time Option__optcode", "DHCP6 Elapsed Time Option__optlen", "DHCP6 Elapsed Time Option__elapsedtime",
                 "DHCP6 Client Identifier Option__optcode", "vendor class data_   |_len", "DHCP6 Option Request Option__optcode",
                 "DHCP6 Option Request Option__optlen", "IP Option Router Alert_   |_option", "IP Option Router Alert_   |_length",
                 "Link Local Multicast Node Resolution - Query__id", "Link Local Multicast Node Resolution - Query__qdcount",
                 "DNS Question Record_   |_qtype", "DNS Question Record_   |_qclass",
                 "ICMPv6 Neighbor Discovery Option - Source Link-Layer Address__type",
                 "ICMPv6 Neighbor Discovery Option - Source Link-Layer Address__len",
                 ]

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
                if key in keep_features:
                    ret[key] = pkt_as_dict(fvalue, indent=indent, label_lvl=label_lvl + lvl + "   |",
                                              first_call=ret)  # noqa: E501
        else:
            key = "{}_{}_{}".format(pkt.name, label_lvl + lvl, f.name)
            if isinstance(fvalue, str):
                fvalue = fvalue.replace("\n", "\n" + " " * (len(label_lvl) +  # noqa: E501
                                                              len(lvl) +
                                                              len(f.name) +
                                                              4))

            if key in keep_features:
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


def pcap_to_df(file_name, out_csv_name):
    file_name = str(file_name)
    print('Opening {} ...'.format(file_name))
    df = []
    for i, pkt in enumerate(PcapReader(file_name)):
        data = pkt_as_dict(pkt)
        #data["bytes"] = str(pkt)
        data["packet_id"] = i + 1
        df.append(data)
    df = pd.DataFrame(df)
    df["filename"] = file_name.split("/")[-1]
    if len(file_name.split("/")) > 2:
        df["attack_type"] = file_name.split("/")[-2]
        df["capturename"] = file_name.split("/")[-3]
    df["time_delta"] = df["time"].diff()
    df.to_csv(out_csv_name, index=False)
    print("done parsing {}".format(file_name))
    return df


def download_and_label_data(labels, data_dir):
    train_dfs = []
    test_dfs = []
    for folder in labels["folder"].unique():

        zipfilename = data_dir / (folder + ".zip")

        try:
            archive = zipfile.ZipFile(zipfilename)
        except (FileNotFoundError, zipfile.BadZipfile):
            download(data_files[folder + ".zip"]["url"], zipfilename)
            archive = zipfile.ZipFile(zipfilename)

        for pcap_filename in labels[labels["folder"] == folder]["relevant_files"].unique():
            pcap_headless_filepath = str(Path(*pcap_filename.parts[1:]))
            csv_filename = Path(data_dir) / pcap_headless_filepath.replace("pcap", "csv").replace("/", "_")

            if csv_filename.exists():
                df = pd.read_csv(csv_filename)
            else:
                archive.extract(pcap_headless_filepath, data_dir)  # remove top level of posix path (data_dir)
                df = pcap_to_df(pcap_filename, out_csv_name=csv_filename)

            if not "malicious" in df.columns.values:
                # label_data
                df["malicious"] = 0
                df["attack_type"] = "clean"
                attack = labels[(labels["folder"] == folder) & (labels["relevant_files"] == pcap_filename) & (labels["malicious"] == 1)]
                assert len(attack) <= 1, attack # should only be one or zero attack periods for this code to work
                if len(attack):
                    start, end = attack[["start_packet", "end_packet"]].values.flatten().astype(int)
                    df.loc[(df["packet_id"] >= start) & (df["packet_id"] < end), "malicious"] = 1
                    df.loc[df["malicious"] == 1, "attack_type"] = attack["attack"].values[0]
                df.to_csv(csv_filename, index=False)
            train_test = labels[(labels["folder"] == folder) & (labels["relevant_files"] == pcap_filename)]["train_test"].values[0]
            if train_test == "train":
                train_dfs.append(df)
            else:
                test_dfs.append(df)

    pd.concat(train_dfs).to_csv(data_dir/"train.csv", index=False)
    pd.concat(test_dfs).to_csv(data_dir/"test.csv", index=False)

if __name__ == "__main__":
    data_dir = Path("datasets")
    training_set_file = data_dir / "train.csv"
    testing_set_file = data_dir / "test.csv"
    if not (training_set_file.exists()) or not (testing_set_file.exists()):
        labels = pd.read_csv(data_dir / "packet_labels.csv", delimiter=";")
        labels["relevant_files"] = labels[["folder", "attack", "filename"]].apply(
            lambda x: data_dir / x["folder"] / x["attack"] / x["filename"], axis=1)
        labels["relevant_files_exists"] = labels["relevant_files"].apply(lambda x: x.exists())
        download_and_label_data(labels, data_dir)