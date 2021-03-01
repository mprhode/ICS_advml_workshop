import requests
from pathlib import Path
from os import listdir
from zipfile import ZipFile
import json
from tqdm import tqdm
import scapy
import py7zr
import pandas as pd
import numpy as np
from download_data import download_and_label_data
from scapy.utils import RawPcapReader

data_dir = Path("datasets")
dataset_file = data_dir / "dataset.csv"
train_test_cutoff = 0.5


categorical = ["Ethernet__type", "IP__dst", "IP__src", "IP__proto",  "IP__flags", "IP__tos",
               "TCP__flags", "ICMP__type", "ICMPv6 Neighbor Discovery - Neighbor Solicitation__type",
               "ICMPv6 Neighbor Discovery - Router Solicitation__type",
               "ICMPv6 Neighbor Discovery Option - Source Link-Layer Address__type",
               "ICMPv6 Neighbor Discovery Option - Source Link-Layer Address__len",
               "DHCP6 Elapsed Time Option__optcode", "DHCP6 Client Identifier Option__optcode",
               "DHCP6 Option Request Option__optcode" ] # todo fill this out

special_categorical = ["IP__src", "TCP__sport", "TCP__dport", "UDP__sport", "UDP__dport"]

ignore = ["time", "packet_id", 'filename', 'capturename']
classification_cols = ["malicious", "attack_type"]
ignore_packet = ["TCP__chksum", "IP__chksum", "TCP__options", "UDP__chksum", "TCP__reserved", "IP__id", "TCP__ack", "TCP__seq",
                 "ModbusADU__transId", "ICMP__chksum", "ICMP__seq", "Link Local Multicast Node Resolution - Query__id",
                 "ICMPv6 Neighbor Discovery - Neighbor Solicitation__cksum",
                 "ICMPv6 Neighbor Discovery - Router Solicitation__cksum", "BOOTP__xid", "BOOTP__hlen", "ICMP__chksum", "ICMP__id",
                 "ICMP__seq", "DHCPv6 Solicit Message__trid"
                 ]
ignore += ignore_packet

df = pd.read_csv("datasets/dataset.csv", usecols=["malicious", "IP__src", "TCP__sport", "TCP__dport", "UDP__sport", "UDP__dport"])
split_point = int(train_test_cutoff * len(df))
clean_train = df[(df["malicious"] == 0) & (df.index < split_point)]
clean_train_srcIP = clean_train["IP__src"].unique()
clean_train_tcpsrcport = clean_train["TCP__sport"].value_counts().head(5).keys()
clean_train_tcpdstport = clean_train["TCP__dport"].value_counts().head(5).keys()
clean_train_udpsrcport = clean_train["UDP__sport"].value_counts().head(5).keys()
clean_train_udpdstport = clean_train["UDP__dport"].value_counts().head(5).keys()

def get_all_data():
    if dataset_file.exists():
        return
    labels = pd.read_csv(data_dir/"packet_labels.csv", delimiter=";")
    labels["relevant_files"] = labels[["folder", "attack", "filename"]].apply(lambda x: data_dir/x["folder"]/x["attack"]/x["filename"], axis=1)
    labels["relevant_files_exists"] = labels["relevant_files"].apply(lambda x: x.exists())
    # print(labels["relevant_files_exists"])
    #if not labels["relevant_files_exists"].all():
    download_and_label_data(labels, data_dir)

def one_hot_encode(df, col, include=None):
    try:
        include = df[col].unique() if include is None else include
        for i in include:
            df["{}_{}".format(col, i)] = (df[col] == i).astype(int)
    except KeyError:
        return df
    return df.drop(columns=[col], axis=1)

def df_handle_categorical(df):
    # categorical to one-hot representation
    for c in categorical:
        if not c in special_categorical:
            df = one_hot_encode(df, c, include=None)
    # special cases:
    df = one_hot_encode(df, "IP__src", include=clean_train_srcIP)
    df = one_hot_encode(df, "TCP__sport", include=clean_train_tcpsrcport)
    df = one_hot_encode(df, "TCP__dport", include=clean_train_tcpdstport)
    df = one_hot_encode(df, "UDP__sport", include=clean_train_udpsrcport)
    df = one_hot_encode(df, "UDP__dport", include=clean_train_udpdstport)
    return df.fillna(0)

def __get_dataset(train=True, nrows=None, filename="datasets/dataset.csv", train_test_cutoff=train_test_cutoff):
    get_all_data()
    nrows = nrows if train or (nrows is None) else nrows + split_point
    all_data = pd.read_csv(filename, nrows=nrows)
    all_data.drop(columns=ignore, inplace=True, axis=1, errors="ignore")

    all_data.fillna(0, inplace=True)
    if train:
        ret = all_data[:split_point].copy()
    else:
        ret = all_data[split_point:].copy()

    ret = df_handle_categorical(ret)

    print(ret["malicious"].value_counts())
    try:
        print(ret["attack_type"].value_counts())
        ret.drop(columns=["attack_type"], axis=1, inplace=True)
    except KeyError:
        pass

    return ret.astype(float)

def get_training_data(nrows=None):
    return __get_dataset(train=True, nrows=nrows)

def get_testing_data(nrows=None):
    return __get_dataset(train=False, nrows=nrows)

def parse_df_for_pcap_validity(df, original_data, columns):
    # NB this function is not complete but rather written for the purposes of this workshop and tested adversarial model outcomes
    # check if df values are valid for packet
    df = pd.DataFrame(df, columns=columns)
    original_data = pd.DataFrame(original_data, columns=columns)

    # 1. categorical variables can only be 1 or 0, only one type per variable allowed to be "on"
    for c in df.columns.values:
        relevant_cols = [cat for cat in categorical if c in cat]
        for cat_col in relevant_cols:
            df[cat_col] = df[cat_col].round().clip(0, 1)
        # if np.where(df[relevant_cols] == 1):
        #     pass

    # 2. Dependent variables - can't set TCP flags on a PING
    print(df.columns.values)
    print(original_data.columns.values)
    # TCP off = no TCP attributes should be set
    df.loc[original_data["IP__proto_6.0"] == 0, [col for col in df.columns.values if "TCP__" in col]] = 0

    # 3. Only positive values allowed
    df = df.clip(0, None)

    # 4. Some can only be integers e.g. len
    df["IP__len"] = df["IP__len"].round()
    df["IP__ttl"] = df["IP__ttl"].round().clip(0, 225)

    # 5. max values on some features

    return df


def compare_data(real, adversarial, columns):
    # prints differences in packets only
    not_matching = np.not_equal(real, adversarial)
    real_no_match = real[not_matching]
    adv_no_match = adversarial[not_matching]
    columns = [c for c, m in zip(columns, not_matching) if m]
    df = pd.DataFrame([real_no_match, adv_no_match], columns=columns)
    df.reindex(["Real", "Adv."])
    print(df)


attacker_test_set = "/home/tilda/projects/ICS_advml_workshop/datasets/eth2dump-pingFloodDDoS1m-0,5h_1.pcap"
def get_label_array(pcap_file, mal_start=None, mal_end=None):
    if attacker_test_set == "datasets/eth2dump-pingFloodDDoS1m-0,5h_1.pcap":
        mal_start, mal_end = 2933, 15636
    n_packets = 0
    for pkt in RawPcapReader(pcap_file):
        n_packets += 1
    mal_benign_labels = np.zeros(n_packets)
    mal_benign_labels[mal_start:mal_end] = 1
    return mal_benign_labels
