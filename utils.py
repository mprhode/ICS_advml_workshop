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

data_dir = Path("datasets")
dataset_file = data_dir / "dataset.csv"
train_test_cutoff = 0.75

usecols = []
categorical = "IP__proto", "TCP__flags"

def get_all_data():
    if dataset_file.exists():
        return
    labels = pd.read_csv(data_dir/"packet_labels.csv", delimiter=";")
    labels["relevant_files"] = labels[["folder", "attack", "filename"]].apply(lambda x: data_dir/x["folder"]/x["attack"]/x["filename"], axis=1)
    labels["relevant_files_exists"] = labels["relevant_files"].apply(lambda x: x.exists())
    if not labels["relevant_files_exists"].all():
        download_and_label_data(labels, data_dir)

def __get_dataset(train=True, nrows=100):
    #get_all_data()

    all_data = pd.concat([pd.read_csv(f, nrows=nrows).iloc[::10] for f in data_dir.iterdir() if f.suffix == ".csv"])
    all_data.fillna(0, inplace=True)
    all_data = all_data[[c for c in all_data.columns.values if not(all_data[c].dtype in [str, object])]]
    for c in all_data.columns.values:
        print(c, all_data[c].unique()[:5], all_data[c].dtype)
    split_point = int(train_test_cutoff * len(all_data))
    if train:
        ret = all_data[:split_point]
    else:
        ret = all_data[split_point:]
    print(ret["malicious"].value_counts())
    return ret

def get_training_data(nrows=None):
    return __get_dataset(train=True, nrows=nrows)

def get_testing_data(nrows=None):
    return __get_dataset(train=False, nrows=nrows)

