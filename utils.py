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

def get_all_data():
    if dataset_file.exists():
        return
    labels = pd.read_csv(data_dir/"packet_labels.csv", delimiter=";")
    labels["relevant_files"] = labels[["folder", "attack", "filename"]].apply(lambda x: data_dir/x["folder"]/x["attack"]/x["filename"], axis=1)
    labels["relevant_files_exists"] = labels["relevant_files"].apply(lambda x: x.exists())
    if not labels["relevant_files_exists"].all():
        download_and_label_data(labels, data_dir)


def __get_dataset(train=True):
    get_all_data()
    all_data = pd.read_csv(dataset_file)
    split_point = int(train_test_cutoff * len(all_data))
    if train:
        return all_data[:split_point]
    return all_data[split_point:]

def get_training_data():
    return __get_dataset(train=True)


def get_testing_data():
    return __get_dataset(train=False)


get_all_data()