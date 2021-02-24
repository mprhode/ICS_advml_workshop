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

data_dir = Path("datasets")
test_train_cutoff = 13

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


def unzip(zipfilename, outfolder):
    archive = py7zr.SevenZipFile(zipfilename, mode='r')
    archive.extractall(path=outfolder)
    archive.close()

def remove_infs(df):
    #df = df.replace([-np.inf, np.inf], np.nan)
    df = df.replace(np.inf, np.finfo("float32").max)
    df = df.replace(np.inf, np.finfo("float32").min)
    df = df.dropna()
    return df

def get_all_data():
    if not data_dir.exists():
        data_dir.mkdir()
    zipfilename = data_dir/"power3class.7z"
    if not(zipfilename.exists()):
        download("http://www.ece.uah.edu/~thm0009/icsdatasets/triple.7z", zipfilename)
    unzip(zipfilename, data_dir/"power3class")

def __get_dataset(start_file, stop_file, nrows=None):
    if not(data_dir/"power3class").exists() or not(len(listdir(data_dir/"power3class")) == 15):
        get_all_data()
    # training data = csv files 1 - 9
    dfs = []

    for i in range(start_file, stop_file):
        dfs.append(remove_infs(
            pd.read_csv(data_dir/"power3class"/"data{}.csv".format(i), nrows=nrows)
        ))

    df = pd.concat(dfs)
    df["malicious"] = df["marker"] == "Attack"

    print(df["malicious"].value_counts())
    return df

def get_training_data(nrows=None):
   return __get_dataset(1, test_train_cutoff, nrows=nrows)

def get_testing_data(nrows=None):
   return __get_dataset(test_train_cutoff, 16, nrows=nrows)
