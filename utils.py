import requests
from pathlib import Path
from os import listdir
from zipfile import ZipFile
import json
from tqdm import tqdm
import scapy
import py7zr
import pandas as pd

# todo finish this with namelist walk to find pcaps

data_dir = Path("datasets")

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

def get_all_data():
    if not data_dir.exists():
        data_dir.mkdir()
    zipfilename = data_dir/"power3class.7z"
    if not(zipfilename.exists()):
        download("http://www.ece.uah.edu/~thm0009/icsdatasets/3class.7z", zipfilename)
    unzip(zipfilename, data_dir/"power3class")

def get_training_data(balanced=True):
    if not(data_dir/"power3class").exists() or not(len(listdir(data_dir/"power3class")) == 15):
        get_all_data()
    # training data = csv files 1 - 9
    dfs = []
    for i in range(1, 10):
        dfs.append(pd.read_csv(data_dir/"power3class"/"data{}.csv".format(i)))
    df = pd.concat(dfs)
    df["malicious"] = df["marker"] == "Attack"

    print(df["malicious"].value_counts())
    print(df.columns.values)
    return df

class Model():
    def __init__(self, config):
        self.call_model = config["algorithm"]
        self.name = config["model_name"]
        self.features = config["features"]
        self.problem = config["problem"]

    def balance_data(self, data):
        ben_rows = data[~data["malicious"]].index
        mal_rows = data[data["malicious"]].index
        max_class = max(len(ben_rows), len(mal_rows))
        ben_rows = ben_rows[:max_class]
        mal_rows = mal_rows[:max_class]
        return data[data.index.isin(ben_rows) | data.index.isin(mal_rows)]

    def prep_data(self, data):
        if self.problem == "anomaly":
            x = data[self.features]
            y = x
        else:
            data = self.balance_data(data)
            x = data[self.features]
            y = data["malicious"]
        return x, y

    def train(self, data):
        x, y = self.prep_data(data)
        ## todo anomaly choose threshold

