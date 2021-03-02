from sklearn.metrics import mean_squared_error, confusion_matrix, f1_score, accuracy_score
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest, RandomForestClassifier, AdaBoostClassifier
from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import LocalOutlierFactor
from sklearn import svm
#import xgboost as xgb

import numpy as np
import pickle as pkl
from pathlib import Path
import yaml
import matplotlib.pyplot as plt
from zipfile import ZipFile
import pandas as pd

from utils import classification_cols, df_handle_categorical, ignore
from download_data import pcap_to_df

np.random.seed(1)

model_folder = Path("Models")
eps = np.finfo('float64').eps

# unzip any models that need it
for item in model_folder.iterdir():
    if item.suffix == ".zip":
        if not (model_folder/item.name).exists():
                z = ZipFile(item)
                z.extractall(model_folder/item.name)
                z.close()

class Model():
    def __init__(self, features, save_model_name=None, verbose=True):
        self.save_model_path = None if save_model_name is None else model_folder / save_model_name
        self.model_exists = False if save_model_name is None else self.save_model_path.exists()

        if self.model_exists:
            if verbose:
                print("save_model_path exists, loading model and config....")
            self.load_model()
            if verbose:
                print(self.call_model)
                print(self.features)
        else:
            self.features = [f for f in features if not (f in classification_cols + ignore)]
            self.config = {
                "features": self.features
            }
        self.tpr = None
        self.tnr = None
        self.cm = None

    def parse_pcap(self, filename):
        data = pcap_to_df(filename, filename.replace(".pcap", ".csv"))
        data = df_handle_categorical(data)
        return data

    def balance_data(self, data):
        ben_rows = data[data["malicious"] == 0].index
        mal_rows = data[data["malicious"] == 1].index
        min_class = min(len(ben_rows), len(mal_rows)) - 1 # -1 to allow easy coding for np.random.choice() below
        ben_rows = np.random.choice(ben_rows, size=min_class, replace=False)
        mal_rows = np.random.choice(mal_rows, size=min_class, replace=False)
        return data[data.index.isin(ben_rows) | data.index.isin(mal_rows)]

    def prep_data(self, data, train=False):
        if not self.anomaly and train:
            data = self.balance_data(data)
        else:
            for f in self.features:
                if not(f in data.columns.values):
                    data[f] = 0
        x = data[self.features].values
        labels = data["malicious"].values.astype(int)
        assert len(x) == len(labels)
        return x, labels

    def get_predictions(self, x):
        return self.call_model.predict(x)

    def fit_model(self, x, labels):
        if self.anomaly:
            self.call_model.fit(x)
        else:
            self.call_model.fit(x, labels)

    def train(self, data, verbose=True, continue_training=False):
        if (not self.save_model_path.exists()) or continue_training:
            x, labels = self.prep_data(data, train=True)
            self.fit_model(x, labels)
            if not(self.save_model_path is None):
                self.save_model()
        self.test(data, dataset_name="Training", verbose=verbose)

    def test(self, data, verbose=True, dataset_name="Testing", malicious=None, return_x_y_preds=False):
        if type(data) is tuple:
            x, labels = data
        else:
            if (type(data) is str) and (".pcap" in data):
                assert malicious is not None, ("Must provide malicious labels (int or iterable) if using pcap, not None")
                data = self.parse_pcap(data)
                data["malicious"] = malicious
            elif type(data) is np.ndarray:
                data = pd.DataFrame(data, columns=self.features)
            if not ("malicious" in data.columns.values):
                data["malicious"] = 1
            x, labels = self.prep_data(data)

        predictions = self.get_predictions(x)
        predictions = predictions.round()

        self.cm = confusion_matrix(labels, predictions)
        # handle one-class perfect predictions

        if (labels.var() == 0) and np.equal(labels, predictions).all():
            self.cm = np.zeros((2, 2))
            label_value = labels.max().astype(int)
            self.cm[label_value, label_value] = len(labels)

        tn, fp, fn, tp = self.cm.ravel().astype(np.float32)
        self.tpr = tp / (tp + fn + eps)
        self.tnr = tn / (tn + fp + eps)

        if verbose:
            print("-----")
            print("{} acc: {:.2f}, f1: {:.2f}, tpr: {:.2f}, tnr {:.2f}".format(
                dataset_name, accuracy_score(labels, predictions), f1_score(labels, predictions), self.tpr, self.tnr))
            print(self.cm)
            print("-----")
        if return_x_y_preds:
            return x, labels, predictions

    def load_model(self):
        with open(self.save_model_path / "model.pkl", "rb") as f:
            self.call_model = pkl.load(f)
        with open(self.save_model_path / "config.yml", "r") as f:
            self.config = yaml.load(f, Loader=yaml.FullLoader)
        self.features = list(self.config["features"])
        if "contamination" in self.config.keys():
            self.contamination = self.config["contamination"]
            self.anomaly = True
        else:
            self.anomaly = False

    def save_model(self):
        if self.model_exists:
            print("not saving model as model already exists")
            return
        # save model and config details
        print("saving model...")
        self.save_model_path.mkdir()
        with open(self.save_model_path/"model.pkl", "wb") as f:
            pkl.dump(self.call_model, f)
        with open(self.save_model_path/"config.yml", "w") as f:
            yaml.dump(self.config, f)

    def get_classifier(self):
        return self.call_model


class BlackBoxModel(Model):
    def __init__(self, save_model_name=None, verbose=False):
        super(BlackBoxModel, self).__init__(None, save_model_name=save_model_name, verbose=verbose)
        self.__features = [f for f in self.features]
        self.features = None

    def train(self):
        return self.call_model

    def save_model(self):
        return self.call_model

    def prep_data(self, data, train=False):
        for f in self.__features:
            if not (f in data.columns.values):
                data[f] = 0
        x = data[self.__features].values
        labels = data["malicious"].values.astype(int)
        assert len(x) == len(labels)
        return x, labels

    def test(self, data):
        try:
            if type(data) is tuple:
                x, labels = data
            else:
                if (type(data) is str) and (".pcap" in data):
                    data = self.parse_pcap(data)
                elif type(data) is np.ndarray:
                    data = pd.DataFrame(data, columns=self.features)
                if not("malicious" in data.columns.values):
                    data["malicious"] = 1
                x, labels = self.prep_data(data)

            predictions = self.get_predictions(x)
            predictions = predictions.round()
            total_detect = predictions.sum()
            print("{:.2f}% ({}) packets detected".format(total_detect*100/len(predictions), total_detect))
            # todo breakdown by packet type
            return predictions
        except Exception:
            return "No result"

    def __str__(self):
        return "No model data"


modelA = BlackBoxModel(save_model_name="modelA")
modelB = BlackBoxModel(save_model_name="modelB")
modelC = BlackBoxModel(save_model_name="modelC")

class AnomalyModel(Model):
    def __init__(self, features, contamination=None, save_model_name=None):
        super(AnomalyModel, self).__init__(features, save_model_name=save_model_name)
        self.model_name = "anomaly detection"
        self.anomaly = True
        self.config["problem"] = "anomaly"
        self.config["contamination"] = float(contamination)
        self.contamination = self.config["contamination"]

    def get_predictions(self, x):
        # transform (-1, 1) to (0, 1)
        preds = (self.call_model.predict(x) + 1) / 2
        return preds


class OneClassSVM(AnomalyModel):
    def __init__(self, features, contamination=None, save_model_name=None):
        super(OneClassSVM, self).__init__(features, contamination=contamination, save_model_name=save_model_name)
        if not (self.save_model_path).exists():
            self.call_model = svm.OneClassSVM(nu=self.config["contamination"])

class ISOF(AnomalyModel):
    def __init__(self, features, contamination=None, save_model_name=None):
        super(ISOF, self).__init__(features, contamination=contamination, save_model_name=save_model_name)
        if not (self.save_model_path).exists():
            self.call_model = IsolationForest(contamination=self.config["contamination"])


class LOF(AnomalyModel):
    def __init__(self, features, contamination=None, save_model_name=None):
        super(LOF, self).__init__(features, contamination=min(0.5, contamination), save_model_name=save_model_name)
        if not (self.save_model_path).exists():
            self.call_model = LocalOutlierFactor(contamination=self.config["contamination"]) # always default to max of 0.5 for LOF as 0.5 is max and dataset is more malicious than benign

    def prep_data(self, data, train=False):
        # balance data for LOF because contamination must be 0.5 or less
        if (self.contamination == 0.5) and train:
            data = self.balance_data(data)
        x = data[self.features].values
        labels = data["malicious"].values.astype(int)
        return x, labels

    def fit_model(self, x, labels):
        self.call_model.fit_predict(x)

    def get_predictions(self, x):
        preds = (self.call_model.fit_predict(x) + 1) / 2
        return preds


class SupervisedModel(Model):
    def __init__(self, features, save_model_name=None):
        super(SupervisedModel, self).__init__(features, save_model_name=save_model_name)
        self.anomaly = False
        self.config["problem"] = "classification"


class RandomForest(SupervisedModel):
    def __init__(self, features, save_model_name=None):
        super(RandomForest, self).__init__(features, save_model_name=save_model_name)
        if not (self.save_model_path).exists():
            self.call_model = RandomForestClassifier()


class SVM(SupervisedModel):
    def __init__(self, features, save_model_name=None):
        super(SVM, self).__init__(features, save_model_name=save_model_name)
        if not (self.save_model_path).exists():
            self.call_model = svm.SVC()
        self.model_name = "SVM"


class XGBoost(SupervisedModel):
    def __init__(self, features, save_model_name=None):
        super(XGBoost, self).__init__(features, save_model_name=save_model_name)
        self.call_model = xgb
        self.config["param"] = {'max_depth': 2, 'eta': 1, 'objective': 'binary:logistic'}
        self.config["num_round"] = 10
        self.model_name = "XGB"
        # here used trained_model + call_model to handle xgb setup

    def fit_model(self, dataset, labels):
        self.trained_model = self.call_model.train(self.config["param"], dataset, self.config["num_round"])

    def prep_data(self, data, train=False):
        if train:
            data = self.balance_data(data)
        x = data[self.features].values
        labels = data["malicious"].values.astype(int)
        dataset = xgb.DMatrix(x, label=labels)
        return dataset, labels

    def load_model(self):
        bst = xgb.Booster({'nthread': self["config"]["nthread"]})  # init model
        self.trained_model = bst.load_model(self.save_model_path/"model.bin")  # load data
        with open(self.save_model_path / "config.yml", "r") as f:
            self.config = yaml.load(f, Loader=yaml.FullLoader)

    def save_model(self):
        if self.model_exists:
            print("not saving model as model already exists")
            return
        # save model and config details
        print("saving model...")
        self.save_model_path.mkdir()
        self.trained_model.saveModel(self.save_model_path/"model.bin")
        with open(self.save_model_path/"config.yml", "w") as f:
            yaml.dump(self.config, f)

    def get_predictions(self, x):
        return self.trained_model.predict(x)

    def get_classifier(self):
        return self.trained_model

class MLP(SupervisedModel):
    def __init__(self, features, save_model_name=None):
        super(MLP, self).__init__(features, save_model_name=save_model_name)
        if not (self.save_model_path).exists():
            self.call_model = MLPClassifier()

class AdaBoost(SupervisedModel):
    def __init__(self, features, save_model_name=None):
        super(AdaBoost, self).__init__(features, save_model_name=save_model_name)
        if not(self.save_model_path).exists():
            self.call_model = AdaBoostClassifier()

class DecisionTree(SupervisedModel):
    def __init__(self, features, save_model_name=None):
        super(DecisionTree, self).__init__(features, save_model_name=save_model_name)
        if not(self.save_model_path).exists():
            self.call_model = DecisionTreeClassifier()

    def show(self):
        plot_tree(self.call_model)
        plt.show()


if __name__ == "__main__":
    from utils import get_testing_data, get_training_data
    import numpy as np

    train_data = get_training_data(nrows=None)

    features = [c for c in train_data.columns.values if not(c in classification_cols)]

    contamination = train_data["malicious"].sum() / len(train_data)
    test_data = get_testing_data(nrows=None)
    AD_models = [LOF, ISOF, OneClassSVM]

    print("contamination ratio", contamination)

    # time model
    for model_name, mc in [("dt", DecisionTree), ("MLP", MLP), ("rf", RandomForest), ("ISOF", ISOF), ("svm", SVM),
                            ("OneClassSVM", OneClassSVM),
                           ("LOF", LOF)]:
        for feat_name, mini_feat in [
            ("time_model", ["time_delta", "IP__ttl"] + [x for x in features if (  "Ethernet__type" in x) or ("IP__proto" in x)]),
            ("src_dst_features", [x for x in features if ("src" in x) or ("dst" in x) or ("port" in x)]),
            ("all", features),
            ("all_except_src_dst", [x for x in features if not("src" in x) and not("dst" in x) and not("port" in x)]),
            ("IP_features", [x for x in features if "IP__" in x]),
            ("tcp_udp_modbus_icmp_boot", [x for x in features if ("TCP_" in x) or ("UDP_" in x) or ("MODBUS_" in x) or ("ICMP" in x) or ("BOOT" in x)])
        ]:

            print("\n", mc, mini_feat)
            if mc in AD_models:
                model = mc(mini_feat, save_model_name="{}_{}".format(feat_name, model_name), contamination=contamination)
            else:
                model = mc(mini_feat, save_model_name="{}_{}".format(feat_name, model_name))
            if model.model_exists:
                continue
            if "svm" in model_name.lower():
                model.train(train_data[::50])
            else:
                model.train(train_data)

            model.test(test_data)


