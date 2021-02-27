from sklearn.metrics import mean_squared_error, confusion_matrix, f1_score, accuracy_score
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest, RandomForestClassifier, AdaBoostClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import LocalOutlierFactor
from sklearn import svm
import xgboost as xgb

import numpy as np
import pickle as pkl
from pathlib import Path
import yaml

np.random.seed(1)

model_folder = Path("Models")


class Model():
    def __init__(self, features, save_model_path=None):
        self.save_model_path = save_model_path
        self.features = features
        self.config = {
            "features": self.features
        }
        if not(self.save_model_path is None):
            print(self.save_model_path)
            print(model_folder)
            self.save_model_path = model_folder / self.save_model_path
            self.model_exists = self.save_model_path.exists()
            if self.model_exists:
                print("save_model_path exists, loading model and config....")
                self.load_model()
                print(self.call_model)
                print(self.config)


    def balance_data(self, data):
        ben_rows = data[data["malicious"] == 0].index
        mal_rows = data[data["malicious"] == 1].index
        max_class = max(len(ben_rows), len(mal_rows))
        ben_rows = ben_rows[:max_class]
        mal_rows = mal_rows[:max_class]
        return data[data.index.isin(ben_rows) | data.index.isin(mal_rows)]

    def prep_data(self, data, train=False):
        if not self.anomaly and train:
            data = self.balance_data(data)
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

    def train(self, data, verbose=True):
        x, labels = self.prep_data(data, train=True)
        self.fit_model(x, labels)
        if not(self.save_model_path is None):
            self.save_model()
        self.test(data, dataset_name="Training", verbose=verbose)

    def test(self, data, verbose=True, dataset_name="Testing"):
        x, labels = self.prep_data(data)
        predictions = self.get_predictions(x)

        predictions = predictions.round()
        if verbose:
            print("-----")
            print("{} accuracy: {}".format(dataset_name, accuracy_score(labels, predictions)))
            print(confusion_matrix(labels, predictions))
            print("-----")

    def load_model(self):
        with open(self.save_model_path / "model.pkl", "rb") as f:
            self.call_model = pkl.load(f)
        with open(self.save_model_path / "config.yml", "r") as f:
            self.config = yaml.load(f)

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



class AnomalyModel(Model):
    def __init__(self, features, contamination=None, save_model_path=None):
        super(AnomalyModel, self).__init__(features, save_model_path=save_model_path)
        self.model_name = "anomaly detection"
        self.anomaly = True
        self.config["problem"] = "anomaly"
        self.config["contamination"] = contamination

    def get_predictions(self, x):
        # transform (-1, 1) to (0, 1)
        preds = (self.call_model.predict(x) + 1) / 2
        return preds


class OneClassSVM(AnomalyModel):
    def __init__(self, features, contamination=None, save_model_path=None):
        super(OneClassSVM, self).__init__(features, contamination=contamination, save_model_path=save_model_path)
        self.call_model = svm.OneClassSVM(nu=contamination)

class RobustCovariance(AnomalyModel):
    def __init__(self, features, contamination=None, save_model_path=None):
        super(RobustCovariance, self).__init__(features, contamination=contamination, save_model_path=save_model_path)
        self.call_model = EllipticEnvelope(contamination=contamination)

class ISOF(AnomalyModel):
    def __init__(self, features, contamination=None, save_model_path=None):
        super(ISOF, self).__init__(features, contamination=contamination, save_model_path=save_model_path)
        self.call_model = IsolationForest(contamination=contamination)


class LOF(AnomalyModel):
    def __init__(self, features, contamination=None, save_model_path=None):
        super(LOF, self).__init__(features, contamination=contamination, save_model_path=save_model_path)
        self.call_model = LocalOutlierFactor(contamination=contamination)

    def prep_data(self, data, train=False):
        # balance data for LOF because contamination must be 0.5 or less
        if train:
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
    def __init__(self, features, save_model_path=None):
        super(SupervisedModel, self).__init__(features, save_model_path=save_model_path)
        self.anomaly = False
        self.config["problem"] = "classification"


class RandomForest(SupervisedModel):
    def __init__(self, features, save_model_path=None):
        super(RandomForest, self).__init__(features, save_model_path=save_model_path)
        self.call_model = RandomForestClassifier()


class SVM(SupervisedModel):
    def __init__(self, features, save_model_path=None):
        super(SVM, self).__init__(features, save_model_path=save_model_path)
        self.call_model = svm.SVC()


class XGBoost(SupervisedModel):
    def __init__(self, features, save_model_path=None):
        super(XGBoost, self).__init__(features, save_model_path=save_model_path)
        self.call_model = xgb
        self.config["param"] = {'max_depth': 2, 'eta': 1, 'objective': 'binary:logistic'}
        self.config["num_round"] = 10

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
            self.config = yaml.load(f)

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

class MLP(SupervisedModel):
    def __init__(self, features, save_model_path=None):
        super(MLP, self).__init__(features, save_model_path=save_model_path)
        self.call_model = MLPClassifier()

class AdaBoost(SupervisedModel):
    def __init__(self, features, save_model_path=None):
        super(AdaBoost, self).__init__(features, save_model_path=save_model_path)
        self.call_model = AdaBoostClassifier()


from utils import get_testing_data, get_training_data
import numpy as np

train_data = get_training_data(nrows=100).astype(float)
contamination = train_data["malicious"].sum() / len(train_data)
test_data = get_testing_data(nrows=100).astype(float)
# print(contamination)
# for mc in [LOF, ISOF, RobustCovariance, OneClassSVM]:
#     try:
#         contamination = contamination if mc != LOF else 0.5
#         model = mc(["snort_log1", "snort_log2", "snort_log3", "snort_log4", 'R1-PA1:VH', 'R1-PM1:V', 'R1-PA2:VH',
#                     'R1-PM2:V', 'R1-PA3:VH', 'R1-PM3:V', 'R1-PA4:IH', 'R1-PM4:I',
#            'R1-PA5:IH', 'R1-PM5:I', 'R1-PA6:IH'], contamination=contamination)
#         model.train(train_data)
#         model.test(test_data)
#     except Exception as e:
#         print(mc, e)

#
ignore = ["attack", "malicious", "time", "packet_id", "filename", "capturename"]
features = [c for c in train_data.columns.values if not(c in ignore)]

for i in range(0,len(features), 5):
    for mc in [XGBoost]:#, RandomForest, MLP, AdaBoost, SVM]:
        print(mc)
        mini_feat = features[i:i+5]
        if True:
            model = mc(mini_feat)
            model.train(train_data)
            model.test(test_data)

        # except Exception as e:
        #     print(mc, e)

