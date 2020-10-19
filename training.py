import sys
import os
import matplotlib.pyplot as plt
import networkx as nx
from sklearn import preprocessing
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.preprocessing import LabelBinarizer
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.utils import shuffle
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from helper_functions import get_utctime
from helper_functions import get_image_path
from helper_functions import get_process
from helper_functions import get_value
from helper_functions import get_commandline_arg
from helper_functions import get_entrophy
from helper_functions import onehotencode_integrity_level
from helper_functions import calc_runtime
import itertools as it
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import roc_curve, auc

input_file_path = sys.argv[1]
output_path = sys.argv[2]
dataframe = pd.DataFrame()
for filename in os.listdir(input_file_path ):
    if "benign" in filename:
        label = 0
    else:
        label = 1
    df = pd.read_csv(input_file_path + "\\" + filename, header=1)

    # Terminated processes
    terminated_df = df
    terminated_df.columns = [
        "Level",
        "Data and Time",
        "Source",
        "Event ID",
        "Task Category",
        "Data",
    ]
    terminated_df = terminated_df.loc[terminated_df["Event ID"] == 5]
    terminated_data = pd.DataFrame(
        terminated_df.Data.str.split("\r\n").tolist(),
        columns=[
            "eventtype",
            "rulename",
            "utctime",
            "processguid",
            "processid",
            "image",
        ],
    )

    terminated_data["termination_time"] = terminated_data.apply(
        lambda x: get_value(x["utctime"]), axis=1
    )
    terminated_data["processguid"] = terminated_data.apply(
        lambda x: get_value(x["processguid"]), axis=1
    )
    terminated_data["processid"] = terminated_data.apply(
        lambda x: get_value(x["processid"]), axis=1
    )
    terminated_data = terminated_data.drop(
        ["eventtype", "rulename", "utctime", "image"], axis=1
    )
    # Created processes
    df.columns = [
        "Level",
        "Data and Time",
        "Source",
        "Event ID",
        "Task Category",
        "Data",
    ]
    df = df.loc[df["Event ID"] == 1]
    final_data = pd.DataFrame()
    try:
        data = pd.DataFrame(
            df.Data.str.split("\n").tolist(),
            columns=[
                "eventtype",
                "rulename",
                "utctime",
                "processguid",
                "processid",
                "image",
                "fileversion",
                "description",
                "product",
                "company",
                "originalfilename",
                "commandline",
                "currentdirectory",
                "user",
                "logonguid",
                "loginid",
                "terminalsessionid",
                "integritylevel",
                "hashes",
                "parentprocessguid",
                "parentprocessid",
                "parentimage",
                "parentcommandline",
            ],
        )
        # Prepare data
        data["creation_time"] = data.apply(
            lambda x: get_utctime(x["utctime"]), axis=1
        )
        data["processguid"] = data.apply(
            lambda x: get_value(x["processguid"]), axis=1
        )
        data["processid"] = data.apply(
            lambda x: get_value(x["processid"]), axis=1
        )
        data["child_path"] = data.apply(
            lambda x: get_image_path(x["image"]), axis=1
        )
        data["child_process"] = data.apply(
            lambda x: get_process(x["image"]), axis=1
        )
        data["child_commandline_args"] = data.apply(
            lambda x: get_commandline_arg(x["commandline"]), axis=1
        )
        data["parent_processid"] = data.apply(
            lambda x: get_value(x["parentprocessid"]), axis=1
        )
        data["parent_path"] = data.apply(
            lambda x: get_image_path(x["parentimage"]), axis=1
        )
        data["parent_process"] = data.apply(
            lambda x: get_process(x["parentimage"]), axis=1
        )
        data["parent_commandline_args"] = data.apply(
            lambda x: get_commandline_arg(x["parentcommandline"]), axis=1
        )
        data["entrophy_child_name"] = data.apply(
            lambda x: get_entrophy(x["child_process"]), axis=1
        )
        data["entrophy_child_commandline"] = data.apply(
            lambda x: get_entrophy(x["child_commandline_args"]), axis=1
        )
        data["entrophy_parent_name"] = data.apply(
            lambda x: get_entrophy(x["parent_process"]), axis=1
        )
        data["entrophy_parent_commandline"] = data.apply(
            lambda x: get_entrophy(x["parent_commandline_args"]), axis=1
        )
        data["integritylevel"] = data.apply(
            lambda x: get_value(x["integritylevel"]), axis=1
        )
        # Onehotencode integrity level
        integrity_encoder = LabelBinarizer()
        integrity_encoder.fit(
            ["Low", "Medium", "High", "System", "AppContainer"]
        )
        transformed = integrity_encoder.transform(data["integritylevel"])
        ohe_df = pd.DataFrame(transformed)
        ohe_df = ohe_df.rename(
            columns={
                0: "Low",
                1: "Medium",
                2: "High",
                3: "System",
                4: "AppContainer",
            }
        )
        data = pd.concat([data, ohe_df], axis=1)

        final_data = pd.merge(
            data, terminated_data, how="inner", on=["processguid", "processid"]
        )
        final_data["runtime"] = final_data.apply(
            lambda x: calc_runtime(x["creation_time"], x["termination_time"]),
            axis=1,
        )
        final_data["label"] = label

    except:
        print(filename)
        print("error splitting")

    dataframe = dataframe.append(final_data)

# onehotencode process name
dataframe["parent_child_process"] = dataframe[
    ["parent_process", "child_process"]
].values.tolist()
dataframe["parent_child_process"]

mlb = MultiLabelBinarizer()
parent_child_process_df = pd.DataFrame(
    mlb.fit_transform(dataframe["parent_child_process"]),
    columns=mlb.classes_,
    index=dataframe.index,
)
parent_child_process_df.add_prefix("process_name_")

# save mlb
pickle.dump(mlb, open(output_path+"\\mlb.pkl", "wb"))

# rearrange columns
dataframe = dataframe[
    [
        "eventtype",
        "rulename",
        "utctime",
        "termination_time",
        "processguid",
        "processid",
        "image",
        "fileversion",
        "description",
        "product",
        "company",
        "originalfilename",
        "commandline",
        "currentdirectory",
        "user",
        "logonguid",
        "loginid",
        "terminalsessionid",
        "integritylevel",
        "hashes",
        "parentprocessguid",
        "parentprocessid",
        "parentimage",
        "parentcommandline",
        "creation_time",
        "child_path",
        "child_process",
        "child_commandline_args",
        "parent_processid",
        "parent_path",
        "parent_process",
        "parent_child_process",
        "parent_commandline_args",  # default features
        "entrophy_child_name",
        "entrophy_parent_name",
        "entrophy_child_commandline",
        "entrophy_parent_commandline",
        "Low",
        "Medium",
        "High",
        "System",
        "AppContainer",
        "runtime",
        "label",
    ]
]

# tf idf commandline args
child_corpus = dataframe[["child_commandline_args"]].values.tolist()
parent_corpus = dataframe[["parent_commandline_args"]].values.tolist()
parent_child_corpus = []
for i in range(0, len(child_corpus)):
    parent_child = str(parent_corpus[i][0]) + " " + str(child_corpus[i][0])
    parent_child_corpus.append(parent_child)

# tf idf on corpus
tfidf_vectorizer = TfidfVectorizer(use_idf=True)
tfidf_vectorizer_vector = tfidf_vectorizer.fit(parent_child_corpus)

tfidf_vectorizer_vectors = tfidf_vectorizer_vector.transform(
    parent_child_corpus
)
tfidf_vectorizer_vectors.todense()

# tf idf sparse matrix to dataframe
vec = pd.DataFrame(tfidf_vectorizer_vectors.todense())

# save tfidf
pickle.dump(tfidf_vectorizer_vector, open(output_path+"\\commandline.pkl", "wb"))

# join onehotencode df + tf idf dataframe to dataframe
dataframe = pd.concat([dataframe, parent_child_process_df], axis=1)
vec.reset_index(drop=True, inplace=True)
dataframe.reset_index(drop=True, inplace=True)
dataframe = pd.concat([dataframe, vec], axis=1)

sample_unusual = len(dataframe.loc[dataframe["label"] == 0])

benign_df = dataframe.loc[dataframe["label"] == 0]
unusual_df = dataframe.loc[dataframe["label"] == 1]
unusual_df = unusual_df.sample(n=sample_unusual, random_state=42)

combine_df = benign_df.append(unusual_df)

try_df = combine_df
df = shuffle(try_df, random_state=42)
label_df = df.pop("label")
array_label = label_df.values
array = df.values
Y = array_label
X = array[:, 33 : len(df.columns)]

# XGBoost model
X_train, X_test, y_train, y_test = train_test_split(
    X, Y, test_size=0.2, random_state=42
)

model = XGBClassifier()
model.fit(X_train, y_train)
kfold = StratifiedKFold(n_splits=10, random_state=42, shuffle=True)
cv_results = cross_val_score(
    model, X_train, y_train, cv=kfold, scoring="accuracy"
)
print("10 Folds : %f (%f)" % (cv_results.mean(), cv_results.std()))
predictions = model.predict(X_test)

print(confusion_matrix(y_test, predictions))
print(classification_report(y_test, predictions))

#ROC
y_score = model.predict_proba(X_test)[:,1]
fpr, tpr, thresholds = roc_curve(y_test, y_score, pos_label=1)
roc_auc = auc(fpr, tpr)
print("roc_auc:"+str(roc_auc))

pickle.dump(model, open(output_path+"\\model.pkl", "wb"))
