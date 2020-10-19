import sys
import pandas as pd
from networkx.algorithms import community
from helper_functions import get_utctime
from helper_functions import get_image_path
from helper_functions import get_process
from helper_functions import get_value
from helper_functions import get_commandline_arg
from helper_functions import get_entrophy
from helper_functions import onehotencode_integrity_level
from helper_functions import calc_runtime
from helper_functions import prevalence_engine
from helper_functions import anomalous_score
from sklearn.preprocessing import LabelBinarizer
from sklearn.preprocessing import MultiLabelBinarizer
import pickle
import numpy as np

score_dataframe = pd.DataFrame()

input_file_path = sys.argv[1]
input_model_path = sys.argv[2]
output_file_path = sys.argv[3]
df = pd.read_csv(input_file_path, header=1)

# Load model
model = pickle.load(open(input_model_path+"\\model.pkl", "rb"))

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
    data["processid"] = data.apply(lambda x: get_value(x["processid"]), axis=1)
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
    integrity_encoder.fit(["Low", "Medium", "High", "System", "AppContainer"])
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
except:
    print("error splitting")

score_dataframe = score_dataframe.append(final_data)

# onehotencode process name
score_dataframe["parent_child_process"] = score_dataframe[
    ["parent_process", "child_process"]
].values.tolist()
mlb = pickle.load(open(input_model_path+"\\mlb.pkl", "rb"))
new_parent_child_process_df = pd.DataFrame(
    mlb.transform(score_dataframe["parent_child_process"]),
    columns=mlb.classes_,
    index=score_dataframe.index,
)
new_parent_child_process_df

# tf idf commandline args
child_corpus = score_dataframe[["child_commandline_args"]].values.tolist()
parent_corpus = score_dataframe[["parent_commandline_args"]].values.tolist()
parent_child_corpus = []
for i in range(0, len(child_corpus)):
    parent_child = str(parent_corpus[i][0]) + " " + str(child_corpus[i][0])
    parent_child_corpus.append(parent_child)

# load vectorizer from pickle
tfidf_vectorizer_vector = pickle.load(open(input_model_path+"\\commandline.pkl", "rb"))
tfidf_vectorizer_vectors = tfidf_vectorizer_vector.transform(
    parent_child_corpus
)
tfidf_vectorizer_vectors.todense()

# tf idf sparse matrix to dataframe
vec = pd.DataFrame(tfidf_vectorizer_vectors.todense())


# rearrange columns
score_dataframe = score_dataframe[
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
        "parent_commandline_args",  # features used
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
    ]
]

# join onehotencode df + tf idf dataframe to dataframe
score_dataframe = pd.concat(
    [score_dataframe, new_parent_child_process_df], axis=1
)
print(score_dataframe.shape)
vec.reset_index(drop=True, inplace=True)
score_dataframe.reset_index(drop=True, inplace=True)
score_dataframe = pd.concat([score_dataframe, vec], axis=1)

# score new data
array = score_dataframe.values
xnew = array[:, 33 : len(score_dataframe.columns)]
score_dataframe["weight"] = model.predict_proba(xnew)[:, 1]

# calculate prevalence and anomalous score
total_num_process = len(score_dataframe)
score_dataframe["prevalence_score"] = score_dataframe.apply(
    lambda x: prevalence_engine(
        x["parent_process"], x["child_process"], x["commandline"], score_dataframe, total_num_process
    ),
    axis=1
)
score_dataframe["anomalous_score"] = score_dataframe.apply(
    lambda x: anomalous_score(x["weight"], x["prevalence_score"]), axis=1
)

# plot graph
from networkx.algorithms import community
import matplotlib.pyplot as plt
import networkx as nx

edges = []
attributes = {}
edge_labels_dict = {}
G = nx.DiGraph()
threshold_plot = []

for index, rows in score_dataframe.iterrows():
    edges.append([rows.parentprocessguid, rows.processguid])
    edge_labels_dict[
        (rows.parentprocessguid, rows.processguid)
    ] = rows.anomalous_score
    threshold_plot.append(rows.anomalous_score)
    G.add_node(rows.processguid)
#     attributes[rows.processid] = rows.processid

# nx.set_node_attributes(G, attributes)
G.add_edges_from(edges)
pos = nx.spring_layout(G)
plt.figure(figsize=(25, 15))
nx.draw(
    G,
    pos,
    edge_color="black",
    width=1,
    linewidths=1,
    node_size=500,
    node_color="pink",
    alpha=0.9,
    labels={node: node for node in G.nodes()},
)
nx.draw_networkx_edge_labels(
    G, pos, edge_labels=edge_labels_dict, font_color="red"
)
nx.draw_networkx_edges(G, pos, edgelist=edge_labels_dict, arrows=True)
plt.axis("off")
plt.show()

# determine threshold
sorted_threshold = sorted(threshold_plot, reverse=False)
new_list = score_dataframe["anomalous_score"].tolist()
arr = np.array(new_list)
# threshold = np.percentile(arr, 75)

# mean = np.mean(arr)
# sorted_threshold = [i for i in sorted_threshold if i >= mean]
plt.bar(range(len(sorted_threshold)), sorted_threshold)
plt.show()

max_diff = 0
max_elem_1 = -1
max_elem_2 = 0
for a, b in zip(sorted_threshold, sorted_threshold[1:]):
    diff = abs(a - b)
    if diff > max_diff:
        max_diff = diff
        max_elem_1 = b
        max_elem_2 = a
print(max_diff)
print(max_elem_1)
print(max_elem_2)

threshold = max_elem_2

# community detection
# girvan_newman computes communities based on centrality notions
communities_generator = community.girvan_newman(G)
top_level_communities = next(communities_generator)
next_level_communities = next(communities_generator)
community_list = sorted(map(sorted, next_level_communities))

output_df = pd.DataFrame()
for c in community_list:
    temp_df = score_dataframe.loc[score_dataframe["processguid"].isin(c)]
    total_len = len(temp_df.index)
    filtered_by_threshold = temp_df.loc[
        temp_df["anomalous_score"] >= threshold
    ]
    filtered_len = len(filtered_by_threshold.index)
    if len(filtered_by_threshold) >= 1:
        perc = filtered_len / total_len
        new_list = filtered_by_threshold["anomalous_score"].tolist()
        arr = np.array(new_list)
        std = np.std(arr)
        mean = np.mean(arr)
        #         maximum = float(temp_df["anomalous_score"].max())
        #         minimum = float(temp_df["anomalous_score"].min())
        df = temp_df.loc[
            :,
            [
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
                "anomalous_score",
            ],
        ]
        df["mean"] = mean
        df["community_index"] = community_list.index(c)
        df["percentage_anomalous_over_total"] = perc
        output_df = output_df.append(df)

output_df[["percentage_anomalous_over_total"]] = output_df[["percentage_anomalous_over_total"]].astype(float)
output_df = output_df.sort_values(["percentage_anomalous_over_total"], ascending=[False])
output_df.to_csv(output_file_path+"\\output.csv", index=False)
