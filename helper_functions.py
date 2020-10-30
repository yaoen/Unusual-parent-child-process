import math

from collections import Counter

from sklearn.preprocessing import LabelBinarizer

import pandas as pd

import datetime


def get_utctime(utctime: str) -> str:
    utctime = utctime.split(": ")
    return utctime[1]


def get_processid(processid: str) -> str:
    processid = processid.split(": ")
    return processid[1].replace("\r", "")


def get_image_path(image: str) -> str:
    image = image.split(": ", 1)[1].replace("\r", "")
    image = image.split("\\")
    return image[:-1]


def get_process(path: str) -> str:
    process = path.split("\\")[-1]
    return process.replace("\r", "")


def get_value(value: str) -> str:
    value = value.split(": ")
    return value[1].replace("\r", "")


def get_commandline_arg(commandline: str) -> str:
    commandline = commandline.split(": ", 1)[1]
    commandline = (commandline.replace("\r", "")
        .replace('"', "")
        .replace("'", "")
        .replace("-", "")
        .replace("/", "")
    )
    commandline = commandline.split(" ")
    commandline = " ".join(commandline[2:])
    return commandline


def get_entrophy(s: str) -> float:
    p, lns = Counter(s), float(len(s))
    return -sum(count / lns * math.log(count / lns, 2) for count in p.values())


def onehotencode_integrity_level(data: str) -> int:
    '''
    one hot encode the 5 integrity levels
    '''   
    jobs_encoder = LabelBinarizer()
    jobs_encoder.fit(["Low", "Medium", "High", "System", "AppContainer"])
    transformed = jobs_encoder.transform(data["integritylevel"])
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
    return ohe_df


def calc_runtime(start: str, end: str) -> int:
    '''
    calculate the runtime of the process
    end time from process terminate - start time from process create
    '''
    try:
        start = start.replace("\r", "")
        end = end.replace("\r", "")
        start_time = datetime.strptime(start, "%Y-%m-%d %H:%M:%S.%f")
        end_time = datetime.strptime(end, "%Y-%m-%d %H:%M:%S.%f")
        return (end_time - start_time).total_seconds()
    except ValueError:
        return 0


def clean_process_name(process_name: str) -> str:
    process_name = "_".join(process_name)
    return process_name


def anomalous_score(weight: float, prevalence: float) -> float:
    return weight * (1 - prevalence)


def prevalence_engine(
    parent: str, child: str, commandline: str, score_dataframe: pd.Dataframe, total_num_process: int

) -> float:
    '''
    calculates the prevalence of a process and commandline given a parent process 
    '''
    # child process prob
    child_dict = score_dataframe.groupby(["child_process"])
    .size()
    .to_dict()

    # parent process prob
    parent_dict = score_dataframe.groupby(["parent_process"])
    .size()
    .to_dict()

    # parent-child process prob
    parent_child_dict = (
        score_dataframe.groupby(["parent_process", "child_process"])
        .size()
        .to_dict()
    )
    # commandline-process prob
    commandline_process_dict = (
        score_dataframe.groupby(["child_process", "commandline"])
        .size()
        .to_dict()
    )
    
    parent_prob = parent_dict[parent] / total_num_process
    child_prob = child_dict[child] / total_num_process
    parent_child_prob = parent_child_dict[(parent, child)] / total_num_process
    commandline_process_prob = (
        commandline_process_dict[(child, commandline)] / total_num_process
    )

    return (parent_child_prob / parent_prob) * (
        commandline_process_prob / child_prob
    )
