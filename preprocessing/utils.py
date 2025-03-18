import pandas as pd
import time

from datetime import timedelta
from sklearn.base import BaseEstimator, TransformerMixin


def parse_time(duration):
    days, duration = duration.split(' days ')
    days = int(days) * 86400
    try:
        t_struct = time.strptime(duration, '%H:%M:%S.%f')
        seconds = timedelta(hours=t_struct.tm_hour, minutes=t_struct.tm_min,
                            seconds=t_struct.tm_sec).total_seconds()
        miliseconds = 0
        if '.' in duration:
            miliseconds = float(f"0.{duration.split('.')[1]}")
    except Exception as e:
        return 0

    # return total number of seconds
    return float(days) + seconds + miliseconds


def get_network_labels():
    with open('../data/network_dataset/traffic_classes', 'r') as file:
        labels = [label.strip() for label in file.readlines()]
    return labels[1:]


def load_network_dataset():
    # Load the dataset
    df = pd.read_csv('../data/network_dataset/traffic.in')
    df['flow_duration'] = df['flow_duration'].apply(parse_time)
    df['origin_ip'] = df['origin_ip'].astype('string')
    df['response_ip'] = df['response_ip'].astype('string')

    # Load the labels
    labels = get_network_labels()

    return df, labels


class IPTransformer(BaseEstimator, TransformerMixin):
    def __init__(self, columns=None):
        self.columns = columns
        pass

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        # Split the IPv4 address fields into 4 parts
        # Each part will be a separate column in the dataframe
        # But first, we must check if the ip is v4 or v6

        for column in self.columns:
            ipv6_column = column + '_ipv6'
            X[ipv6_column] = X[column].str.contains(':')
            X[ipv6_column] = X[ipv6_column].astype('int')

            new_columns = [f"{column}_{i}" for i in range(4)]
            X[new_columns] = X[column].apply(
                lambda x: 
                    pd.Series(str(x).split('.')) if '.' in x else pd.Series([0, 0, 0, 0])
            )

            X[new_columns] = X[new_columns].astype('int')

        # Drop the original columns
        X.drop(self.columns, axis=1, inplace=True)

        return X
