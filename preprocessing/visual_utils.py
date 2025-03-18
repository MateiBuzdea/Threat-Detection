import matplotlib.pyplot as plt
import pandas as pd

# Hotfix to allow script to be run from anywhere
__import__('sys').path.append('..')

from preprocessing.utils import get_network_labels

def plot_labels_distribution(labels):
    plt.hist(labels, color='blue')
    plt.title("Traffic distribution")
    plt.xlabel("Label")
    plt.ylabel("Frequency")
    plt.show()


def show_dataset_md(df: pd.DataFrame):
    pd.set_option('display.max_rows', 50)
    pd.set_option('display.max_columns', 30)
    print(df.head().to_markdown())


if __name__ == "__main__":
    labels = get_network_labels()
    plot_labels_distribution(labels)
