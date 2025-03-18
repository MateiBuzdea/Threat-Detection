from sklearn.preprocessing import LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report

# Hotfix to allow script to be run from anywhere
__import__('sys').path.append('..')

from preprocessing.utils import *
from preprocessing.visual_utils import *

from decision_tree import DecisionTree


traffic_data, labels = load_network_dataset()

label_encoder = LabelEncoder()
labels = label_encoder.fit_transform(labels)

DF_FIELDS = traffic_data.columns
IP_FIELDS = ['origin_ip', 'response_ip']
show_dataset_md(traffic_data)

# split the ip fields into 4 columns
ip_transformer = ColumnTransformer(
    transformers=[
        ('ip_splitter', IPTransformer(IP_FIELDS), IP_FIELDS),
    ],
    remainder='passthrough'
)

updated_traffic_data = ip_transformer.fit_transform(traffic_data)
updated_traffic_data = pd.DataFrame(updated_traffic_data)
show_dataset_md(updated_traffic_data)

X_train, X_test, y_train, y_test = train_test_split(updated_traffic_data, labels, test_size=0.2, stratify=labels)

# Classify using Custom Decision Tree
dt = DecisionTree()
dt.fit(X_train, y_train)
dt_predict = dt.predict(X_test)

# Evaluate the model
dt_cmat = confusion_matrix(y_test, dt_predict)
report = classification_report(y_test, dt_predict, target_names=label_encoder.classes_)

print(report)
