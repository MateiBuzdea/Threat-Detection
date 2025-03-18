from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.linear_model import LogisticRegression

# Hotfix to allow script to be run from anywhere
__import__('sys').path.append('..')

from preprocessing.utils import *
from preprocessing.visual_utils import *


traffic_data, labels = load_network_dataset()

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

# Classify using Logistic Regression
lr = LogisticRegression(max_iter=500)
lr.fit(X_train, y_train)
lr_predict = lr.predict(X_test)

# Evaluate the model
lr_cmat = confusion_matrix(y_test, lr_predict)
report = classification_report(y_test, lr_predict)

print(report)