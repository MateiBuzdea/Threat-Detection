from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import StandardScaler

import numpy as np

# Hotfix to allow script to be run from anywhere
__import__('sys').path.append('..')

from preprocessing.utils import *
from preprocessing.visual_utils import *

from logistic_regression import LogisticRegression


traffic_data, labels = load_network_dataset()
labels = np.array(labels)

DF_FIELDS = traffic_data.columns
IP_FIELDS = ['origin_ip', 'response_ip']

# split the ip fields into 4 columns
ip_transformer = ColumnTransformer(
    transformers=[
        ('ip_splitter', IPTransformer(IP_FIELDS), IP_FIELDS),
    ],
    remainder='passthrough'
)

updated_traffic_data = ip_transformer.fit_transform(traffic_data)
updated_traffic_data = pd.DataFrame(updated_traffic_data)

X_train, X_test, y_train, y_test = train_test_split(updated_traffic_data, labels, test_size=0.2, stratify=labels)

# One-hot encode the labels
encoder = OneHotEncoder()
y_train = encoder.fit_transform(y_train.reshape(-1, 1)).toarray()

# Scale the data to avoid huge initial errors
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Classify using Custom Logistic Regression
lr = LogisticRegression()
lr.fit(X_train, y_train, learning_rate=0.01, epochs=500, batch_size=32, verbose=True)
lr_predict = lr.predict(X_test)

lr_predict = encoder.inverse_transform(lr_predict)

# Evaluate the model
lr_cmat = confusion_matrix(y_test, lr_predict)
report = classification_report(y_test, lr_predict, target_names=encoder.categories_[0])

print(report)
