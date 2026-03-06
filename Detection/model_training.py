import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import IsolationForest


def data_path(path : str):
    return pd.read_csv(path).drop(columns='timestamp')

def model_train_pred(models):
    X = data_path(path='Data/Intrusion_fixed_balanced.csv')
    y_pred_list = [ ]
    for model in list(models.values()):
        estimator = model.fit(X)
        
        # Predicting via IsolationForest Estimator
        y_pred = estimator.predict(X)
        y_pred_list.append(y_pred)

        pickle.dump(estimator, open('models/IsoForest.pkl', 'wb'))

    return y_pred

preds = model_train_pred(models=dict
    (
        IsolationForest = IsolationForest(

                          n_estimators=200,
                          contamination=0.03,
                          n_jobs=-1
        )
    )
)
print(preds)


