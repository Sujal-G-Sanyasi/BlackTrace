import pandas as pd
import numpy as np
import pickle
import time
import Intrusion.sliding_window.feature_extraction as fex

def anomaly_tagger(preds):
        if preds == -1:
            return "ANOMALY"
        
        elif preds == 1:
            return "NORMAL"
        
        else:
            return "UNKNOWN"
        
def decisionBoundary(decision):
     if decision < -2.0:
          return "Threat Level : Catastrophic"
     
     elif decision > -2.0 and decision < 0:
          return "Threat Level : HIGH"
     
     elif decision > 0:
          return "SAFE"
     
     else:
          return "UNKNOWN"
     

def model_testing():

    FILE_PATH = open("models/IsoForest.pkl", 'rb')
    model = pickle.load(FILE_PATH)

    while True:
        time.sleep(1)

        feature_vec = fex.latest_feature_vector.drop(columns='timestamp')

        if feature_vec is None:
            print("Waiting..........")
            continue
        
        pred = model.predict(feature_vec)
        decision_score = model.decision_function(feature_vec)

        print(anomaly_tagger(pred))
        print(decisionBoundary(decision_score))

model_testing()

        
        
        





        
    
