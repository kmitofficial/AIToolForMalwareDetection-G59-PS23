import joblib
import pefile as pe
import numpy as np
import warnings
import os
import sys

warnings.filterwarnings('ignore')


def predicto_1(s):

    current_dir = os.path.dirname(os.path.abspath(__file__))
    remo=list(current_dir.rsplit("\\"))
    remo=remo[:len(remo)-1]
    ram_maha="\\".join(remo)

    fourth_model_path = os.path.join(ram_maha, 'Modals_proj\\fourth_model.pkl')
    

    my_model=joblib.load(fourth_model_path)

    mahadict={}

    with open(s,"rb") as f:
        tem=f.read(1024)
        for i in range(0,1024):
            mahadict.update({i:int(tem[i])})

    feats=[]

    for i in range(0,1024):
        try:
            feats.append(mahadict[i])
        except:
            pass

    probs=my_model.predict_proba(np.array([feats]))

    maino=[]
    maino.append(my_model.predict(np.array([feats])))
    maino.append(probs)
    return maino

