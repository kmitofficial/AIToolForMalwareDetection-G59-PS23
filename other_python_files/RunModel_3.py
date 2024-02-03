import pefile
import os
import warnings
import joblib
import numpy as np

warnings.filterwarnings('ignore')

def predicto_3(s):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    remo=list(current_dir.rsplit("\\"))
    remo=remo[:len(remo)-1]
    ram_maha="\\".join(remo)

    fifth_model_path = os.path.join(ram_maha, 'Modals_proj\\fifth_func_model.pkl')
    fifth_column_names_path=os.path.join(ram_maha, 'Modals_proj\\fifth_func_column_names.pkl')

    my_model=joblib.load(fifth_model_path)
    xy=joblib.load(fifth_column_names_path)
    feats=[]

    try:
        
        z=pefile.PE(s)
        funcs_se=set({})
        #print(z)
        try:
            for i in z.DIRECTORY_ENTRY_IMPORT:
                #print(i.dll)
                for j in i.imports:
                    if(j.name!=None):
                        w=str(j.name.decode())
                        #print(w,"   ",len(w))
                        funcs_se.add(w)

        except:
            print("parse not possible : import directory missing")


        if(hasattr(z,'DIRECTORY_ENTRY_DELAY_IMPORT')):
                for i in z.DIRECTORY_ENTRY_DELAY_IMPORT:
                    for j in i.imports:
                        if(j.name!=None):
                            funcs_se.add(str(j.name.decode()))

        for i in xy:
            if(i in funcs_se):
                feats.append(1)
            else:
                feats.append(0)

        probs=my_model.predict_proba(np.array([feats]))

        maino=[]
        maino.append(my_model.predict(np.array([feats])))
        maino.append(probs)
                
        return "code: Success",maino
    
    except pefile.PEFormatError as e:
        return e,[]

    
