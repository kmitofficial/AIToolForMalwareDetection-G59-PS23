import joblib
import pefile
import numpy as np
import warnings
import os

warnings.filterwarnings('ignore')
# the first value will give the class/label , the second one will be the a pair of values with 1st value of the list is non-virus probability and the 2nd value is the virus probability

def predicto_5(s):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    remo=list(current_dir.rsplit("\\"))
    remo=remo[:len(remo)-1]
    ram_maha="\\".join(remo)

    first_model_path = os.path.join(ram_maha, 'Modals_proj\\first_model.pkl')
    first_column_names_path=os.path.join(ram_maha, 'Modals_proj\\first_column_names.pkl')
    
    xy=joblib.load(first_column_names_path)[:4]

    my_model=joblib.load(first_model_path)
    secs=('.code','.text')

    pe_obj=pefile.PE(s)
    main_feat={}

    main_feat.update({"size_of_data":float(int(hex(pe_obj.OPTIONAL_HEADER.SizeOfInitializedData),16))})

    for i in pe_obj.sections:
        if((i.Name.decode()).startswith(secs)):
            main_feat.update({"virtual_address":float(int(hex(i.VirtualAddress),16))})
            main_feat.update({"virtual_size":float(int(hex(i.Misc_VirtualSize),16))})
            main_feat.update({"entropy":i.get_entropy()})
        
    feats=[]

    if(len(main_feat)!=4):
        for i in xy:
            if i not in list(main_feat.keys()):
                main_feat.update({i:0.0})
        

    for i in xy:
        try:
            feats.append(main_feat[i])
        except:
            pass

    probs=my_model.predict_proba(np.array([feats]))

    maino=[]
    maino.append(my_model.predict(np.array([feats])))
    maino.append(probs)
    return maino

