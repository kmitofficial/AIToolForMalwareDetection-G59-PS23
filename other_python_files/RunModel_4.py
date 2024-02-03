import joblib
import pefile
import re
import numpy as np
import warnings
import os
from timeit import default_timer as timer

# the first value will give the class/label , the second one will be the a pair of values with 1st value of the list is non-virus probability and the 2nd value is the virus probability


def extract_suspicious_imports(pe_obj):
    check_sus=["CreateProcess","OpenProcess","TerminateProcess","VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","LoadLibrary",
               " GetProcAddress","FreeLibrary","RegOpenKey","RegCreateKey","RegSetValue","RegDeleteKey","IsDebuggerPresent","CheckRemoteDebuggerPresent",
               "SetWindowsHookEx","CallNextHookEx","Sleep","GetTickCount","CryptEncrypt","CryptDecrypt","CryptGenKey","InternetOpen","InternetOpenUrl",
               "HttpOpenRequest","CreateFile","ReadFile","WriteFile","DeleteFile","GetSystemInfo","sGetVersionEx"]
    
    suspicious_imports = []
    c=0
    try:

        for entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
            c+=1
            for imp in entry.imports:
                if(imp.name!=None):
                    if(imp.name.decode() in check_sus):
                        suspicious_imports.append(imp.name)
    except:
        pass


    return suspicious_imports,c


def header_guy(patho):
    pe=pefile.PE(patho)
    mahadicto={}

    for i in pe.DOS_HEADER.dump():
        init_split=re.split("[\s\t]",i)
        order=[w for w in init_split if(len(w)>1)]
        try:
            temp=order[2]
            ns=""
            for i in temp:
                if(i.isalnum()):
                    ns+=i

            mahadicto.update({ns[0]+"_"+ns[1:]:int(order[3],16)})
        except:
            pass

    for i in pe.FILE_HEADER.dump():
        init_split=re.split("[\s\t]",i)
        order=[w for w in init_split if(len(w)>1)]
        try:
            temp=order[2]
            ns=""
            for i in temp:
                if(i.isalnum()):
                    ns+=i

            mahadicto.update({ns:int(order[3],16)})

        except:
            pass

    for j in pe.OPTIONAL_HEADER.dump():
        init_split=re.split("[\s\t]",j)
        order=[w for w in init_split if(len(w)>1)]

        try:
            temp=order[2]
            ns=""
            for i in temp:
                if(i.isalnum()):
                    ns+=i

            mahadicto.update({ns:int(order[3],16)})

        except:
            pass
    
    section_entro=[]
    characteristics=[]

    for i in pe.sections:
        w=i.get_entropy()
        section_entro.append(w)
        characteristics.append(i.Characteristics)

        #print(section_entro)
        #print(characteristics)
        
    mahadicto.update({"SectionMinEntropy":min(section_entro)})
    mahadicto.update({"SectionMaxEntropy":max(section_entro)})
    mahadicto.update({"SectionMaxChar":max(characteristics)})
    suspicious_imp,dire=extract_suspicious_imports(pe)
    mahadicto.update({"SuspiciousImportFunctions":len(suspicious_imp),"DirectoryEntryImport":dire})
        
    return mahadicto

def predicto_4(s):
    current_dir = os.path.dirname(os.path.abspath(__file__))

    remo=list(current_dir.rsplit("\\"))
    remo=remo[:len(remo)-1]
    ram_maha="\\".join(remo)

    second_column_names_path=os.path.join(ram_maha,"Modals_proj\\second_column_names.pkl")
    xy=joblib.load(second_column_names_path)
    warnings.filterwarnings("ignore")


    second_model_path=os.path.join(ram_maha,"Modals_proj\\second_model.pkl")
    my_model=joblib.load(second_model_path)
    feats=[]

    try:
        mahadicto=header_guy(s)

        for i in xy:
            try:
                feats.append(mahadicto[i])
            except:
                pass

        probs=my_model.predict_proba(np.array([feats]))

        maino=[]
        maino.append(my_model.predict(np.array([feats])))
        maino.append(probs)
        return "code: Success",maino
    except ValueError:
        return "parse incomplete : absence of vital sections of the pe file, indicating obsfurcation and malware behaviour",[np.array([1]),[0.5,0.5]]
    except pefile.PEFormatError as e:
        return e,[]
        
