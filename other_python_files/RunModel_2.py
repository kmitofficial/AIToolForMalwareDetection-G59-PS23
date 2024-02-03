import pefile as pe
import datetime
import time
import joblib
import warnings
import numpy as np
import os


def tds_cal(z):
    time_now=datetime.datetime.now()
    chk=time_now.year
        
    file_time=z.FILE_HEADER.TimeDateStamp
    file_time_readable=int(time.strftime('%Y', time.gmtime(file_time)))
        
    if(file_time>=1980 and file_time<=chk):
        return 1
    else:
        return 0

    
def predicto_2(s):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    remo=list(current_dir.rsplit("\\"))
    remo=remo[:len(remo)-1]
    ram_maha="\\".join(remo)

    third_model_path = os.path.join(ram_maha, 'Modals_proj\\third_model.pkl')
    third_column_names_path=os.path.join(ram_maha, 'Modals_proj\\third_column_names.pkl')
    

    xy=joblib.load(third_column_names_path)
    warnings.filterwarnings("ignore")

    my_model=joblib.load(third_model_path)
    feats=[]
    
    mahadict={}

    try:

        z=pe.PE(s)

        mahadict.update({"optcksum":z.OPTIONAL_HEADER.CheckSum})
        mahadict.update({"ohs":(z.OPTIONAL_HEADER.SizeOfCode+z.OPTIONAL_HEADER.SizeOfInitializedData)})
        mahadict.update({"codesize":z.OPTIONAL_HEADER.SizeOfCode})
        mahadict.update({"majssver":z.OPTIONAL_HEADER.MajorSubsystemVersion})
        mahadict.update({"minssver":z.OPTIONAL_HEADER.MinorSubsystemVersion})
        mahadict.update({"char":z.FILE_HEADER.Characteristics})
        mahadict.update({"majlv":z.OPTIONAL_HEADER.MajorLinkerVersion})
        mahadict.update({"mach":z.FILE_HEADER.Machine})
        mahadict.update({"ss":z.OPTIONAL_HEADER.Subsystem})
        mahadict.update({"majiver":z.OPTIONAL_HEADER.MajorImageVersion})
        mahadict.update({"minlv":z.OPTIONAL_HEADER.MinorLinkerVersion})
        mahadict.update({"dllch":z.OPTIONAL_HEADER.DllCharacteristics})
        mahadict.update({"sosr":z.OPTIONAL_HEADER.SizeOfStackReserve})
        mahadict.update({"nsec":len(z.sections)})
        mahadict.update({"exehdradr":z.DOS_HEADER.e_lfanew})
        mahadict.update({"adrentpt":z.OPTIONAL_HEADER.AddressOfEntryPoint})
        mahadict.update({"sig":z.NT_HEADERS.Signature})
        mahadict.update({"tds":tds_cal(z)})
        mahadict.update({"majosver":z.OPTIONAL_HEADER.MajorOperatingSystemVersion})

        for i in z.sections:
            #print(i)
                    
            if(str(i.Name.decode()).startswith(".text")):
                mahadict.update({"Text_entro ":i.get_entropy()})
                mahadict.update({"Text_mscfaddr":i.Misc_PhysicalAddress})
                mahadict.update({"Text_ptrrawdat":i.PointerToRawData})
                mahadict.update({"cbase":(z.OPTIONAL_HEADER.ImageBase+i.VirtualAddress)})
                mahadict.update({"Text_byteaddr":i.VirtualAddress})
                mahadict.update({"Text_secsize":i.SizeOfRawData})
                mahadict.update({"Text_datsize":i.Misc_VirtualSize})

            if(str(i.Name.decode()).startswith(".data")):
                mahadict.update({"Data_secsize":i.SizeOfRawData})
                mahadict.update({"Data_entro":i.get_entropy()})
                mahadict.update({"Data_ptrrawdat":i.PointerToRawData})
                mahadict.update({"dbase":(z.OPTIONAL_HEADER.ImageBase+i.VirtualAddress)})
                mahadict.update({"Data_byteaddr":i.VirtualAddress})
                mahadict.update({"Data_datsize":i.Misc_VirtualSize})
                mahadict.update({"Data_mscfaddr":i.Misc_PhysicalAddress})
                mahadict.update({"Data_char":i.Characteristics})
                            
            if(str(i.Name.decode()).startswith(".rsrc")):
                mahadict.update({"Rsrc_secsize":i.SizeOfRawData})
                mahadict.update({"Rsrc_entro":i.get_entropy()})
                mahadict.update({"Rsrc_mscfaddr":i.Misc_PhysicalAddress})
                mahadict.update({"Rsrc_datsize":i.Misc_VirtualSize})

        for i in xy:
            try:
                feats.append(mahadict[i])
            except:
                #print(i)
                pass

        probs=my_model.predict_proba(np.array([feats]))

        maino=[]
        maino.append(my_model.predict(np.array([feats])))
        maino.append(probs)
            
        return "code: Success",maino
    except ValueError:
        return "parse incomplete : absence of vital sections of the pe file, indicating obsfurcation and malware behaviour",[np.array([1]),[0.5,0.5]]
    except pe.PEFormatError as e:
        return e,[]

