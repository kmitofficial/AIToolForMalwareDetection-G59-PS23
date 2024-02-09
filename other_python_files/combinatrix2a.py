import os
current_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(current_dir)
import RunModel_1 as r1
import RunModel_2 as r2
import RunModel_3 as r3
import RunModel_4 as r4
import RunModel_5_ver2 as r5




def maha_predicto(s):
    
    global malware
    malware=False
    majority_pred=0
    remo=s.rsplit("\\")[-1]
    # print()
    print("file name : ",remo)
    # print("file path : ",s)
    # print("*"*100)
    # print()
    if(remo.endswith(".dll")):
        p4_txt="The prediction is generated through a comprehensive analysis of the file's sections, imported Dynamic Link Libraries (DLLs), and Optional Header. The identified file is {prediction} with a confidence level of {perc:.2f} percent."
        
        err_4,p4=r4.predicto_4(s)
        
        if(p4[0][0]==0):
            p4_txt=p4_txt.format(prediction="MALWARE",perc=(p4[1][0][0]*100))
    
        elif(p4[0][0]==1):
            p4_txt=p4_txt.format(prediction="MALWARE",perc=p4[1][0][1]*100)
            #print(p4_txt)
            #print(p4)
            if("Success" not in err_4):
                pass
                #print("NOTE : ",err_4)
            
        return [p4[0][0],"","","",p4_txt,""]
    
    else:            
            
        p1_txt=""
        p2_txt=""
        p3_txt=""
        p4_txt=""
        p5_txt=""

        try:
            
            p1=r1.predicto_1(s)
            err_2,p2=r2.predicto_2(s)
            err_3,p3=r3.predicto_3(s)
            err_4,p4=r4.predicto_4(s)
            p5=r5.predicto_5(s)

            preds=[p1[0][0],p2[0][0],p3[0][0],p4[0][0],p5[0][0]]
            majority_pred=max(preds,key=preds.count)
            print(preds)

            print("majority prediction : ",end=" ")
            if(majority_pred==1):
    
                if(preds.count(1)==3):
                    majority_pred=2
        
                malware=True
            if(majority_pred==0):
                malware=False

            print(majority_pred)
            
            
            # \033[1m{prediction}\033[0m
            p1_txt="According to the ransomware detection model, the analyzed file is predicted to be {prediction} with a confidence level of {perc:.2f}%. This model examines the initial 1024 bytes of the PE file to ascertain its nature."
            p2_txt="This classifier thoroughly analyzes key sections, including the entire PE header and its characteristics. The identified file is predicted to be {prediction} with a confidence level of {perc:.2f}%."
            p3_txt="The classification is determined by analyzing the imported DLL calls and functions of a PE file. The identified file is predicted to be {prediction} with a confidence level of {perc:.2f}%.."
            p4_txt="The prediction is generated through a comprehensive analysis of the file's sections, imported Dynamic Link Libraries (DLLs), and Optional Header. The identified file is {prediction} with a confidence level of {perc:.2f} percent."
            p5_txt="This model is less preferred due to its minimal feature set and rapid scan-based classification. The predicted file is '{prediction}' with a confidence level of {perc:.2f}%."


            try:

                if(p1[0][0]==0):
                    p1_txt=p1_txt.format(prediction="BENIGN or GOODWARE",perc=p1[1][0][0]*100,)
                    #print(p1_txt)
                elif(p1[0][0]==1):
                    p1_txt=p1_txt.format(prediction="MALWARE",perc=p1[1][0][1]*100)
                    #print(p1_txt)

            except:
                pass
                #print("error has occured in this model ! might indicate missing parameters ")

            #print("*"*100)

            try:

                if(p2[0][0]==0):
                    p2_txt=p2_txt.format(prediction="BENIGN or GOODWARE",perc=p2[1][0][0]*100)
                    #print(p2_txt)
                elif(p2[0][0]==1):
                    p2_txt=p2_txt.format(prediction="MALWARE",perc=p2[1][0][1]*100)
                    #print(p2_txt)
                    if("Success" not in err_2):
                        #print("NOTE : ",err_2)
                        pass
            except:
                pass
                #print("error has occured in this model ! might indicate missing parameters ")

            #print("*"*100)

            try:

                if(p3[0][0]==0):
                    p3_txt=p3_txt.format(prediction="BENIGN or GOODWARE",perc=p3[1][0][0]*100)
                    #print(p3_txt)
                elif(p3[0][0]==1):
                    p3_txt=p3_txt.format(prediction="MALWARE",perc=p3[1][0][1]*100)
                    #print(p3_txt)
            except:
                pass
                #print("error has occured in this model ! might indicate missing parameters ")

            #print("*"*100)

            try:

                if(p4[0][0]==0):
                    p4_txt=p4_txt.format(prediction="BENIGN or GOODWARE",perc=p4[1][0][0]*100)
                    #print(p4_txt)
                elif(p4[0][0]==1):
                    p4_txt=p4_txt.format(prediction="MALWARE",perc=p4[1][0][1]*100)
                    #print(p4_txt)
                    if("Success" not in err_4):
                        pass
                        #print("NOTE : ",err_4)

            except:
                pass
                #print("error has occured in this model ! might indicate missing parameters ")

            #print("*"*100)

            try:

                if(p5[0][0]==0):
                    p5_txt=p5_txt.format(prediction="BENIGN or GOODWARE",perc=p5[1][0][0]*100)
                    #print(p5_txt)
                elif(p5[0][0]==1):
                    p5_txt=p5_txt.format(prediction="MALWARE",perc=p5[1][0][1]*100)
                    #print(p5_txt)

            except:
                pass
                #print("error has occured in this model ! might indicate missing parameters ")

            #print("*"*100)

        except Exception as e:
            print(e)
            print("ERROR PARSING FILE ! Missing PE header might indicate corrupted PE file or the file uploaded isn't of a portable executable format(.exe,.dll,.ax...)")
        
        tot=[majority_pred,p1_txt,p2_txt,p3_txt,p4_txt,p5_txt]

        return tot
#put the path of the PE file above
