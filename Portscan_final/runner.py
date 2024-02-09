#s2
import os
import joblib
import pandas as pd
import numpy as np
import warnings
import subprocess
import time

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

def find_wireshark_folder():
    potential_paths = [
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("APPDATA"),
    ]
    for path in potential_paths:
        if path:
            wireshark_folder = os.path.join(path, "Wireshark")
            if os.path.exists(wireshark_folder):
                return os.path.abspath(wireshark_folder).replace("\\", "/")
def network_run(duration_seconds):
    wireshark_folder = find_wireshark_folder()
    # print(wireshark_folder)

    #############################################################################################################################################

    relative_path = "packetcaptures1"
    current_dir = os.path.dirname(os.path.abspath(__file__))
    packetcaptures_path = os.path.join(current_dir, relative_path)
    os.makedirs(packetcaptures_path, exist_ok=True)
    # print(packetcaptures_path)

    #############################################################################################################################################

    # duration_seconds = int(input("Enter the duration of the capture in seconds: "))

    #############################################################################################################################################

    commands = (
        f"cd {wireshark_folder} && "
        f"tshark -i Wi-Fi -f tcp -w {packetcaptures_path}/captured_packets.pcap -a duration:{duration_seconds} && "
        "-R tcp -Y tcp &&"
        "tshark -k"
    )

    # Run the process in the background, redirecting output and errors
    process = subprocess.Popen(
        ["cmd", "/c", commands],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW
    )

    print("Packet capture started in the background.")
    print()

    # Optionally wait for completion or check status
    time.sleep(duration_seconds + 2)  # Wait slightly longer than capture duration
    if process.poll() is None:
        print("Packet capture is still running...")
    else:
        print("Packet capture has finished.")
        print()


    #s1

    # First section
    relative_path = "CICFlowMeter-4.0"
    current_dir = os.path.dirname(os.path.abspath(__file__))
    packetcaptures_path = os.path.join(current_dir, relative_path)
    os.makedirs(packetcaptures_path, exist_ok=True)

    # Second section
    relative_path1 = "packetcaptures1"
    current_dir = os.path.dirname(os.path.abspath(__file__))
    packetcaptures_path1 = os.path.join(current_dir, relative_path1)
    os.makedirs(packetcaptures_path1, exist_ok=True)

    # Hello path
    hello = os.path.join(packetcaptures_path1, "captured_packets.pcap")

    commands = (
        rf"cd /d {packetcaptures_path} && "
        rf"cd bin && cfm.bat {hello} {packetcaptures_path1}"
    )

    # Use shell=True to keep the terminal open
    process = subprocess.Popen(["cmd", "/c", commands], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Wait for the process to complete
    process.wait()

    # Check if the process completed successfully
    if process.returncode != 0:
        print("Packets not saved.")
    else:
        print()


    hello1 = os.path.join(packetcaptures_path1, "captured_packets.pcap_Flow.csv")
    # print(hello1)





    #pendushark
    current_dir = os.path.dirname(os.path.abspath(__file__))
    print(current_dir)

    remo=list(current_dir.rsplit("\\"))
    remo=remo[:len(remo)-1]
    ram_maha="\\".join(remo)

    model_1_path = os.path.join(ram_maha, "Portscan_final\model_1.pkl")

    loaded_model=joblib.load(model_1_path)#model_1.pkl location
    feature_pred_array=list()

    real_data=pd.read_csv(hello1)
    #CIC flowmeter converted csv

    rem=real_data[['Flow IAT Max','Bwd Pkts/s','Fwd Pkt Len Mean',
                'Subflow Fwd Byts','Pkt Size Avg','Fwd Pkt Len Max',
                'TotLen Fwd Pkts','PSH Flag Cnt','Fwd Seg Size Avg',
                'Flow Duration','Init Fwd Win Byts']]
    feature_pred_array=list()
    for i,r in rem.iterrows():
        fet1=list()

        fet1.append(r['Flow IAT Max'])
        fet1.append(r['Bwd Pkts/s'])
        fet1.append(r['Fwd Pkt Len Mean'])
        fet1.append(r['Subflow Fwd Byts'])
        fet1.append(r['Pkt Size Avg'])
        fet1.append(r['Fwd Pkt Len Max'])
        fet1.append(r['TotLen Fwd Pkts'])
        fet1.append(r['PSH Flag Cnt'])
        fet1.append(r['Fwd Seg Size Avg'])
        fet1.append(r['Flow Duration'])
        fet1.append(r['Init Fwd Win Byts'])


        feature_pred_array.append(fet1)
        array_pred = np.array(feature_pred_array)

    mal=0
    try:
        count1=0
        for i in loaded_model.predict(array_pred):
            if i==1:
                count1+=1
                if count1==3:# minimum 3 packets in the csv have to be flagged (having more PSH ON packets might result in this)
                    mal=2
    except:
        pass 


    #this is another section


    hello5 = os.path.join(packetcaptures_path1,"smthng.csv")
    # Specify the tshark command
        
    tshark_command =( 
    f"cd {wireshark_folder} && "
    f'tshark -r {hello} -Y "tcp" -T fields -e tcp.window_size_value -e tcp.completeness.str > {hello5}'
    )

    # Execute the tshark command using subprocess
    try:
        subprocess.run(tshark_command, shell=True, check=True)
        print("tshark command executed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing tshark command: {e}")



    df=pd.read_csv(hello5)
    first_column=df.columns[0]

    df = df.rename(columns={first_column: 'window'})

    df[['window_size', 'comp_str']] = df['window'].str.split('\t', expand=True)
    df.drop('window', axis=1, inplace=True)

    df['window_size'] = pd.to_numeric(df['window_size'], errors='coerce').astype('Int64')


    for index, row in df.iterrows():
        if row['window_size'] == 513:
            if row['comp_str'] == "·F·ASS":
                mal=1
                break
        
        elif row['window_size'] == 256:
            if row['comp_str'] == "·F·ASS":
                mal=1
                break

        elif row['window_size'] == 1024:
            mal=1
            break


    if mal==1:
        print("A portscan has been attempted on your system!!!")
        return 1
    elif mal==2:
        print("Mostly normal network activity, however Our AI/ML modal suspects a small scale PortScan activity in ur network.")
        return 2
    else:
        print("Perfectly Normal Network Activity, Happy Networking!!")
        return 3