import magic
import PySimpleGUI as sg
import joblib, json, os, pefile
import numpy as np
import pandas as pd
from io import DEFAULT_BUFFER_SIZE
from scipy.stats import entropy
from sklearn.preprocessing import StandardScaler

def get_entropy(path):
    res = 0
    try:
        byte_counts = np.zeros(256, dtype=np.uint64)
        with open(path, 'rb') as file:
            while chunk := file.read(DEFAULT_BUFFER_SIZE):
                byte_counts += np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256).astype(np.uint64)
        file_size = os.path.getsize(path)
        res = entropy(byte_counts / file_size, base=2) if file_size else 0
    except:
        pass
    return res

def parse_pe(path):
    d = dict()
    try:
        d = pefile.PE(path).dump_dict()
        d.pop('LOAD_CONFIG', None)
        d.pop('TLS', None)
        d['Parsing Warnings'] = 'Parsing Warnings' in d
        _keys = list(d.keys())
        for key in _keys:
            if isinstance(d[key], list):
                d.pop(key, None)

    except:
        d['Parsing Warnings'] = True

    return d

def scan_file(filename):
    # Grab file object, give to AI, return either malware or not
    model = joblib.load(best_model_name)

    # Apply permutations to data
    df = pd.DataFrame({'path': [filename]})
    df['entropy'] = df['path'].apply(get_entropy)
    _temp_df_data = df.copy()
    _temp_df = _temp_df_data['path'].apply(parse_pe)
    df = pd.concat([_temp_df_data, pd.json_normalize(_temp_df)], axis=1)
    with open('columns.json', 'r') as file:
        cols = json.load(file)
    df = pd.DataFrame({col: df[col] if col in df.columns else pd.Series() for col in cols})
    df = df.fillna(0)
    scaler = joblib.load('scaler.pkl')
    x = scaler.transform(df.drop(columns=['path']))
    
    #result = model.predict(x)[0]
    confidence = model.predict_proba(x)[0][1]
    
    output = filename

    # Use magic number to determine file type
    filetype = magic.from_file(filename)
    output += "\nFile is of type " + filetype

    # Add prediction
    output += f'\n\nI calculate a {round(confidence * 100, 2)}% probability that the file is malware'

    return output

with open("test_results.json", "r") as file:
    results = json.load(file)
    best_model_name = max(results, key=lambda m: (results[m]['accuracy'], -results[m]['time_ns']))
    best_model_name = f'models/{best_model_name.replace(' ', '_')}_model.pkl'

layout = [[sg.Text('What file do you want to scan?')], 
          [sg.Input(key='-IN-', enable_events=True), sg.FileBrowse(target='-IN-', initial_folder='Downloads')],
          [sg.Text(key='-OUT-', size=(50,10), text='')],
          [sg.Button('Exit')]]
window = sg.Window('File Scan', layout)

while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Exit':
        break
    if event == '-IN-':
        filename = values[event]
        window['-OUT-'].update('Scanning...')
        output = scan_file(filename)
        window['-OUT-'].update(output)

window.close()