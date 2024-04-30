import json
import pandas as pd

df = pd.read_csv('./train-data.csv')
with open('./columns.json', 'w') as file:
    json.dump(df.columns.to_list(), file)