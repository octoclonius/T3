import joblib
import json
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance

df_test_data = pd.read_csv('./test-data.csv')
df_test_labels = pd.read_csv('./test-labels.csv')

scaler = joblib.load('./scaler.pkl')
x_test = scaler.transform(df_test_data.drop(columns=['path']))
y_test = np.array(df_test_labels['malicious'])

model = joblib.load('./models/best_model.pkl')
result = permutation_importance(model, x_test, y_test, n_repeats=10, random_state=42)

with open('./columns.json', 'r') as file:
    cols = json.load(file)[1:]
    feature_importances = {cols[i]: {'importance_mean': result.importances_mean[i], 'importance_std': result.importances_std[i]} for i in range(len(cols))}
feature_importances = dict(sorted(feature_importances.items(), key=lambda x: (-x[1]['importance_mean'], -x[1]['importance_std'], x[0])))
with open('./feature_importances.json', 'w') as file:
    json.dump(feature_importances, file)