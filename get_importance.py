import joblib
import json

model = joblib.load('models/Random_Forest_Classifier_model.pkl')
with open('columns.json', 'r') as cols:
    feature_importances = [(feature, importance) for feature, importance in zip(json.load(cols)[1:], model.feature_importances_)]
feature_importances.sort(key=lambda x: (-x[1], x[0]))
with open('feature_importances.json', 'w') as file:
    json.dump(feature_importances, file)